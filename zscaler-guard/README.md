# zscaler-guard

A Claude Code mod that keeps what a corporate DLP proxy (Zscaler) blocks out of what Claude Code sends to the model. It applies the method of [`pdpa-thai`](https://github.com/Boom-Vitt/boombignose-mods) (MIT): rewrite each row on this machine before it is stored, so the value never enters the conversation.

## ปัญหาที่แก้

`API Error: 403 Internet Security by Zscaler` หมายถึง Zscaler (ZIA inline DLP / ZDP) ตรวจ HTTPS ไปยัง `api.anthropic.com` แล้วพบเนื้อหาที่ตรงกับ DLP dictionary เช่น บัตรเครดิต เลขบัตรประชาชน เลขบัญชี กุญแจส่วนตัว หรือ token

สิ่งที่ทำให้ปัญหานี้หนักกว่าที่เห็น: **Claude Code ส่งบทสนทนาทั้งก้อนทุกเทิร์น** พอมีค่าต้องห้ามหลุดเข้าไปในประวัติแค่ครั้งเดียว (ผลจาก `Read` ไฟล์ CSV, log, หรือ Claude สร้างข้อมูลทดสอบเอง) ทุกคำขอหลังจากนั้นจะโดน 403 จนกว่าจะ `/rewind` หรือ `/clear` ("poisoned conversation")

## หลักการ (สิ่งที่ยืมจาก pdpa-thai)

| pdpa-thai | zscaler-guard |
|---|---|
| ตรวจบนเครื่อง ไม่เรียก network/process/model/MCP | เหมือนกัน (`claude plugin validate` แสดงว่าเรียกแค่ `$.clock` `$.command` `$.session.messages` `$.state` `$.ui`) |
| hook `prompt.submit`, `session.append`, `prompt.attachment`, `prompt.context`, `tool.call` | เหมือนกัน + `command.run` (อาร์กิวเมนต์ของ slash command), `prompt.compose`, `classic.StopFailure` |
| แทนค่าด้วย tag `[REDACTED:KIND_n~sfx]` ทางเดียว ไม่เก็บค่าจริง | เหมือนกัน ใช้ kind ขึ้นต้น `ZS_` และข้าม tag ของ pdpa-thai (ทำงานคู่กันได้ ไม่ซ้อนกัน) |
| regex บน shadow text ความยาวเท่าเดิม เวลาเป็นเชิงเส้น | เหมือนกัน + test ที่ตรวจเวลาเชิงเส้น |
| fail-open (hook ล้ม = ส่งข้อความเดิม) | **fail-closed**: hook ล้ม = เก็บเป็นโน้ต "withheld" แทน |

## สิ่งที่เพิ่มเพื่อ Zscaler

1. **ชุดกฎตามหมวดที่ DLP มักบล็อก**: `THAI_ID` (mod-11), `CARD` (Luhn + prefix ของแบรนด์บัตร ลด false positive จาก timestamp), `CARD_META` (CVV, วันหมดอายุ เฉพาะที่มี label), `SSN`, `IBAN` (mod-97), `SWIFT`, `BANK_ACCOUNT`, `PASSPORT`, `PRIVATE_KEY` (PEM/PGP ทั้งบล็อก), `SECRET` (GitHub/GitLab/AWS/Google/Slack/Stripe/npm/JWT, Bearer, Basic auth, `password=` และค่าในลักษณะเดียวกัน, รหัสผ่านใน `scheme://user:pass@host`)
2. **กันไว้ทั้งก้อน (withhold) แทนการตัดค่าออก** เมื่อ
   - ก้อนนั้นมีค่าอ่อนไหวตั้งแต่ `bulkThreshold` ค่าขึ้นไป (ค่าเริ่มต้น 25) ซึ่งดูเป็นชุดข้อมูล ชื่อและที่อยู่ที่เหลืออยู่ก็ยังระบุตัวคนได้
   - ตรงกับ `customWithhold` (เนื้อหาที่องค์กรกำหนดว่าห้ามส่ง เช่น ป้ายชั้นความลับ) **จะไม่ลบแค่ป้ายแล้วส่งเนื้อหา** เพราะนั่นคือการหลบ DLP
   - ใหญ่เกิน 1,000,000 ตัวอักษร (ตรวจในเวลาที่กำหนดไม่ได้)
3. **ป้องกันที่ต้นทาง**: เพิ่ม section ใน system prompt บอก Claude ว่าห้ามเขียนค่าต้องห้ามในคำตอบหรือในอินพุตของเครื่องมือ และถ้าต้องใช้ข้อมูลทดสอบให้เขียนโค้ดสร้างตอนรัน เพราะ mod ใดก็แก้ `tool_use` input และ thinking ไม่ได้
4. **ปกปิดข้อความที่ Claude ตอบด้วย** (pdpa-thai ข้าม) เพราะค่าใดก็ตามในประวัติ ไม่ว่าใครเขียน ทำให้โดน 403 ทุกเทิร์น
5. **รู้ตัวเมื่อโดน 403**: hook `classic.StopFailure` จับข้อความ Zscaler แล้วนับใน status line (`ZS: redact · 403×1`) และบอกวิธีกู้
6. **`/zscaler-guard scan`**: ไล่ดูบทสนทนาที่ส่งไปแล้ว บอกว่าข้อความที่เท่าไรมีค่าชนิดไหน (ไม่แสดงค่าจริง) เพื่อ `/rewind` ไปก่อนจุดนั้น
7. **กฎขององค์กร** ผ่าน `userConfig`: `customRedact` และ `customWithhold` ให้ทีม Security ส่งรูปแบบที่ตรงกับ DLP policy จริงมาใส่ได้โดยไม่ต้องแก้โค้ด

## หลักที่ไม่ข้าม

ค่าจะถูก**ลบออก ไม่ใช่ปลอมตัว** ไม่มีการเข้ารหัส แยกตัวอักษร หรือใช้ตัวอักษรหน้าตาคล้ายกันเพื่อให้ผ่านการตรวจ ข้อมูลไม่ออกจากเครื่อง ซึ่งตรงกับเจตนาของ DLP policy อยู่แล้ว 403 หายไปเป็นผลตามมา ไม่ใช่เป้าหมาย

## คำสั่ง

```text
/zscaler-guard            สถานะ ตัวนับ และกฎที่ใช้
/zscaler-guard redact     ปกปิดค่า และกันไว้ทั้งก้อนเมื่อเป็นชุดข้อมูลหรือเนื้อหาต้องห้าม (ค่าเริ่มต้น)
/zscaler-guard block      ไม่ส่งพรอมต์ที่มีค่าอ่อนไหวเลย ส่วนผลลัพธ์ของเครื่องมือยังถูกปกปิด
/zscaler-guard off        ปิด
/zscaler-guard scan       หาค่าที่ค้างอยู่ในบทสนทนา
```

พิมพ์คำสั่งในช่องข้อความตรง ๆ ถ้าครอบด้วย ``` คำสั่งจะถูกส่งเป็นข้อความธรรมดา ไม่ถูกรัน

### โหมด (ดูได้ที่ status line: `ZS: redact`, `ZS: block`, `ZS: off`)

| สิ่งที่ส่งไป | `redact` (ค่าเริ่มต้น) | `block` | `off` |
|---|---|---|---|
| ข้อความที่คุณพิมพ์ มีค่าอ่อนไหว | ปกปิดเฉพาะค่านั้นด้วย tag แล้วส่งที่เหลือ | **ไม่ส่งข้อความนั้น** และแจ้งให้แก้ก่อน | ส่งตามเดิม |
| ผลจากเครื่องมือ (อ่านไฟล์, Bash, @file, context) | ปกปิด / กันไว้ทั้งก้อนถ้าเป็นชุดข้อมูล | เหมือน redact | ส่งตามเดิม |
| ข้อความที่ไม่มีค่าอ่อนไหว | ส่งตามปกติ | ส่งตามปกติ | ส่งตามปกติ |

- **`redact`** เหมาะกับงานทั่วไป ทำงานต่อได้ไม่สะดุด Claude เห็นแค่ tag แทนค่าจริง
- **`block`** เหมาะเมื่อต้องการรู้ตัวทุกครั้งที่วางข้อมูลจริงลงในพรอมต์ แล้วเลือกเองว่าจะลบหรือใช้ค่าสมมุติแทน
- **`off`** ปิด guard ใช้ชั่วคราวเท่านั้น ค่าที่หลุดเข้าบทสนทนาตอนปิดจะถูกส่งซ้ำทุกเทิร์นจนกว่าจะ `/rewind` หรือ `/clear`

## ตั้งค่า (`/config` หรือ `pluginConfigs` ใน `~/.claude/settings.json`)

| ฟิลด์ | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `bulkThreshold` | 25 | จำนวนค่าในก้อนเดียวที่ถือว่าเป็นชุดข้อมูลและกันไว้ทั้งก้อน (0 = ปิด) |
| `withholdMedia` | false | แทนรูปและ PDF ด้วยโน้ต (สำหรับ policy ที่ OCR รูป) |
| `customRedact` | "" | regex คั่นด้วย `;;` สำหรับค่าที่ DLP ขององค์กรบล็อก เช่นรูปแบบเลขสัญญา |
| `customWithhold` | "" | regex คั่นด้วย `;;` สำหรับเนื้อหาที่ห้ามส่งทั้งก้อน รูปแบบ `/body/flags` ใช้ flag `i m s u` ได้ |

## เมื่อโดน 403 (runbook)

0. ถ้า error บอกว่า Authentication failed หรือ Sign in again แปลว่า Zscaler ขอยืนยันตัวตน ไม่ใช่ DLP: รัน `/login` หรือ re-authenticate ที่ Zscaler Client Connector ไม่ต้อง `/rewind` หรือ `/clear` (mod ขึ้น toast บอกและไม่นับเป็น 403 ของ DLP)
1. ดู status line ว่าเป็น `ZS: … · 403×n` (mod จับได้)
2. `/zscaler-guard scan` เพื่อดูว่าข้อความไหนมีค่าที่ DLP น่าจะจับ
3. `/rewind` ไปก่อนข้อความนั้น หรือ `/clear` ถ้าไม่ต้องการบริบทเดิม
4. ถ้า scan ไม่พบอะไร สาเหตุอาจเป็น dictionary ขององค์กร (EDM/IDM, source code, OCR), นโยบายหมวด URL หรือขนาดคำขอ ให้แจ้งทีม Security พร้อมเวลาที่เกิด แล้วนำรูปแบบที่ได้มาใส่ `customRedact` / `customWithhold`

## ข้อจำกัด

- regex ทำได้ดีที่สุดเท่าที่ทำได้: พลาดได้และจับเกินได้ และ DLP policy จริงขององค์กรอาจมี dictionary ที่ mod ไม่รู้จัก
- `tool_use` input และ thinking ของ Claude ไม่มี mod ใดแก้ได้: mod จะเตือนเมื่อ Claude ใส่ค่าอ่อนไหวในการเรียกเครื่องมือ และ section ใน system prompt ช่วยป้องกันที่ต้นทาง
- รูปและเอกสารผ่านไปตามเดิม ยกเว้นเปิด `withholdMedia` และ attachment ที่มี media ทาง engine อาจคงไว้ตามเดิม
- ประวัติที่ resume มา และ transcript ของ subagent ที่บันทึกไว้แล้วไม่ถูกตรวจซ้ำ
- system prompt และคำอธิบายเครื่องมือ/skill ไม่ถูกตรวจ
- ผลของ hook ของ plugin อื่นที่ทำงานก่อน mod นี้อาจเห็นข้อความเดิม
- ใช้ได้ต่อผู้ใช้หนึ่งคนและเครื่องเดียว ปิดเองได้ จึงไม่ใช่ control ที่บังคับใช้ทั้งองค์กรหรือหลักฐานด้าน compliance

## การทำงานคู่กับ pdpa-thai

ติดตั้งคู่กันได้: pdpa-thai ดูแลข้อมูลส่วนบุคคลตาม PDPA (ชื่อ ที่อยู่ เบอร์โทร อีเมล IP) ส่วน zscaler-guard ดูแลหมวดที่ DLP บล็อกและการกู้จาก 403 ทั้งสองข้าม tag ของกันและกัน ค่าที่ทั้งคู่จับได้จะถูกแทนเพียงครั้งเดียว

## ตรวจด้วยตัวเอง

```bash
claude plugin validate .
claude plugin test .
```

ตัวอย่างใน `tests/` สร้างตอนรันทั้งหมด (คำนวณ check digit ในโค้ด) จึงไม่มีเลขบัตร เลขประจำตัว หรือกุญแจจริงอยู่ในไฟล์ใด

## License

MIT. The detection engine is adapted from pdpa-thai, MIT © 2026 Boom-Vitt.
