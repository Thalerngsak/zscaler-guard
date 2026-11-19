# zscaler-guard

A Claude Code mod for teams behind a Zscaler DLP proxy. It stops `API Error: 403 Internet Security by Zscaler` at the source: values a DLP policy blocks (card numbers, national IDs including Thai mod-11 IDs, bank and IBAN numbers, private keys, API tokens, passwords) are redacted on your machine before Claude Code stores or sends them, and whole datasets are withheld instead of trimmed. It also recognises the 403 when it happens and tells you how to recover.

mod สำหรับ Claude Code ในองค์กรที่ใช้ Zscaler DLP แก้ปัญหา `API Error: 403 Internet Security by Zscaler` ที่ต้นเหตุ: ปกปิดเลขบัตร เลขบัตรประชาชน (ตรวจ check digit แบบไทย) เลขบัญชีและ IBAN กุญแจส่วนตัว token และรหัสผ่านบนเครื่องก่อนที่ Claude Code จะเก็บหรือส่ง ถ้าเป็นชุดข้อมูลจะกันไว้ทั้งก้อนแทนการตัดบางส่วน และเมื่อโดน 403 จะบอกสาเหตุกับวิธีแก้ ทำงานในเครื่องทั้งหมด ไม่เรียกเครือข่ายเอง

## Install / ติดตั้ง

In Claude Code / พิมพ์ใน Claude Code:

```text
/plugin marketplace add Thalerngsak/zscaler-guard
/plugin install zscaler-guard@zscaler-guard
```

Then run `/reload-plugins` (or start a new session). `ZS: redact` on the status line means it is active.

จากนั้นรัน `/reload-plugins` หรือเปิด session ใหม่ ถ้าแถบสถานะด้านล่างขึ้น `ZS: redact` แปลว่าทำงานแล้ว

## Use / ใช้งาน

```text
/zscaler-guard            status, counters and active rules      ดูสถานะ ตัวนับ และกฎที่ใช้
/zscaler-guard scan       find sensitive values already in the    หาค่าอ่อนไหวที่ค้างอยู่ในบทสนทนา
                          conversation
/zscaler-guard redact     redact sensitive values (default)      ปกปิดค่าอ่อนไหว (ค่าเริ่มต้น)
/zscaler-guard block      refuse prompts that hold sensitive      ไม่ส่งพรอมต์ที่มีค่าอ่อนไหว
                          values
/zscaler-guard off        turn it off                            ปิด
```

Type the command at the prompt as is; inside a ``` code fence it is sent as plain text and does not run.

พิมพ์คำสั่งในช่องข้อความตรง ๆ ถ้าครอบด้วย ``` คำสั่งจะถูกส่งเป็นข้อความธรรมดา ไม่ถูกรัน

### Modes / โหมด

| Mode (status line) | Your prompt holds a sensitive value | Tool output, @file, context |
|---|---|---|
| `ZS: redact` (default) | the value is replaced by a tag, the rest is sent | redacted; datasets withheld whole |
| `ZS: block` | the prompt is not sent; you are told to fix it first | same as redact |
| `ZS: off` | sent as is | sent as is |

Use `redact` day to day. Use `block` when you want to know every time real data is pasted into a prompt. `off` is for short checks only: a value that enters the conversation while it is off is resent every turn until `/rewind` or `/clear`.

| โหมด (แถบสถานะ) | ข้อความที่คุณพิมพ์มีค่าอ่อนไหว | ผลจากเครื่องมือ, @file, context |
|---|---|---|
| `ZS: redact` (ค่าเริ่มต้น) | แทนค่านั้นด้วย tag แล้วส่งข้อความที่เหลือ | ปกปิด และกันไว้ทั้งก้อนถ้าเป็นชุดข้อมูล |
| `ZS: block` | ไม่ส่งข้อความนั้น และแจ้งให้แก้ก่อน | เหมือน redact |
| `ZS: off` | ส่งตามเดิม | ส่งตามเดิม |

- **`redact`** ใช้งานทั่วไป ทำงานต่อได้ไม่สะดุด Claude เห็นแค่ tag แทนค่าจริง
- **`block`** ใช้เมื่อต้องการรู้ตัวทุกครั้งที่วางข้อมูลจริงลงในพรอมต์ แล้วเลือกเองว่าจะลบหรือใช้ค่าสมมุติแทน
- **`off`** ใช้ชั่วคราวเท่านั้น ค่าที่หลุดเข้าบทสนทนาตอนปิดจะถูกส่งซ้ำทุกเทิร์นจนกว่าจะ `/rewind` หรือ `/clear`

### When you still get a 403 / ถ้ายังโดน 403

- **"Authentication failed" / "Sign in again":** Zscaler wants you to sign in again; this is not a DLP block. Run `/login` or re-authenticate in Zscaler Client Connector. No need to `/rewind` or `/clear`.
  Zscaler ขอยืนยันตัวตน ไม่ใช่การบล็อกข้อมูล ให้รัน `/login` หรือ re-authenticate ที่ Zscaler Client Connector ไม่ต้อง `/rewind` หรือ `/clear`
- **Otherwise:** run `/zscaler-guard scan`, then `/rewind` to before the message it points to.
  กรณีอื่น ให้รัน `/zscaler-guard scan` แล้ว `/rewind` ไปก่อนข้อความที่มีปัญหา

Details, settings (`customRedact`, `customWithhold`, `bulkThreshold`, `withholdMedia`) and the full 403 runbook: [zscaler-guard/README.md](zscaler-guard/README.md).

รายละเอียด การตั้งค่า และขั้นตอนแก้ 403 ฉบับเต็ม (ภาษาไทย) อยู่ที่ [zscaler-guard/README.md](zscaler-guard/README.md)

## How it was tested / การทดสอบ

Unit tests (`claude plugin test zscaler-guard`) build every test value at run time, so the repository holds no real card, ID or key. Before release the detector ran over a real working folder of 283,116 unique text files (code, configs, logs, docs): no crashes, no value left after redaction, redaction stable on a second pass, under 30 ms per file.

unit test (`claude plugin test zscaler-guard`) สร้างค่าทดสอบทั้งหมดตอนรัน จึงไม่มีเลขบัตร เลขบัตรประชาชน หรือกุญแจจริงอยู่ใน repo ก่อนเผยแพร่ได้ทดสอบกับไฟล์ข้อความจริง 283,116 ไฟล์ (โค้ด, config, log, เอกสาร): ไม่มีไฟล์ไหนทำให้พัง ไม่มีค่าเหลือหลังปกปิด รันซ้ำได้ผลเดิม และใช้เวลาไม่เกิน 30 ms ต่อไฟล์

## Credits / เครดิต

The detection method is adapted from [pdpa-thai](https://github.com/Boom-Vitt/boombignose-mods) by Boom-Vitt (MIT). Licence: [MIT](LICENSE); [zscaler-guard/LICENSE](zscaler-guard/LICENSE) also carries pdpa-thai's MIT notice.

วิธีตรวจจับดัดแปลงจาก [pdpa-thai](https://github.com/Boom-Vitt/boombignose-mods) ของ Boom-Vitt (MIT) สัญญาอนุญาต [MIT](LICENSE) ส่วน [zscaler-guard/LICENSE](zscaler-guard/LICENSE) มี notice MIT ของ pdpa-thai รวมอยู่ด้วย
