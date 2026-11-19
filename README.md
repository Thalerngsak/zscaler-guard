# zscaler-guard

A Claude Code mod for teams behind a Zscaler DLP proxy. It stops `API Error: 403 Internet Security by Zscaler` at the source: values a DLP policy blocks (card numbers, national IDs including Thai mod-11 IDs, bank and IBAN numbers, private keys, API tokens, passwords) are redacted on your machine before Claude Code stores or sends them, and whole datasets are withheld instead of trimmed. It also recognises the 403 when it happens and tells you how to recover.

mod สำหรับ Claude Code ในองค์กรที่ใช้ Zscaler DLP: ปกปิดเลขบัตร เลขบัตรประชาชน เลขบัญชี กุญแจ token และรหัสผ่านในเครื่องก่อนส่งให้ Claude กันชุดข้อมูลไว้ทั้งก้อน และบอกวิธีแก้เมื่อโดน 403 ทำงานในเครื่องทั้งหมด ไม่เรียกเครือข่ายเอง

## Install / ติดตั้ง

In Claude Code:

```text
/plugin marketplace add Thalerngsak/zscaler-guard
/plugin install zscaler-guard@zscaler-guard
```

Then run `/reload-plugins` (or start a new session). `ZS: redact` on the status line means it is active.

## Use / ใช้งาน

```text
/zscaler-guard            status, counters and active rules
/zscaler-guard scan       find sensitive values already in the conversation
/zscaler-guard block      refuse prompts that hold sensitive values
/zscaler-guard off        turn it off
```

Details, settings (`customRedact`, `customWithhold`, `bulkThreshold`, `withholdMedia`) and the 403 runbook: [zscaler-guard/README.md](zscaler-guard/README.md).

## How it was tested

Unit tests (`claude plugin test zscaler-guard`) build every test value at run time, so the repository holds no real card, ID or key. Before release the detector ran over a real working folder of 283,116 unique text files (code, configs, logs, docs): no crashes, no value left after redaction, redaction stable on a second pass, under 30 ms per file.

## Credits

The detection method is adapted from [pdpa-thai](https://github.com/Boom-Vitt/boombignose-mods) by Boom-Vitt (MIT). Licence: [MIT](zscaler-guard/LICENSE).
