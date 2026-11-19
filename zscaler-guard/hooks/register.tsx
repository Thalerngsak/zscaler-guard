import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { ZscalerGuardMode } from '../types'
import {
  compilePolicy,
  findSensitive,
  guardText,
  issuedTag,
  newTags,
  newTally,
  scanTexts,
  scrub,
  sealed,
  touched,
  withheldNote,
  type Policy,
  type Tally,
} from './detect'

// Why this mod exists: a Zscaler DLP rule that matches anything in a request answers 403
// ("Internet Security by Zscaler"), and Claude Code sends the whole conversation every turn, so
// one matching value in the history blocks every later turn until /rewind or /clear. pdpa-thai's
// method (rewrite each row before it is stored) keeps such values out of the history in the first
// place; this mod applies it to the DLP's categories, withholds whole blocks a value-level redaction
// cannot make safe, and recognises the 403 itself so the person knows how to recover.

const guardMode = atom({ plugin: 'zscaler-guard', key: 'guardMode' } as const, 'redact' as ZscalerGuardMode)
const tagSuffix = atom({ plugin: 'zscaler-guard', key: 'tagSuffix' } as const, '')
const incidents = atom({ plugin: 'zscaler-guard', key: 'incidents' } as const, 0)
const hidden = atom({ plugin: 'zscaler-guard', key: 'hidden' } as const, 0)
const withheld = atom({ plugin: 'zscaler-guard', key: 'withheld' } as const, 0)

const MODES = ['redact', 'block', 'off'] as const

const HELP: Record<ZscalerGuardMode, string> = {
  redact: 'redact: ปกปิดค่าที่ DLP มักบล็อกก่อนส่งให้ Claude และกันไว้ทั้งก้อนเมื่อเป็นชุดข้อมูลหรือเนื้อหาต้องห้าม (ค่าเริ่มต้น)',
  block: 'block: ไม่ส่งพรอมต์ที่มีค่าอ่อนไหว ส่วนผลลัพธ์ของเครื่องมือยังถูกปกปิดเหมือน redact',
  off: 'off: ปิดการป้องกัน ค่าที่ส่งไประหว่างนี้จะค้างในบทสนทนาและถูกส่งซ้ำทุกเทิร์น',
}

const USAGE = 'Usage: /zscaler-guard [redact | block | off | status | scan]'

// The model cannot have its tool_use inputs or thinking rewritten by any mod, so the one way to
// keep a value it would invent (test data, a sample card) out of the history is to ask it not to.
// Added once per thread; the engine keeps a thread's recorded prompt, so it never flips mid-thread.
const POLICY_SECTION = {
  id: 'zscaler-guard:policy',
  scope: 'session',
  text:
    'This session runs behind a corporate DLP proxy (Zscaler). It rejects any request that contains payment card numbers ' +
    'with their CVV or expiry, national ID numbers, bank account, IBAN or SWIFT numbers, private keys, API tokens or ' +
    'passwords. Every request carries the whole conversation, so one such value in your reply, your reasoning or a tool ' +
    'input (file contents, a command) blocks every later turn. Never write a literal value of those kinds. When test data ' +
    'is needed, write code that generates it at run time, or use placeholders that are obviously not real. Values shown ' +
    'as ZS_<KIND> redaction tags were removed before they reached you: do not guess them or use a tag as a real value; ' +
    'ask the user to handle the real value. When a block says zscaler-guard withheld it, ask the user for a small ' +
    'de-identified sample, the column names or a summary.',
} as const

const ZSCALER = /zscaler/i
// Zscaler serves the same 403 page when its own sign-in (SSO, Client Connector) has lapsed; that is
// not a DLP hit, and the DLP advice (rewind, clear) would throw the conversation away for nothing
const ZS_AUTH = /authenticat|sign[ -]?in|log[ -]?in|re-?auth|\bSSO\b|SAML|credential|session (?:has )?expired/i
const ZS_DLP = /\bDLP\b|data loss|data protection|sensitive|dictionary/i

// one suffix per session, kept in state so a hot reload keeps it; it marks the tags this session issued
async function suffix($: EngineInterface) {
  const fresh = (await $.clock.now()).toString(36).slice(-5)
  await update($, tagSuffix, cur => cur || fresh)
  return read($, tagSuffix)
}

async function showStatus($: EngineInterface) {
  const n = await read($, incidents)
  $.ui.status(`ZS: ${await read($, guardMode)}${n ? ` · 403×${n}` : ''}`)
}

function summary(t: Tally) {
  const parts: string[] = []
  if (t.redacted) parts.push(`ปกปิด ${t.redacted} ค่า`)
  if (t.withheld) parts.push(`กันไว้ทั้งก้อน ${t.withheld} ส่วน`)
  if (t.media) parts.push(`กันรูปหรือเอกสาร ${t.media} ชิ้น`)
  return `Zscaler guard: ${parts.join(', ')} ก่อนส่งให้ Claude`
}

async function tallyUp($: EngineInterface, t: Tally) {
  if (t.redacted) await update($, hidden, n => n + t.redacted)
  if (t.withheld + t.media) await update($, withheld, n => n + t.withheld + t.media)
}

type Config = { policy: Policy; errors: string[]; withholdMedia: boolean; customRedact: number }

async function statusText($: EngineInterface, cfg: Config) {
  const { policy, errors, withholdMedia, customRedact } = cfg
  const mode = await read($, guardMode)
  return [
    `Zscaler guard: ${HELP[mode]}`,
    `เซสชันนี้: ปกปิดแล้ว ${await read($, hidden)} ค่า, กันไว้ทั้งก้อน ${await read($, withheld)} ส่วน, ตรวจพบ Zscaler 403 ${await read($, incidents)} ครั้ง`,
    `กฎ: built-in + customRedact ${customRedact} + customWithhold ${policy.withhold.length}; bulkThreshold ${policy.bulk || 'off'}; withholdMedia ${withholdMedia ? 'on' : 'off'}`,
    errors.length ? `รูปแบบที่กำหนดเองซึ่งไม่ถูกต้องและถูกข้าม: ${errors.length} รายการ` : '',
    `เปลี่ยนโหมดด้วย /zscaler-guard ${MODES.join(' | ')} · หาค่าที่ค้างในบทสนทนาด้วย /zscaler-guard scan`,
  ]
    .filter(Boolean)
    .join('\n')
}

// What is already in the conversation: the rows as stored, which every request resends. It
// reports where and what kind, never the value.
async function scan($: EngineInterface, policy: Policy) {
  const msgs = await $.session.messages()
  const items: { index: number; role: string; where: string; text: string }[] = []
  msgs.forEach((m, i) => {
    items.push({ index: i + 1, role: m.role, where: 'ข้อความ', text: m.text })
    for (const r of m.toolResults ?? []) items.push({ index: i + 1, role: m.role, where: 'ผลลัพธ์ของเครื่องมือ', text: r.text })
    for (const u of m.toolUses) items.push({ index: i + 1, role: m.role, where: `อินพุตของ ${u.tool}`, text: JSON.stringify(u.input) })
  })
  const found = scanTexts(items, policy)
  if (found.length === 0) {
    return [
      `Zscaler guard scan: ตรวจ ${msgs.length} ข้อความ ไม่พบค่าที่กฎรู้จัก`,
      'ถ้ายังโดน 403 สาเหตุอาจไม่ใช่เนื้อหาที่กฎนี้รู้จัก เช่น นโยบายหมวด URL ขนาดคำขอ รูปภาพ หรือ dictionary ที่องค์กรกำหนดเอง',
      'ให้แจ้งทีม Security พร้อมเวลาที่เกิด แล้วเพิ่มรูปแบบที่ได้รับใน customRedact หรือ customWithhold',
    ].join('\n')
  }
  const lines = found.map(f => {
    const kinds = Object.entries(f.kinds).map(([k, n]) => `${k}×${n}`).join(', ')
    return `  #${f.index} ${f.role} · ${f.where}: ${kinds}`
  })
  return [
    `Zscaler guard scan: ตรวจ ${msgs.length} ข้อความ พบค่าที่ DLP อาจบล็อก ${found.length} จุด (ไม่แสดงค่าจริง)`,
    ...lines,
    `ค่าเหล่านี้ถูกส่งไปแล้วและจะถูกส่งซ้ำทุกเทิร์น: ใช้ /rewind ย้อนไปก่อนข้อความ #${found[0].index} หรือ /clear แล้วเริ่มใหม่`,
  ].join('\n')
}

export const register: Register = (on, options) => {
  const { policy, errors } = compilePolicy(options)
  const withholdMedia = options.withholdMedia === true
  const customRedact = policy.rules.filter(r => r.kind === 'CUSTOM').length
  const cfg: Config = { policy, errors, withholdMedia, customRedact }

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'zscaler-guard',
      description: 'Zscaler DLP guard: redact | block | off | status | scan',
    })
    await showStatus($)
    if (errors.length) $.ui.toast(`zscaler-guard: ข้ามรูปแบบที่กำหนดเองซึ่งไม่ถูกต้อง ${errors.length} รายการ`)
    return next(e)
  })

  on('command.run', { command: 'zscaler-guard' }, async ($, e) => {
    const arg = e.args.trim().toLowerCase()
    const mode = MODES.find(m => m === arg)
    if (mode) {
      await update($, guardMode, () => mode)
      await showStatus($)
      return { text: `โหมด Zscaler guard → ${HELP[mode]}` }
    }
    if (arg === 'scan') return { text: await scan($, policy) }
    if (arg === '' || arg === 'status') return { text: await statusText($, cfg) }
    return { text: USAGE }
  })

  on('prompt.compose', async ($, e, next) => {
    const r = await next(e)
    return { sections: [...r.sections.filter(s => s.id !== POLICY_SECTION.id), POLICY_SECTION] }
  })

  // a slash command's arguments: prompt.submit cannot rewrite them, so they are masked here
  on('command.run', async ($, e, next) => {
    if (e.command === 'zscaler-guard') return next(e)
    const mode = await read($, guardMode)
    if (mode === 'off') return next(e)
    const v = guardText(e.args, newTags(await suffix($)), policy, 'command arguments')
    if (v.action === 'pass') return next(e)
    if (mode === 'block' || v.action === 'withhold') {
      $.ui.toast(`Zscaler guard: ไม่รัน /${e.command} เพราะอาร์กิวเมนต์มีค่าอ่อนไหว`)
      return { text: `zscaler-guard did not run /${e.command}: its arguments hold sensitive values. Remove them, or run /zscaler-guard redact.` }
    }
    $.ui.toast(`Zscaler guard: ปกปิด ${v.found} ค่าในอาร์กิวเมนต์ของ /${e.command}`)
    return next({ ...e, args: v.text })
  }).catch(($, e, next) =>
    next.called ? next(e) : { text: `zscaler-guard could not inspect the arguments of /${e.command}, so it did not run.` },
  )

  // the prompt first, so even the queue record of what was typed is clean
  on('prompt.submit', async ($, e, next) => {
    const mode = await read($, guardMode)
    if (mode === 'off' || e.command) return next(e) // a command's arguments were handled at command.run
    const tags = newTags(await suffix($))
    const v = guardText(e.text, tags, policy, 'prompt')
    const ctx = e.context?.map(c => guardText(c, tags, policy, 'prompt context'))
    const ctxFound = ctx?.some(c => c.action !== 'pass') ?? false
    if (v.action === 'pass' && !ctxFound) return next(e)

    // a hidden prompt that starts its own turn takes no rewrite: it can only be held back
    const canRewrite = !e.isMeta || Boolean(e.turnId)
    if (v.action === 'withhold' || !canRewrite || (mode === 'block' && v.action === 'redact')) {
      const why = v.action === 'withhold' ? v.reason : `${v.found} sensitive values`
      $.ui.toast(`Zscaler guard: ไม่ส่งพรอมต์นี้ให้ Claude (${why})`)
      return { drop: `zscaler-guard held this prompt back (${why}). Edit it, or run /zscaler-guard redact | off.` }
    }
    const t = newTally()
    t.redacted = v.found + (ctx?.reduce((n, c) => n + c.found, 0) ?? 0)
    await tallyUp($, t)
    if (t.redacted) $.ui.toast(summary(t))
    return next({ ...e, text: v.text, ...(ctx ? { context: ctx.map(c => c.text) } : {}) })
  }).catch(($, e, next) =>
    next.called ? next(e) : { drop: 'zscaler-guard could not inspect this prompt, so it was not sent. Try again, or run /zscaler-guard off.' },
  )

  // every row the conversation keeps, the model's own text blocks included: any matching value in
  // the history trips the DLP on every later request, whoever wrote it. Notices never reach the
  // model; compaction summaries are written from rows already guarded.
  on('session.append', async ($, e, next) => {
    if (e.door === 'compaction' || e.door === 'notice') return next(e)
    if ((await read($, guardMode)) === 'off') return next(e)
    const tally = newTally()
    const where = e.door === 'response' ? 'reply text' : 'content'
    const content = scrub(e.message.content, tally, newTags(await suffix($)), { policy, withholdMedia, where }) as typeof e.message.content
    if (!touched(tally)) return next(e)
    await tallyUp($, tally)
    $.ui.toast(summary(tally))
    return next({ ...e, message: { ...e.message, content } })
  }).catch(($, e, next) =>
    // fail closed: a row this mod could not inspect is stored as a note, not as it was
    next.called ? next(e) : next({ ...e, message: { ...e.message, content: sealed(e.message.content) as typeof e.message.content } }),
  )

  // text that rides a request without becoming a row: @file mentions, edited files, reminders
  on('prompt.attachment', async ($, e, next) => {
    if ((await read($, guardMode)) === 'off') return next(e)
    const v = guardText(e.text, newTags(await suffix($)), policy, 'attached file')
    if (v.action === 'pass') return next(e)
    if (v.action === 'withhold') $.ui.toast(`Zscaler guard: กันไฟล์แนบไว้ทั้งก้อน (${v.reason})`)
    return next({ ...e, text: v.text })
  }).catch(($, e, next) => (next.called ? next(e) : next({ ...e, text: withheldNote('attached file', 'zscaler-guard could not inspect it') })))

  // CLAUDE.md and the other context blocks
  on('prompt.context', async ($, e, next) => {
    if ((await read($, guardMode)) === 'off') return next(e)
    const tags = newTags(await suffix($))
    return next({ ...e, blocks: e.blocks.map(b => ({ ...b, text: guardText(b.text, tags, policy, 'context block').text })) })
  }).catch(($, e, next) =>
    next.called ? next(e) : next({ ...e, blocks: e.blocks.map(b => ({ ...b, text: withheldNote('context block', 'zscaler-guard could not inspect it') })) }),
  )

  // A tag used as a real value would corrupt the person's work: refuse. A literal sensitive value
  // the model put in a call is already in the history (no mod can rewrite a tool_use), so the most
  // useful thing is to say so now rather than at the next 403.
  on('tool.call', async ($, e, next) => {
    if ((await read($, guardMode)) === 'off') return next(e)
    const json = JSON.stringify(e)
    if (issuedTag(await suffix($)).test(json)) {
      return {
        deny: 'zscaler-guard hides sensitive values behind ZS_ tags. Do not use a tag as a real value; ask the user for it, or have them run /zscaler-guard off.',
      }
    }
    const n = findSensitive(json.slice(0, 200_000), policy).length
    if (n) $.ui.toast(`Zscaler guard: Claude ใส่ค่าอ่อนไหว ${n} ค่าในการเรียก ${String(e.tool)} ซึ่งจะถูกส่งซ้ำทุกเทิร์น ถ้าโดน 403 ให้ /rewind ไปก่อนข้อความนี้`)
    return next(e)
  })

  // recognise the block itself, so the person learns why and what to do
  on('classic.StopFailure', async ($, e, next) => {
    const said = `${e.error_details ?? ''}\n${e.last_assistant_message ?? ''}`
    if (ZSCALER.test(said) && ZS_AUTH.test(said) && !ZS_DLP.test(said)) {
      $.ui.toast('Zscaler ขอยืนยันตัวตน (403) ไม่ใช่การบล็อกข้อมูล: รัน /login ใหม่ หรือ re-authenticate ที่ Zscaler Client Connector ไม่ต้อง /rewind หรือ /clear ถ้ายังไม่ได้ให้แจ้ง IT ว่า endpoint ของ Claude ถูกบล็อก')
    } else if (ZSCALER.test(said)) {
      await update($, incidents, n => n + 1)
      await showStatus($)
      $.ui.toast('Zscaler บล็อกคำขอ (403): ข้อมูลที่อยู่ในบทสนทนาแล้วจะถูกส่งซ้ำทุกเทิร์น รัน /zscaler-guard scan เพื่อหาจุด แล้ว /rewind หรือ /clear')
    }
    return next(e)
  })
}
