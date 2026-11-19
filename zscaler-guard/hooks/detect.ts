// zscaler-guard: detection, redaction and withholding.
//
// The method is pdpa-thai's (boombignose-mods, MIT (c) 2026 Boom-Vitt): rules run on a shadow of
// the text with the same length, overlapping spans merge, each value becomes a tag the model can
// still refer to, a tag is never detected again (so passes are idempotent and the mod coexists
// with pdpa-thai's tags), and no mapping back to the value is kept.
//
// What is new here:
//   1. the rule set aims at what corporate DLP (Zscaler) usually blocks: payment cards with their
//      CVV/expiry, national IDs, bank/IBAN/SWIFT, private keys, cloud tokens, credentials in URLs;
//   2. a second class of rule that WITHHOLDS a whole block (a dataset, a restricted document)
//      instead of trimming values out of it;
//   3. organisation-supplied patterns (userConfig), so the rules can mirror the actual DLP policy.
//
// The line held throughout: a value is removed, never disguised. Nothing is encoded, split or
// swapped for look-alike characters. The data does not leave the machine, which is exactly what
// the DLP policy asks for; the 403 goes away as a consequence, not as the goal.

export type Kind =
  | 'THAI_ID' | 'CARD' | 'CARD_META' | 'SSN' | 'IBAN' | 'SWIFT' | 'BANK_ACCOUNT'
  | 'PASSPORT' | 'PRIVATE_KEY' | 'SECRET' | 'CUSTOM'
export type Span = [start: number, end: number, kind: Kind]
type Hit = [number, number]
export type Rule = { kind: Kind; find: (s: string) => Iterable<Hit> }

// Same-length shadow: Thai digits become Arabic, exotic horizontal spaces become ' '.
const norm = (t: string) =>
  t
    .replace(/[๐-๙]/g, c => String.fromCharCode(c.charCodeAt(0) - 0x0e50 + 48))
    .replace(/[\u00a0\u2000-\u200a\u202f\u205f\u3000\t]/g, ' ')

const digits = (s: string) => s.replace(/\D/g, '')

// ---------------------------------------------------------------- validators

// mod-11 check digit of a 13-digit Thai national / juristic ID
export const thaiIdOk = (s: string) => {
  const d = digits(s)
  if (d.length !== 13 || d[0] === '0' && d[1] === '0') return false
  let sum = 0
  for (let i = 0; i < 12; i++) sum += Number(d[i]) * (13 - i)
  return (11 - (sum % 11)) % 10 === Number(d[12])
}

export const luhnOk = (d: string) => {
  let sum = 0
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i])
    if (i % 2) n = n * 2 > 9 ? n * 2 - 9 : n * 2
    sum += n
  }
  return sum % 10 === 0
}

// Issuer prefixes of the card schemes in use in Thailand and abroad (Visa, Mastercard incl. the
// 2-series, Amex, Diners, JCB, UnionPay/Discover/local 6-series). Cuts the false positives a bare
// Luhn check gives on timestamps and order numbers (pdpa-thai documents those).
const IIN = /^(?:4|5[1-5]|2(?:22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720)|3\d|6)/

// A digit run that is part of a decimal or scientific number is a measurement, not an identifier:
// 0.4532…, .4532…, 1794415725609.5, 4532…e-5 (coordinates, probabilities, model weights, epoch
// times with fractions, all common in JSON and CSV). A '.' right after a letter (no.4532…) is
// punctuation and still counts.
// A digit run glued to Latin letters, or continuing a hyphenated alphanumeric token, is part of a
// hash, a UUID or a build id (9d9b…4532…fa9, …d1-2345-6789-…), not a card or an ID. Thai letters
// stay allowed: Thai is written without spaces (บัตร4532…).
const NOT_DECIMAL_BEFORE = String.raw`(?<![^A-Za-z฀-๿]\.|^\.)(?<![A-Za-z_])(?<![A-Za-z0-9_]-)`
const NOT_DECIMAL_AFTER = String.raw`(?!\.\d)(?![eE][+-]?\d)(?![A-Za-z_])(?!-[A-Za-z0-9_])`

// IBAN length by country (SWIFT IBAN registry): a real IBAN has its country's exact length
const IBAN_LEN: Record<string, number> = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29, BY: 28, CH: 21, CR: 22, CY: 28,
  CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29, ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18,
  GR: 27, GT: 28, HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20, LB: 28, LC: 32,
  LI: 21, LT: 20, LU: 20, LV: 21, MC: 27, MD: 24, ME: 22, MK: 19, MR: 27, MT: 31, MU: 30, NL: 18, NO: 15, PK: 24,
  PL: 28, PS: 29, PT: 25, QA: 29, RO: 24, RS: 22, SA: 24, SC: 31, SE: 24, SI: 19, SK: 24, SM: 27, ST: 25, SV: 28,
  TL: 23, TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, XK: 20,
}

// ISO 13616: the country's length, then mod-97
export const ibanOk = (s: string) => {
  const t = s.replace(/ /g, '').toUpperCase()
  if (IBAN_LEN[t.slice(0, 2)] !== t.length) return false
  const r = t.slice(4) + t.slice(0, 4)
  let m = 0
  for (const ch of r) {
    const v = ch >= 'A' && ch <= 'Z' ? String(ch.charCodeAt(0) - 55) : ch
    for (const c of v) m = (m * 10 + Number(c)) % 97
  }
  return m === 1
}

// a value that is code or a placeholder, not a secret
const CODE_VALUE =
  /^(?:string|number|boolean|any|unknown|undefined|null|true|false|void|never|object|str|int|bool|None|Optional.*|Record.*|[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+(?:[(\[].*)?|[A-Za-z_$][\w$]*\(.*|\$\{.*|\$[A-Za-z_]\w*|\{\{.*|<.*>|%\(.*|\*+|x+|X+|\.{3}|changeme|redacted|REDACTED|function|async|await|new|this|self|return|lambda|def|func|fn|nil|NULL|nullptr|[(\[{=>?].*|\d{1,3}|[A-Za-z_$][\w$]?|[A-Za-z_$][\w$]*[)\]].*)$/

// ---------------------------------------------------------------- rule builders

function re(kind: Kind, regex: RegExp, o: { groups?: number[]; ok?: (v: string) => boolean } = {}): Rule {
  return {
    kind,
    *find(s) {
      for (const m of s.matchAll(regex)) {
        const at = (o.groups ?? [0]).map(g => m.indices?.[g]).find(Boolean)
        if (at && at[1] > at[0] && (!o.ok || o.ok(s.slice(at[0], at[1])))) yield [at[0], at[1]]
      }
    },
  }
}

// a run of digit groups split by single spaces or hyphens; Thai digits are already Arabic here
const CARD_RUN = new RegExp(String.raw`(?<!\d)${NOT_DECIMAL_BEFORE}\d+(?:[ -]\d+)*(?!\d)${NOT_DECIMAL_AFTER}`, 'g')

// How cards are written: one unbroken run, or groups of 4 to 6 digits (4-4-4-4, Amex 4-6-5,
// Diners 4-6-4) with a last group of 1 to 6. Lists of short numbers (browser versions 3 4 5 ...
// 12 13, SVG path data, minified tables) are not card formatting.
function cardShape(groups: [number, number][], i: number, j: number) {
  if (i === j) return true
  for (let k = i; k < j; k++) {
    const n = groups[k][1] - groups[k][0]
    if (n < 4 || n > 6) return false
  }
  const last = groups[j][1] - groups[j][0]
  return last >= 1 && last <= 6
}

// Every card in a run, left to right: at each group, the longest span of 13-19 digits that has a
// card's shape and scheme prefix and passes Luhn; after a hit, carry on past it. Nothing a pass
// leaves can form a card, so a second pass finds nothing (idempotent).
// a number under a key that names it an id of something else (Android msgid=, requestId:, traceId)
const ID_KEY = /(?:msg|message|request|trace|span|order|txn|transaction|correlation|event|session|ref|reference)[_-]?id["']?[ \t]*[:=][ \t]*["']?$/i

function* cards(s: string): Iterable<Hit> {
  for (const m of s.matchAll(CARD_RUN)) {
    const base = m.index
    if (ID_KEY.test(s.slice(Math.max(0, base - 40), base))) continue
    const groups: [number, number][] = []
    for (const g of m[0].matchAll(/\d+/g)) groups.push([g.index, g.index + g[0].length])
    let i = 0
    while (i < groups.length) {
      let hit = -1
      let count = 0
      for (let j = i; j < groups.length; j++) {
        count += groups[j][1] - groups[j][0]
        if (count > 19) break
        if (count < 13 || !cardShape(groups, i, j)) continue
        const d = digits(m[0].slice(groups[i][0], groups[j][1]))
        if (IIN.test(d) && luhnOk(d)) hit = j
      }
      if (hit === -1) i++
      else {
        yield [base + groups[i][0], base + groups[hit][1]]
        i = hit + 1
      }
    }
  }
}

// PEM / PGP private key blocks, scanned with indexOf so no input makes it quadratic. A block with
// no END line (a truncated paste) is hidden up to the last line that still looks like key data.
function* privateKeys(s: string): Iterable<Hit> {
  const head = /-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----/g
  for (let m = head.exec(s); m; m = head.exec(s)) {
    const endTag = `-----END ${m[1]}-----`
    const e = s.indexOf(endTag, head.lastIndex)
    let stop: number
    if (e !== -1) stop = e + endTag.length
    else {
      stop = head.lastIndex
      for (let at = s.indexOf('\n', stop); at !== -1 && at < s.length; ) {
        const nl = s.indexOf('\n', at + 1)
        const line = s.slice(at + 1, nl === -1 ? s.length : nl)
        if (!/^[ \t]*(?:[A-Za-z0-9+/=]{16,}|Proc-Type:.*|DEK-Info:.*|Comment:.*|Version:.*)?[ \t\r]*$/.test(line)) break
        stop = nl === -1 ? s.length : nl
        if (nl === -1) break
        at = nl
      }
    }
    yield [m.index, stop]
    head.lastIndex = Math.max(stop, head.lastIndex)
  }
}

const THAI_ID_RUN = new RegExp(String.raw`(?<!\d)${NOT_DECIMAL_BEFORE}[1-8][ -]?\d{4}[ -]?\d{5}[ -]?\d{2}[ -]?\d(?!\d)${NOT_DECIMAL_AFTER}`, 'g')
// 13 unbroken digits starting with 1 are also milliseconds since 1970 (2001-2033). Next to a time
// label (<created>, "updatedAt":, timestamp=) they are a time, not a person.
const TIME_LABEL = /(?:time|date|created|updated|modified|stamp|expir|epoch|milli|since|until|\bts|\bms|_at|[a-z]At)["'>\]\s:=]{0,6}$/i

function* thaiIds(s: string): Iterable<Hit> {
  for (const m of s.matchAll(THAI_ID_RUN)) {
    const v = m[0]
    if (!thaiIdOk(v)) continue
    if (/^1\d{12}$/.test(v) && TIME_LABEL.test(s.slice(Math.max(0, m.index - 40), m.index))) continue
    yield [m.index, m.index + v.length]
  }
}

const SECRET_LABEL =
  'password|passwd|pwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|' +
  'AccountKey|SharedAccessKey|SharedAccessSignature|รหัสผ่าน'

// ---------------------------------------------------------------- the built-in rule pack

export const BUILTIN: readonly Rule[] = [
  // national IDs
  { kind: 'THAI_ID', find: thaiIds },
  re('SSN', /(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/gd),
  re('PASSPORT', /(?:passport|เลขที่หนังสือเดินทาง|เลขพาสปอร์ต|พาสปอร์ต)\D{0,20}?([A-Z]{1,2}\d{6,8})\b/gdi, { groups: [1] }),

  // payment cards and what travels with them
  { kind: 'CARD', find: cards },
  re('CARD_META', /(?:cvv2?|cvc2?|card[ _-]?security[ _-]?code|security[ _-]?code|รหัสหลังบัตร)["']?[ \t]*[:=：][ \t]*["']?(\d{3,4})(?!\d)/gdi, { groups: [1] }),
  re(
    'CARD_META',
    /(?:\bexp|card[ _-]?exp(?:iry|iration)?(?:[ _-]?date)?|exp(?:iry|iration)?[ _-]?(?:month|mm)|valid[ _-]?thru|วันหมดอายุบัตร|บัตรหมดอายุ)["']?[ \t]*[:=：][ \t]*["']?((?:0[1-9]|1[0-2])[ \t]?[/-][ \t]?(?:\d{4}|\d{2}))(?!\d)/gdi,
    { groups: [1] },
  ),

  // bank accounts
  re('IBAN', /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/gd, { ok: ibanOk }),
  re('SWIFT', /(?:SWIFT|Swift|swift|BIC|Bic|bic)(?:[ _-]?(?:CODE|Code|code))?["']?[ \t]*[:=：][ \t]*["']?([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/gd, { groups: [1] }),
  re('BANK_ACCOUNT', /(?:เลขที่บัญชี|หมายเลขบัญชี|บัญชี|account[ \t]*(?:no\.?|number|#)|acct\.?|พร้อมเพย์|promptpay)\D{0,15}((?:\d[ -]?){9,14}\d)/gdi, { groups: [1] }),

  // keys, tokens, credentials
  { kind: 'PRIVATE_KEY', find: privateKeys },
  re(
    'SECRET',
    /\b(?:sk-[A-Za-z0-9_-]{20,}|[sr]k_live_[0-9A-Za-z]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{36}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/gd,
  ),
  re('SECRET', /\bBearer[ \t]+([A-Za-z0-9._~+/=-]{20,})/gdi, { groups: [1] }),
  re('SECRET', /Authorization["']?[ \t]*[:=][ \t]*["']?Basic[ \t]+([A-Za-z0-9+/]{8,}={0,2})/gdi, { groups: [1] }),
  re(
    'SECRET',
    new RegExp(`(?:${SECRET_LABEL})["']?[ \\t]*(?::=|[:=])[ \\t]*(?:"((?:[^"\\\\\\n]|\\\\.)*)"|'((?:[^'\\\\\\n]|\\\\.)*)'|([^\\s"',;]+))`, 'gdi'),
    { groups: [1, 2, 3], ok: v => !CODE_VALUE.test(v) },
  ),
  // the password part of scheme://user:password@host (database URLs, JDBC, AMQP, Redis, ...)
  re('SECRET', /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@"'<>]{1,64}:([^\s@/"'<>]{1,128})@/gdi, { groups: [1], ok: v => !CODE_VALUE.test(v) }),
]

// ---------------------------------------------------------------- policy (built-in + organisation)

export type Policy = {
  rules: readonly Rule[]
  // a block matching any of these is withheld whole: the organisation marks it as restricted
  withhold: readonly RegExp[]
  // a block with this many detected values or more is withheld whole (a dataset); 0 = off
  bulk: number
}

export type PolicyOptions = {
  customRedact?: unknown
  customWithhold?: unknown
  bulkThreshold?: unknown
}

const MAX_CUSTOM = 50

// `a ;; b` or one per line; `/body/flags` keeps flags (i, m, s, u)
function patterns(v: unknown): string[] {
  const list = Array.isArray(v) ? v : typeof v === 'string' ? v.split(/\n|;;/) : []
  return list.map(p => String(p).trim()).filter(Boolean).slice(0, MAX_CUSTOM)
}

function compile(p: string, extra: string): RegExp {
  const lit = /^\/(.+)\/([imsu]*)$/s.exec(p)
  return lit ? new RegExp(lit[1], lit[2] + extra) : new RegExp(p, extra)
}

export function compilePolicy(o: PolicyOptions = {}): { policy: Policy; errors: string[] } {
  const errors: string[] = []
  const custom: Rule[] = []
  for (const p of patterns(o.customRedact)) {
    try {
      custom.push(re('CUSTOM', compile(p, 'gd')))
    } catch {
      errors.push(`customRedact: ${p}`)
    }
  }
  const withhold: RegExp[] = []
  for (const p of patterns(o.customWithhold)) {
    try {
      withhold.push(compile(p, ''))
    } catch {
      errors.push(`customWithhold: ${p}`)
    }
  }
  const n = Number(o.bulkThreshold ?? 25)
  return { policy: { rules: [...BUILTIN, ...custom], withhold, bulk: Number.isFinite(n) && n > 0 ? Math.floor(n) : 0 }, errors }
}

export const DEFAULT_POLICY = compilePolicy().policy

// ---------------------------------------------------------------- tags

// Same tag shape as pdpa-thai, kinds prefixed ZS_ so a reader can tell which guard acted. Either
// mod skips the other's tags, so running both is idempotent.
const TAG = 'RE' + 'DACTED'
const PLACEHOLDER = new RegExp(`\\[${TAG}:([A-Z_]+)_(\\d+)(?:~[a-z0-9]+)?\\]`, 'g')

export const issuedTag = (sfx: string) => new RegExp(`\\[${TAG}:ZS_[A-Z_]+_\\d+~${sfx}\\]`)

export type Tags = { sfx: string; seen: Map<string, number>; counts: Record<string, number> }
export const newTags = (sfx = ''): Tags => ({ sfx, seen: new Map(), counts: {} })

export function findSensitive(text: string, policy: Policy = DEFAULT_POLICY): Span[] {
  const s = norm(text)
  const found: Span[] = []
  for (const rule of policy.rules) for (const [a, b] of rule.find(s)) found.push([a, b, rule.kind])
  found.sort((x, y) => x[0] - y[0] || y[1] - x[1])

  // a tag from an earlier pass (ours or pdpa-thai's) is never detected again
  const held = [...s.matchAll(PLACEHOLDER)].map(m => [m.index, m.index + m[0].length])
  const free = held.length ? found.filter(([a, b]) => !held.some(([ha, hb]) => a < hb && b > ha)) : found

  const merged: Span[] = []
  for (const sp of free) {
    const last = merged[merged.length - 1]
    if (last && sp[0] < last[1]) last[1] = Math.max(last[1], sp[1])
    else merged.push([sp[0], sp[1], sp[2]])
  }
  return merged
}

function replace(text: string, spans: Span[], tags: Tags): string {
  const s = norm(text)
  for (const m of s.matchAll(PLACEHOLDER)) tags.counts[m[1]] = Math.max(tags.counts[m[1]] ?? 0, Number(m[2]))
  let out = ''
  let at = 0
  for (const [a, b, kind] of spans) {
    const k = `ZS_${kind}`
    const key = `${k}:${s.slice(a, b)}`
    let n = tags.seen.get(key)
    if (!n) {
      n = tags.counts[k] = (tags.counts[k] ?? 0) + 1
      tags.seen.set(key, n)
    }
    out += `${text.slice(at, a)}[${TAG}:${k}_${n}${tags.sfx ? `~${tags.sfx}` : ''}]`
    at = b
  }
  return out + text.slice(at)
}

// ---------------------------------------------------------------- the verdict on one piece of text

// Past this size the text is not scanned at all: it is withheld (what a DLP proxy does with
// content it cannot inspect), and the per-hook time budget is never at risk.
export const MAX_SCAN = 1_000_000

export type Verdict =
  | { action: 'pass'; text: string; found: 0 }
  | { action: 'redact'; text: string; found: number }
  | { action: 'withhold'; text: string; found: number; reason: string }

export const withheldNote = (where: string, reason: string) =>
  `[zscaler-guard: ${where} withheld and not sent (${reason}). ` +
  'Ask the user for a small de-identified sample, the column names or a summary instead.]'

export function guardText(text: string, tags: Tags, policy: Policy = DEFAULT_POLICY, where = 'content'): Verdict {
  if (text.length > MAX_SCAN) {
    const reason = `${text.length} characters, too large to inspect locally`
    return { action: 'withhold', text: withheldNote(where, reason), found: 0, reason }
  }
  const marker = policy.withhold.findIndex(r => r.test(text))
  if (marker !== -1) {
    const reason = `matches restricted-content rule #${marker + 1} set by your organisation`
    return { action: 'withhold', text: withheldNote(where, reason), found: 0, reason }
  }
  const spans = findSensitive(text, policy)
  // Values another guard (pdpa-thai) already turned into tags still count: which hook runs first
  // must not decide whether a dataset is withheld or merely trimmed.
  const prior = policy.bulk > 0 ? [...text.matchAll(PLACEHOLDER)].length : 0
  if (policy.bulk > 0 && spans.length + prior >= policy.bulk) {
    const n = spans.length + prior
    const reason = `${n} sensitive values, which looks like a dataset`
    return { action: 'withhold', text: withheldNote(where, reason), found: spans.length, reason }
  }
  if (spans.length === 0) return { action: 'pass', text, found: 0 }
  return { action: 'redact', text: replace(text, spans, tags), found: spans.length }
}

// ---------------------------------------------------------------- a row's content

export type Tally = { redacted: number; withheld: number; media: number }
export const newTally = (): Tally => ({ redacted: 0, withheld: 0, media: 0 })
export const touched = (t: Tally) => t.redacted + t.withheld + t.media > 0

type ScrubOptions = { policy?: Policy; withholdMedia?: boolean; where?: string }

const MEDIA_NOTE = '[zscaler-guard: an image or document was withheld and not sent (withholdMedia is on).]'

// A row's content is a string or blocks. Text and tool_result content are rewritten; an image or
// document is dropped for a note only when withholdMedia is on. Everything else (tool_use,
// thinking) is left as is; the engine pins it. One tag table per row.
export function scrub(content: unknown, tally: Tally, tags: Tags, o: ScrubOptions = {}): unknown {
  const policy = o.policy ?? DEFAULT_POLICY
  const where = o.where ?? 'content'
  const one = (text: string) => {
    const v = guardText(text, tags, policy, where)
    if (v.action === 'redact') tally.redacted += v.found
    if (v.action === 'withhold') tally.withheld++
    return v.text
  }
  if (typeof content === 'string') return one(content)
  if (!Array.isArray(content)) return content
  return content.map(block => {
    if (block?.type === 'text' && typeof block.text === 'string') return { ...block, text: one(block.text) }
    if (block?.type === 'tool_result') return { ...block, content: scrub(block.content, tally, tags, { ...o, where: 'tool output' }) }
    if (o.withholdMedia && (block?.type === 'image' || block?.type === 'document')) {
      tally.media++
      return { type: 'text', text: MEDIA_NOTE }
    }
    return block
  })
}

// What a failing hook leaves in place of a row's text: fail closed, never fail open.
export function sealed(content: unknown): unknown {
  const note = withheldNote('content', 'zscaler-guard could not inspect it')
  if (typeof content === 'string') return note
  if (!Array.isArray(content)) return content
  return content.map(block =>
    block?.type === 'text' ? { ...block, text: note } : block?.type === 'tool_result' ? { ...block, content: note } : block,
  )
}

// ---------------------------------------------------------------- scanning what is already sent

export type Finding = { index: number; role: string; where: string; kinds: Partial<Record<Kind | 'RESTRICTED', number>> }

export function scanTexts(items: { index: number; role: string; where: string; text: string }[], policy: Policy = DEFAULT_POLICY): Finding[] {
  const out: Finding[] = []
  for (const it of items) {
    if (!it.text) continue
    const kinds: Finding['kinds'] = {}
    if (policy.withhold.some(r => r.test(it.text))) kinds.RESTRICTED = 1
    for (const [, , k] of findSensitive(it.text.slice(0, MAX_SCAN), policy)) kinds[k] = (kinds[k] ?? 0) + 1
    if (Object.keys(kinds).length) out.push({ index: it.index, role: it.role, where: it.where, kinds })
  }
  return out
}
