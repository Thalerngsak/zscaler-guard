import { expect, test } from 'claude-code/testing'

import { compilePolicy, findSensitive, guardText, MAX_SCAN, newTags, newTally, scrub, sealed } from '../hooks/detect'
import { AWS_ID, CARD, DB_URL, GH_TOKEN, IBAN, ID, ID_DASHED, j, luhn, PEM, TAG, thaiId } from './fixtures'

const kinds = (t: string) => findSensitive(t).map(s => s[2])
const red = (t: string) => guardText(t, newTags()).text

test('national IDs: Thai mod-11 with or without dashes, and Thai digits', () => {
  expect(kinds(`id ${ID}`)).toEqual(['THAI_ID'])
  expect(kinds(`id ${ID_DASHED}`)).toEqual(['THAI_ID'])
  const thai = ID.replace(/\d/g, d => String.fromCharCode(0x0e50 + Number(d)))
  expect(kinds(`เลขบัตร ${thai}`)).toEqual(['THAI_ID'])
  // one digit off fails the checksum
  const bad = ID.slice(0, 12) + String((Number(ID[12]) + 1) % 10)
  expect(kinds(`id ${bad}`)).toEqual([])
})

test('cards need a scheme prefix and Luhn; CVV and expiry only next to a label', () => {
  expect(kinds(`card ${CARD}`)).toEqual(['CARD'])
  // a 13-digit millisecond timestamp that passes Luhn is not a card (no scheme starts with 17)
  const ts = luhn(j('17944', '1572', '560'))
  expect(kinds(`at ${ts}`).includes('CARD')).toBe(false)
  expect(kinds('cvv: 123')).toEqual(['CARD_META'])
  expect(kinds('card expiry: 09/29')).toEqual(['CARD_META'])
  expect(kinds('"exp": "09/29"')).toEqual(['CARD_META'])
  expect(kinds('Expiry Date: 09/2029 (insurance policy)')).toEqual([])
  expect(kinds('"cvn": 1234')).toEqual([])
  expect(kinds('"exp": 1794415725')).toEqual([])
})

test('bank: IBAN by mod-97, SWIFT and account numbers by label', () => {
  expect(kinds(`pay to ${IBAN}`)).toEqual(['IBAN'])
  expect(kinds(`pay to ${IBAN.slice(0, -1)}9`).includes('IBAN')).toBe(IBAN.endsWith('9'))
  expect(kinds(j('SWIFT code: ', 'ABCD', 'TH', 'BK'))).toEqual(['SWIFT'])
  expect(kinds('the swift implementation of it')).toEqual([])
  expect(kinds(j('เลขที่บัญชี ', '123-4-56789-0'))).toEqual(['BANK_ACCOUNT'])
})

test('keys and tokens: PEM blocks whole, truncated PEM to its last key line', () => {
  const t = `before\n${PEM()}\nafter`
  expect(red(t)).toBe(`before\n[${TAG}:ZS_PRIVATE_KEY_1]\nafter`)
  const cut = j('-----BEGIN ', 'PRIVATE KEY-----\n', 'Q'.repeat(64), '\n', 'Q'.repeat(40), '\nnext paragraph')
  expect(red(cut)).toBe(`[${TAG}:ZS_PRIVATE_KEY_1]\nnext paragraph`)
  expect(kinds(GH_TOKEN)).toEqual(['SECRET'])
  expect(kinds(`id=${AWS_ID}`)).toEqual(['SECRET'])
  expect(red(DB_URL)).toBe(j('postgres://app:', `[${TAG}:ZS_SECRET_1]`, '@db.internal:5432/loans'))
})

test('code and placeholders are not secrets', () => {
  expect(kinds('password: string')).toEqual([])
  expect(kinds('token = os.environ.get("X")')).toEqual([])
  expect(kinds('postgres://app:${DB_PASS}@db/x')).toEqual([])
  expect(kinds('password = "********"')).toEqual([])
})

test('idempotent, and pdpa-thai tags are left alone', () => {
  const once = red(`card ${CARD} and id ${ID}`)
  expect(red(once)).toBe(once)
  const pdpa = `[${TAG}:CARD_1~abcde]`
  expect(red(`seen ${pdpa}`)).toBe(`seen ${pdpa}`)
  // the same value in one block keeps one tag; numbering skips numbers already present
  expect(red(`${CARD} / ${CARD}`)).toBe(`[${TAG}:ZS_CARD_1] / [${TAG}:ZS_CARD_1]`)
})

test('a dataset is withheld whole, not trimmed', () => {
  const rows = Array.from({ length: 30 }, (_, i) => `${i},${thaiId(j('3', String(1000 + i), '20000', '55'))}`).join('\n')
  const v = guardText(rows, newTags())
  expect(v.action).toBe('withhold')
  expect(v.text).toMatch(/^\[zscaler-guard: content withheld and not sent \(30 sensitive values/)
  // threshold 0 turns it off: the values are redacted instead
  const off = compilePolicy({ bulkThreshold: 0 }).policy
  expect(guardText(rows, newTags(), off).action).toBe('redact')
})

test('a dataset pdpa-thai already tagged is still withheld (hook order does not matter)', () => {
  const tagged = Array.from({ length: 30 }, (_, i) => `${i},[${TAG}:THAI_ID_${i + 1}~abcde]`).join('\n')
  const v = guardText(tagged, newTags())
  expect(v.action).toBe('withhold')
  expect(v.text).toContain('30 sensitive values')
  // a few tags alone are left as they are
  expect(guardText(`seen [${TAG}:CARD_1~abcde]`, newTags()).action).toBe('pass')
})

test('organisation patterns: customRedact redacts, customWithhold withholds, bad ones are reported', () => {
  const { policy, errors } = compilePolicy({ customRedact: 'CN-\\d{8} ;; (', customWithhold: '/strictly\\s+confidential/i' })
  expect(errors).toEqual(['customRedact: ('])
  expect(guardText('contract CN-12345678 ok', newTags(), policy).text).toBe(`contract [${TAG}:ZS_CUSTOM_1] ok`)
  const v = guardText('Strictly Confidential\nboard minutes', newTags(), policy)
  expect(v.action).toBe('withhold')
  expect(v.text).not.toContain('board minutes')
})

test('too large to inspect is withheld', () => {
  expect(guardText('a'.repeat(MAX_SCAN + 1), newTags()).action).toBe('withhold')
})

test('scrub rewrites text and tool results, drops media only when asked, seals on failure', () => {
  const t = newTally()
  const content = [
    { type: 'tool_result', tool_use_id: 't1', content: [{ type: 'text', text: `card ${CARD}` }, { type: 'image', source: {} }] },
    { type: 'tool_use', id: 'u1', name: 'Bash', input: { command: 'ls' } },
  ]
  const out = scrub(content, t, newTags('sfx01'), { withholdMedia: true }) as typeof content
  expect(t).toEqual({ redacted: 1, withheld: 0, media: 1 })
  expect(JSON.stringify(out)).toContain(`[${TAG}:ZS_CARD_1~sfx01]`)
  expect(JSON.stringify(out)).not.toContain('"image"')
  expect(out[1]).toEqual(content[1])

  const kept = scrub(content, newTally(), newTags(), {}) as typeof content
  expect(JSON.stringify(kept)).toContain('"image"')

  expect(JSON.stringify(sealed([{ type: 'text', text: `card ${CARD}` }]))).not.toContain(CARD)
})

test('every scan stays linear on hostile input (it runs on every tool result)', () => {
  const time = (s: string) => {
    const t0 = Date.now()
    findSensitive(s)
    return Date.now() - t0
  }
  const big = 200_000
  const inputs = [
    '1 '.repeat(big / 2),
    '@'.repeat(big),
    j('-----BEGIN ', 'PRIVATE KEY-----\n').repeat(big / 28),
    'password='.repeat(big / 9),
    'a://b:'.repeat(big / 6),
    'GB00 '.repeat(big / 5),
  ]
  for (const s of inputs) expect(time(s)).toBeLessThan(1500)
})

test('decimal and scientific numbers are measurements, not cards or IDs', () => {
  const frac = CARD.replace(/ /g, '')
  expect(kinds(`{"p": 0.${frac}}`)).toEqual([])
  expect(kinds(`[0.${frac}, -0.${frac}, .${frac}]`)).toEqual([])
  expect(kinds(`lat=13.${ID}`)).toEqual([])
  expect(kinds(`t=${ID}.5`)).toEqual([])
  expect(kinds(`v=${frac}e-5`)).toEqual([])
  // still a card or an ID after punctuation that is not a decimal point, and in a CSV field
  expect(kinds(`card no.${frac}`)).toEqual(['CARD'])
  expect(kinds(`1,${frac}\n2,${ID}`)).toEqual(['CARD', 'THAI_ID'])
  expect(kinds(`card ${CARD}.`)).toEqual(['CARD'])
})

test('digits inside hashes, UUIDs and build ids are not cards or IDs; Thai text glued to a number still is', () => {
  const frac = CARD.replace(/ /g, '')
  const uuid = `f9a1${frac.slice(0, 4)}-${frac.slice(4, 8)}-${frac.slice(8, 12)}-${frac.slice(12, 16)}-${'a1'.repeat(6)}`
  expect(kinds(`id: ${uuid}`)).toEqual([])
  expect(kinds(`sha deadbeef${frac}cafe`)).toEqual([])
  expect(kinds(`build-${ID}-x`)).toEqual([])
  expect(kinds(`บัตร${frac}`)).toEqual(['CARD'])
  expect(kinds(`เลขบัตรประชาชน${ID}ครับ`)).toEqual(['THAI_ID'])
  expect(kinds(`(${CARD.replace(/ /g, '-')})`)).toEqual(['CARD'])
})

test('corpus findings: version lists, two cards in one run, IBAN lengths, epoch times, Go :=', () => {
  const d = CARD.replace(/ /g, '')
  // browser version lists and SVG paths are not card formatting
  const versions = Array.from({ length: 120 }, (_, i) => String(i + 1)).join(' ')
  expect(kinds(versions)).toEqual([])
  // two cards on one line are both found, and nothing is left behind
  const two = `${CARD} ${CARD.replace(/ /g, '-')}`
  expect(kinds(two)).toEqual(['CARD', 'CARD'])
  expect(findSensitive(red(two))).toEqual([])
  // an IBAN-shaped id whose country length is wrong is not an IBAN
  expect(kinds(`MsgId ${IBAN}X`)).toEqual([])
  expect(kinds(`pay ${IBAN}`)).toEqual(['IBAN'])
  // a 13-digit epoch-milliseconds time next to a time label is a time
  const ms = thaiId(j('1', '7944', '15725', '60'))
  expect(kinds(`<created>${ms}</created>`)).toEqual([])
  expect(kinds(`"updatedAt": ${ms}`)).toEqual([])
  expect(kinds(`citizenId: ${ms}`)).toEqual(['THAI_ID'])
  // Go short assignment, keywords and small numbers are code; a literal is still a secret
  expect(kinds('token := jwt.GenInternal(ctx)')).toEqual([])
  expect(kinds('token := ""')).toEqual([])
  expect(kinds('const refreshToken = async () => ({})')).toEqual([])
  expect(kinds('this.setPrivateKey = function (pk) {')).toEqual([])
  expect(kinds('private_key: 17 values')).toEqual([])
  expect(kinds(j('password := "', 'n0t', 'Real', '"'))).toEqual(['SECRET'])
})

test('corpus findings, round 2: type signatures, arrows, minified code, SQL placeholders, id keys', () => {
  const d = CARD.replace(/ /g, '')
  expect(kinds('unregister(token: object): void')).toEqual([])
  expect(kinds('const f = token => {')).toEqual([])
  expect(kinds('{withCredentials:s,withXSRFToken:s,adapter:s}')).toEqual([])
  expect(kinds('getAuthHeader(accessToken: accessToken);')).toEqual([])
  expect(kinds('WHERE (transaction_token = ? and used = false)')).toEqual([])
  expect(kinds(`<string msgid="${d}" name="search">`)).toEqual([])
  expect(kinds(`"requestId": "${d}"`)).toEqual([])
  expect(kinds(`"cardNo": "${d}"`)).toEqual(['CARD'])
  expect(kinds(j('password = "', 'n0t', 'Real', '"'))).toEqual(['SECRET'])
})
