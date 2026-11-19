import { expect, mock, test } from 'claude-code/testing'

import { CARD, TAG, j, thaiId } from './fixtures'

const ZS = new RegExp(`\\[${TAG}:ZS_CARD_1~[a-z0-9]+\\]`)
const PRESENTATION = { layout: 'main', columns: 100 } as const

test('a prompt reaches the engine redacted, with this session suffix', async ($, on) => {
  let entered = ''
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  on('prompt.submit', (_$, e) => {
    entered = e.text
    return { ...e }
  })
  await $.prompt.submit({ text: `charge ${CARD} today`, wait: false, origin: { kind: 'composer' } })
  expect(entered).toMatch(ZS)
  expect(entered).not.toContain(CARD)
})

test('block mode holds the prompt back', async ($, on) => {
  let reached = false
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  on('command.register', () => ({ value: { command: 'zscaler-guard' } }))
  on('prompt.submit', (_$, e) => {
    reached = true
    return { ...e }
  })
  await $.command.run({ command: 'zscaler-guard', args: 'block', origin: { kind: 'composer' }, presentation: PRESENTATION } as never)
  const r = await $.prompt.submit({ text: `charge ${CARD} today`, wait: false, origin: { kind: 'composer' } })
  expect(reached).toBe(false)
  expect('drop' in r && r.drop).toMatch(/zscaler-guard held this prompt back/)
})

test('a tool result is stored redacted, and a dataset is stored as a note', async ($, on) => {
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  const session = mock.session(on)
  const rows = Array.from({ length: 30 }, (_, i) => thaiId(j('3', String(1000 + i), '20000', '55'))).join('\n')
  for (const [id, text] of [['t1', `card ${CARD}`], ['t2', rows]] as const) {
    await $.session.append({
      door: 'tool-result',
      origin: { kind: 'tool', tool: 'Read' },
      uuid: `u-${id}`,
      message: { type: 'user', role: 'user', content: [{ type: 'tool_result', tool_use_id: id, content: text }] },
    } as never)
  }
  const stored = session.appended().map(r => JSON.stringify(r.message.content))
  expect(stored[0]).toMatch(ZS)
  expect(stored[0]).not.toContain(CARD)
  expect(stored[1]).toContain('withheld and not sent (30 sensitive values')
})

test('a tool call that uses one of this session tags is refused', async ($, on) => {
  on('clock.now', () => ({ value: 1_700_000_000_000 }))
  let tagged = ''
  on('prompt.submit', (_$, e) => {
    tagged = (ZS.exec(e.text) ?? [''])[0]
    return { ...e }
  })
  on('tool.call', () => ({ result: {} }))
  await $.prompt.submit({ text: `charge ${CARD}`, wait: false, origin: { kind: 'composer' } })
  const r = await $.tool.call({ tool: 'Bash', command: `echo ${tagged}` } as never)
  expect(JSON.stringify(r)).toMatch(/zscaler-guard hides sensitive values/)
})

test('a 403 from Zscaler is counted and shown on the status line', async ($, on) => {
  let status: string | undefined
  on('ui.status', (_$, e) => {
    status = (e as { text?: string }).text
    return { value: undefined }
  })
  on('classic.StopFailure', () => ({}))
  await $.classic.StopFailure({ error: 'unknown', error_details: '403 Forbidden: Internet Security by Zscaler' } as never)
  expect(status).toBe('ZS: redact · 403×1')
})

test('a Zscaler sign-in 403 gets sign-in advice and is not counted as a DLP block', async ($, on) => {
  let status: string | undefined
  const toasts: string[] = []
  on('ui.status', (_$, e) => {
    status = (e as { text?: string }).text
    return { value: undefined }
  })
  on('ui.toast', (_$, e) => {
    toasts.push(String((e as { text?: string }).text))
    return { value: undefined }
  })
  on('classic.StopFailure', () => ({}))
  await $.classic.StopFailure({ error: 'authentication_failed', error_details: '403 Internet Security by Zscaler. Authentication failed, sign in again to continue.' } as never)
  expect(status).toBeUndefined()
  expect(toasts.join(' ')).toMatch(/\/login/)
  await $.classic.StopFailure({ error: 'unknown', error_details: '403 Internet Security by Zscaler: blocked by DLP policy' } as never)
  expect(status).toBe('ZS: redact · 403×1')
})

test('the system prompt gains the DLP section once', async ($, on) => {
  on('prompt.compose', () => ({ sections: [{ id: 'intro', text: 'hi', scope: 'shared' }] }))
  const r = await $.prompt.compose({ model: 'm', promptModel: 'm', surfaces: [], tools: [], outputStyle: null, traits: [] } as never)
  expect(r.sections.map(s => s.id)).toEqual(['intro', 'zscaler-guard:policy'])
})
