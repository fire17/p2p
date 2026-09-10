import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, appendFileSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import { terminalClient } from '../bin/tunnel-terminal-client.js'
import { makeTermRow, decodeTermRow } from '../src/tunnel-terminal.js'

const owner = 'OWNER_AUTHENTICATED_KEY', other = 'WRONG_AUTHENTICATED_KEY'
const generation = 'a'.repeat(32), grantId = 'b'.repeat(32)
function fixture(t, onSend) {
  const dir = mkdtempSync(join(tmpdir(), 'p2p-terminal-client-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const inbox = join(dir, 'inbox.jsonl'), cursor = join(dir, 'cursor.json')
  writeFileSync(cursor, '{"offset":123}')
  const sent = [], output = [], errors = [], stdin = new PassThrough()
  let alive = true
  const f = { dir, inbox, sent, output, errors, stdin,
    row: payload => makeTermRow(payload, owner),
    receive: (payload, from = owner) => appendFileSync(inbox, JSON.stringify(makeTermRow(payload, from)) + '\n'),
    raw: row => appendFileSync(inbox, JSON.stringify(row) + '\n'),
    ready: request => ({ v: 1, type: 'ready', requestId: request.requestId, grantId, generation,
      serverTime: Date.now(), shell: 'fixture shell', interactive: 'line', maxOutputBytes: 1048576 }),
    event: (request, event) => ({ v: 1, ...event, requestId: request.requestId, grantId, generation }),
    exit: (request, code = 0, extra = {}) => f.receive(f.event(request, { type: 'exit', code, signal: null, timedOut: false, truncated: false, ...extra })),
    data: (request, text, stream = 'stdout') => f.receive(f.event(request, { type: 'data', stream, data: Buffer.from(text).toString('base64') })),
    setAlive: value => { alive = value },
    events: () => output.join('').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)),
    audit: () => existsSync(join(dir, 'term-client-audit.jsonl')) ? readFileSync(join(dir, 'term-client-audit.jsonl'), 'utf8') : '',
    run: (options = {}) => terminalClient({ verb: 'exec', pos: ['echo fixture'], flags: { timeout: 0.3 }, ...options,
      session: { dir, id: 'c'.repeat(32), self: 'CLIENT_KEY', peerKey: owner,
        requireLive: () => { if (!alive) throw Object.assign(new Error('daemon stopped'), { exitCode: 5 }) },
        appendOutbox: row => { const request = decodeTermRow(row); sent.push(request); onSend(request, f) } },
      io: { stdin, stdout: { write: text => output.push(text) }, stderr: { write: text => errors.push(text) } } }),
  }
  return f
}

test('terminal client: never sends exec without remote owner readiness; wire grant messages are not accepted', async t => {
  const f = fixture(t, (request, f) => {
    if (request.type === 'hello') {
      f.receive({ ...f.ready(request), type: 'grant' })
      f.receive({ v: 1, type: 'refused', requestId: request.requestId, reason: 'not-enabled' })
    }
  })
  assert.equal(await f.run(), 77)
  assert.deepEqual(f.sent.map(x => x.type), ['hello'])
  assert.equal(f.events().at(-1).code, 77)
})

test('terminal client: authenticated peer, grant, generation, request ID, and channel isolate terminal output', async t => {
  const f = fixture(t, (request, f) => {
    if (request.type === 'hello') {
      f.receive(f.ready(request), other)
      f.raw({ ...makeTermRow(f.ready(request), owner), channel: 'chat' })
      f.receive(f.ready(request))
    } else if (request.type === 'exec') {
      assert.equal(request.generation, generation, 'echo remote generation, not our different local generation')
      assert.equal(request.grantId, grantId)
      assert.ok(request.expiresAt > Date.now() && request.expiresAt <= Date.now() + 400)
      const bad = f.event(request, { type: 'data', stream: 'stdout', data: Buffer.from('spoof').toString('base64') })
      f.receive(bad, other)
      f.receive({ ...bad, grantId: 'd'.repeat(32) })
      f.receive({ ...bad, generation: 'd'.repeat(32) })
      f.receive({ ...bad, requestId: 'd'.repeat(32) })
      f.raw({ ...makeTermRow(bad, owner), channel: 'chat' })
      const accepted = f.row(f.event(request, { type: 'data', stream: 'stdout', data: Buffer.from('accepted').toString('base64') }))
      f.raw(accepted); f.raw(accepted)
      f.exit(request, 7)
    }
  })
  assert.equal(await f.run(), 7)
  assert.equal(f.events().filter(x => x.type === 'data').map(x => x.text).join(''), 'accepted')
  assert.equal(f.events().at(-1).code, 7)
  assert.equal(readFileSync(join(f.dir, 'cursor.json'), 'utf8'), '{"offset":123}', 'chat cursor never moved')
  assert.ok(f.audit().includes('commandHash'))
  assert.ok(!f.audit().includes('echo fixture') && !f.audit().includes('accepted'), 'audit does not copy command/output values')
})

test('terminal client: UTF-8 streaming retains multibyte text split between data frames', async t => {
  const text = 'שלום 🌻\n', bytes = Buffer.from(text)
  const f = fixture(t, (request, f) => {
    if (request.type === 'hello') f.receive(f.ready(request))
    else if (request.type === 'exec') {
      for (const byte of bytes) f.receive(f.event(request, { type: 'data', stream: 'stdout', data: Buffer.from([byte]).toString('base64') }))
      f.exit(request)
    }
  })
  assert.equal(await f.run(), 0)
  assert.equal(f.events().filter(x => x.type === 'data').map(x => x.text).join(''), text)
})

test('terminal client: oversized unrelated chat row is skipped without consuming chat or blocking terminal', async t => {
  const f = fixture(t, (request, f) => {
    if (request.type === 'hello') {
      f.raw({ v: 1, from: owner, id: 'chat', text: 'x'.repeat(1048576) })
      f.receive(f.ready(request))
    } else if (request.type === 'exec') f.exit(request)
  })
  assert.equal(await f.run({ flags: { timeout: 2 } }), 0)
  assert.equal(readFileSync(join(f.dir, 'cursor.json'), 'utf8'), '{"offset":123}')
})

test('terminal client: timeout emits a structured failure and one grant-bound cancellation', async t => {
  const f = fixture(t, (request, f) => { if (request.type === 'hello') f.receive(f.ready(request)) })
  const began = Date.now()
  assert.equal(await f.run({ flags: { timeout: 0.1 } }), 124)
  assert.ok(Date.now() - began < 1000)
  const cancels = f.sent.filter(x => x.type === 'cancel')
  assert.equal(cancels.length, 1)
  assert.equal(cancels[0].requestId, f.sent.find(x => x.type === 'exec').requestId)
  assert.equal(cancels[0].grantId, grantId)
  assert.equal(f.events().at(-1).code, 124)
})

test('terminal client: excessive output is bounded and cancelled; truncation never reports CLI success', async t => {
  const f = fixture(t, (request, f) => {
    if (request.type === 'hello') f.receive({ ...f.ready(request), maxOutputBytes: 4 })
    else if (request.type === 'exec') f.data(request, 'too much output')
  })
  assert.equal(await f.run(), 75)
  assert.equal(f.events().filter(x => x.type === 'data').length, 0)
  assert.equal(f.sent.filter(x => x.type === 'cancel').length, 1)
  const g = fixture(t, (request, f) => {
    if (request.type === 'hello') f.receive(f.ready(request))
    else if (request.type === 'exec') f.exit(request, 0, { truncated: true })
  })
  assert.equal(await g.run(), 75)
  assert.equal(g.events().at(-1).truncated, true)
})

test('terminal client: cancellation and failed process cleanup remain non-success even with remote code zero', async t => {
  for (const [flag, expectedCode] of [['cancelled', 130], ['cleanupFailed', 75]]) {
    const f = fixture(t, (request, f) => {
      if (request.type === 'hello') f.receive(f.ready(request))
      else if (request.type === 'exec') f.exit(request, 0, { [flag]: true })
    })
    assert.equal(await f.run(), expectedCode)
    assert.equal(f.events().at(-1)[flag], true)
    assert.equal(f.events().at(-1).code, 0, 'retain original command exit in structured result')
  }
})

test('terminal client: local secret literals and oversized requests are refused before exec transmission', async t => {
  const key = 'P2P_TERMINAL_FIXTURE_SECRET', previous = process.env[key]
  process.env[key] = 'fixture-only-secret-2819'
  t.after(() => { if (previous === undefined) delete process.env[key]; else process.env[key] = previous })
  const f = fixture(t, () => assert.fail('secret-bearing command must not reach transport'))
  await assert.rejects(f.run({ pos: ['echo fixture-only-secret-2819'] }), /local secret value/)
  assert.deepEqual(f.sent, [])
  assert.equal(f.audit(), '')
  const g = fixture(t, (request, f) => { if (request.type === 'hello') f.receive(f.ready(request)) })
  assert.equal(await g.run({ pos: ['\u0001'.repeat(32768)] }), 2)
  assert.deepEqual(g.sent.map(x => x.type), ['hello'])
})

test('terminal client: revoked grant and stopped local daemon cannot continue a request', async t => {
  const f = fixture(t, (request, f) => {
    if (request.type === 'hello') f.receive(f.ready(request))
    else if (request.type === 'exec') f.receive(f.event(request, { type: 'refused', reason: 'revoked' }))
  })
  assert.equal(await f.run(), 77)
  const g = fixture(t, (request, f) => {
    if (request.type === 'hello') f.receive(f.ready(request))
    else if (request.type === 'exec') f.setAlive(false)
  })
  assert.equal(await g.run(), 5)
})

test('terminal shell: idle SIGINT closes input instead of swallowing Ctrl-C forever', async t => {
  const f = fixture(t, (request, f) => {
    if (request.type === 'hello') {
      f.receive(f.ready(request))
      setTimeout(() => process.emit('SIGINT'), 40)
    }
  })
  const before = process.listenerCount('SIGINT')
  const timer = setTimeout(() => f.stdin.end(), 1000)
  t.after(() => clearTimeout(timer))
  assert.equal(await f.run({ verb: 'shell', pos: [] }), 130)
  assert.equal(f.sent.some(x => x.type === 'exec'), false)
  assert.equal(process.listenerCount('SIGINT'), before)
})
