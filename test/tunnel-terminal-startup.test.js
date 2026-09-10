import test from 'node:test'
import assert from 'node:assert/strict'
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { serveTerminal } from '../src/tunnel-terminal-server.js'
import { decodeTermRow, makeTermRow, termId } from '../src/tunnel-terminal.js'

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const generation = 'a'.repeat(32), peerKey = 'STARTUP_TEST_PEER'
async function until(predicate) {
  const end = Date.now() + 8000
  while (Date.now() < end) { const value = predicate(); if (value) return value; await sleep(10) }
  throw new Error('startup fixture timed out')
}
function readRows(path, offset) {
  if (!existsSync(path)) return { rows: [], next: offset }
  const data = readFileSync(path), tail = data.subarray(offset), end = tail.lastIndexOf(10)
  return end < 0 ? { rows: [], next: offset } : {
    rows: tail.subarray(0, end).toString().split('\n').filter(Boolean).map(JSON.parse), next: offset + end + 1,
  }
}
function fixture(t, { delay = 30, startupTimeoutMs = 5000 } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'p2p-terminal-startup-'))
  const shell = join(dir, 'sh'), inbox = join(dir, 'inbox.jsonl'), statePath = join(dir, 'term-owner.json')
  // A real owned shell process that deliberately delays interpreter startup.
  writeFileSync(shell, `#!/bin/sh\nsleep ${delay}\nprintf ready > interpreter-started\nexec /bin/sh "$@"\n`, { mode: 0o700 })
  const controller = new AbortController(), sent = []
  let connected = true, info, failure
  const session = { dir, id: generation,
    requireLive: () => ({ id: generation, connected, peerKey, self: 'STARTUP_TEST_OWNER' }),
    readRows, appendOutbox: row => sent.push(decodeTermRow(row)) }
  const runner = serveTerminal({ session, allowKey: peerKey, shell, cwd: dir, startupTimeoutMs,
    signal: controller.signal, io: { stdout: { write() {} }, stderr: { write() {} } }, onReady: value => { info = value } })
  void runner.catch(error => { failure = error })
  t.after(async () => { controller.abort(); await runner.catch(() => {}); rmSync(dir, { recursive: true, force: true }) })
  return { dir, sent, runner, controller, state: () => JSON.parse(readFileSync(statePath, 'utf8')),
    ready: () => { if (failure) throw failure; return info },
    disconnect: () => { connected = false },
    send: payload => appendFileSync(inbox, JSON.stringify(makeTermRow(payload, peerKey)) + '\n'),
  }
}
const options = { skip: process.platform === 'win32', timeout: 15000 }

test('terminal startup waits for interpreter framing before ready and preserves the first command deadline', options, async t => {
  const f = fixture(t, { delay: 0.8 })
  const hello = { v: 1, type: 'hello', requestId: termId() }
  f.send(hello)
  await sleep(100)
  assert.equal(f.ready(), undefined)
  assert.equal(f.state().ready, false)
  assert.equal(f.sent.length, 0, 'no grant or output is published during initialization')
  const ready = await until(f.ready)
  assert.equal(existsSync(join(f.dir, 'interpreter-started')), true)
  assert.equal(ready.ready, true)
  await until(() => f.sent.find(event => event.type === 'ready'))
  const requestId = termId()
  f.send({ v: 1, type: 'exec', requestId, grantId: ready.grantId, generation,
    command: "printf first-command-proof", timeoutMs: 300, expiresAt: Date.now() + 1000, maxOutputBytes: 4096 })
  const result = await until(() => f.sent.find(event => event.type === 'exit' && event.requestId === requestId))
  assert.equal(result.code, 0)
  assert.equal(result.timedOut, false)
  assert.equal(f.sent.filter(event => event.type === 'data').map(event => Buffer.from(event.data, 'base64').toString()).join(''), 'first-command-proof')
})

test('terminal startup has a separate bounded deadline and cleans the unready shell', options, async t => {
  const f = fixture(t, { startupTimeoutMs: 200 })
  const pid = f.state().shellPid
  await assert.rejects(f.runner, /did not initialize within 200 ms/)
  assert.equal(f.state().active, false)
  assert.equal(f.state().ready, false)
  assert.equal(f.state().cleanupFailed, false)
  assert.equal(f.sent.length, 0)
  assert.equal(existsSync(join(f.dir, 'term-owner.lock')), false)
  assert.throws(() => process.kill(pid, 0), 'the unready shell is gone')
})

for (const action of ['local stop', 'interrupt', 'disconnect']) {
  test(`terminal startup responds to ${action} before granting execution`, options, async t => {
    const f = fixture(t), state = f.state()
    if (action === 'local stop') writeFileSync(join(f.dir, 'term-stop.json'), JSON.stringify({ grantId: state.grantId, generation }))
    else if (action === 'interrupt') f.controller.abort()
    else f.disconnect()
    const result = await f.runner
    assert.equal(result.cleanupFailed, false)
    assert.equal(f.ready(), undefined)
    assert.equal(f.state().active, false)
    assert.equal(f.sent.length, 0)
    assert.equal(existsSync(join(f.dir, 'term-owner.lock')), false)
    assert.throws(() => process.kill(state.shellPid, 0), 'the unready shell is gone')
  })
}
