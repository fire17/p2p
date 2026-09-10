import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, appendFileSync, readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, delimiter } from 'node:path'
import { spawnSync } from 'node:child_process'
import { serveTerminal } from '../src/tunnel-terminal-server.js'
import { terminalClient } from '../bin/tunnel-terminal-client.js'
import { makeTermRow, decodeTermRow, termId } from '../src/tunnel-terminal.js'

const ownerGeneration = 'a'.repeat(32), allowed = 'AUTHENTICATED_ALLOWED_PEER'
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const powerShell = shell => /powershell|pwsh/i.test(shell)
const quote = (value, shell) => powerShell(shell) ? "'" + value.replaceAll("'", "''") + "'" : "'" + value.replaceAll("'", "'\\''") + "'"
const program = (shell, script) => {
  // Windows PowerShell 5.1's native argument adapter strips embedded double
  // quotes. Keep this fixture's Node argument independent of that legacy parser;
  // the actual terminal command still traverses the real chosen shell.
  const encoded = Buffer.from(script).toString('base64')
  // Bun's eval scope does not inherit its synthetic module-level require.
  const argument = `Function('require',Buffer.from('${encoded}','base64').toString('utf8'))(require)`
  return (powerShell(shell) ? '& ' : '') + quote(process.execPath, shell) + ' -e ' + quote(argument, shell)
}
function available(shell) {
  return existsSync(shell) || (process.env.PATH || '').split(delimiter).some(dir => existsSync(join(dir, shell)) || existsSync(join(dir, shell + '.exe')))
}
const shells = process.platform === 'win32' ? ['pwsh', 'powershell.exe'] : ['/bin/sh', 'pwsh']
test('required Windows CI shells are real PowerShell 7 and Windows PowerShell 5.1', {
  skip: process.env.P2P_REQUIRE_WINDOWS_SHELLS !== '1',
}, () => {
  assert.equal(process.platform, 'win32', 'P2P_REQUIRE_WINDOWS_SHELLS=1 requires an actual Windows runner')
  for (const [shell, expected] of [['pwsh', /^7\./], ['powershell.exe', /^5\.1\./]]) {
    assert.ok(available(shell), `required shell ${shell} is missing; Windows coverage must not silently skip`)
    // The first Windows PowerShell startup on a fresh runner may JIT cold. This
    // allowance applies only to the version preflight, not execution deadlines.
    const probe = spawnSync(shell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()'], { encoding: 'utf8', timeout: 45000 })
    assert.equal(probe.status, 0, `${shell} did not execute: ${probe.error?.message || probe.stderr}`)
    assert.match(probe.stdout.trim(), expected, `${shell} must identify the required PowerShell edition`)
  }
})
function readRows(path, offset) {
  if (!existsSync(path)) return { rows: [], next: offset }
  const data = readFileSync(path), tail = data.subarray(offset), end = tail.lastIndexOf(10)
  if (end < 0) return { rows: [], next: offset }
  return { rows: tail.subarray(0, end).toString('utf8').split('\n').filter(Boolean).map(JSON.parse), next: offset + end + 1 }
}
async function until(predicate, timeout = 8000) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) { const value = predicate(); if (value) return value; await sleep(10) }
  throw new Error('terminal fixture timed out')
}
async function fixture(t, shell, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'p2p-terminal-owner-')), inbox = join(dir, 'inbox.jsonl')
  const controller = new AbortController(), sent = [], localOutput = []
  let connected = true, info, terminalError
  const session = { dir, id: ownerGeneration,
    requireLive: () => ({ id: ownerGeneration, connected, peerKey: allowed, self: 'OWNER_KEY' }),
    readRows, appendOutbox: row => { sent.push(decodeTermRow(row)); options.onOutbox?.(row) } }
  const runner = serveTerminal({ session, allowKey: allowed, shell, cwd: dir, env: { ...process.env, ...options.env },
    signal: controller.signal, io: { stdout: { write: text => localOutput.push(text) } }, onReady: value => { info = value } })
  runner.catch(error => { terminalError = error })
  t.after(async () => { controller.abort(); await runner.catch(() => {}); rmSync(dir, { recursive: true, force: true }) })
  // Initialization has its own bounded budget, independently of the 5-second
  // command deadline asserted below. Cold PowerShell may exceed eight seconds
  // when this fixture shares a runner with the full repository suite.
  await until(() => { if (terminalError) throw terminalError; return info }, 50000)
  const f = { dir, inbox, info, sent, runner, controller, localOutput,
    send: (payload, from = allowed, channel = 'term') => appendFileSync(inbox, JSON.stringify({ ...makeTermRow(payload, from), channel }) + '\n'),
    request: (command, extra = {}) => ({ v: 1, type: 'exec', requestId: termId(), grantId: info.grantId, generation: ownerGeneration,
      command, timeoutMs: 5000, maxOutputBytes: 1048576, expiresAt: Date.now() + 5000, ...extra }),
    response: request => until(() => sent.find(event => event.requestId === request.requestId && ['exit', 'refused'].includes(event.type))),
    output: request => sent.filter(event => event.requestId === request.requestId && event.type === 'data').map(event => Buffer.from(event.data, 'base64').toString('utf8')).join(''),
    disconnect: () => { connected = false },
    audit: () => readFileSync(join(dir, 'term-owner-audit.jsonl'), 'utf8'),
  }
  return f
}

for (const shell of shells) {
  test(`terminal ${shell}: real client and owner service agree across separate tunnel generations`, { skip: !available(shell), timeout: 60000 }, async t => {
    let clientInbox
    const f = await fixture(t, shell, { onOutbox: row => appendFileSync(clientInbox, JSON.stringify(row) + '\n') })
    const clientDirectory = join(f.dir, 'client state'); mkdirSync(clientDirectory)
    clientInbox = join(clientDirectory, 'inbox.jsonl')
    const printed = []
    const code = await terminalClient({ verb: 'exec', pos: [program(shell, "console.log('actual-client-server-proof');process.exit(9)")], flags: { timeout: 5 },
      session: { dir: clientDirectory, id: 'c'.repeat(32), self: allowed, peerKey: 'OWNER_KEY',
        requireLive: () => ({ id: 'c'.repeat(32), peerKey: 'OWNER_KEY', connected: true }),
        appendOutbox: row => appendFileSync(f.inbox, JSON.stringify(row) + '\n') },
      io: { stdout: { write: text => printed.push(text) }, stderr: { write() {} } } })
    assert.equal(code, 9)
    const events = printed.join('').trim().split('\n').map(JSON.parse)
    assert.ok(events.filter(event => event.type === 'data').map(event => event.text).join('').includes('actual-client-server-proof'))
    assert.equal(events.at(-1).code, 9)
    assert.ok(f.audit().includes(events.at(-1).requestId))
    assert.ok(readFileSync(join(clientDirectory, 'term-client-audit.jsonl'), 'utf8').includes(events.at(-1).requestId))
  })

  test(`terminal owner ${shell}: persistent cwd/env, actual nonzero exit, and chat isolation`, { skip: !available(shell), timeout: 60000 }, async t => {
    const f = await fixture(t, shell), subdirectory = join(f.dir, 'directory with spaces')
    mkdirSync(subdirectory)
    const change = powerShell(shell)
      ? `Set-Location -LiteralPath ${quote(subdirectory, shell)}; $env:P2P_TERMINAL_FIXTURE_STATE='persisted-value'; $p2pTerminalFixture='persistent-global'`
      : `cd ${quote(subdirectory, shell)}; export P2P_TERMINAL_FIXTURE_STATE='persisted-value'; p2pTerminalFixture='persistent-global'`
    const first = f.request(change); f.send(first)
    assert.equal((await f.response(first)).code, 0)
    const showVariable = powerShell(shell) ? 'Write-Output $p2pTerminalFixture; ' : 'printf "%s\\n" "$p2pTerminalFixture"; '
    const second = f.request(showVariable + program(shell, "require('node:fs').writeFileSync('cwd-proof.txt','relative-write-proof');console.log(process.cwd());console.log(process.env.P2P_TERMINAL_FIXTURE_STATE);process.exit(7)"))
    f.send(second)
    assert.equal((await f.response(second)).code, 7)
    const cwdProof = join(subdirectory, 'cwd-proof.txt')
    assert.ok(existsSync(cwdProof), `native process must write in the persisted directory; observed output: ${f.output(second)}`)
    assert.equal(readFileSync(cwdProof, 'utf8'), 'relative-write-proof', 'physical cwd proof tolerates Windows long/8.3 path spellings')
    assert.ok(f.output(second).includes('persisted-value'))
    assert.ok(f.output(second).includes('persistent-global'), 'ordinary shell variables persist between separate exec requests')
    const chat = f.request(program(shell, "require('node:fs').writeFileSync('chat-must-not-run','bad')"))
    f.send(chat, allowed, 'chat')
    await sleep(100)
    assert.equal(existsSync(join(subdirectory, 'chat-must-not-run')), false)
    assert.equal(f.sent.some(event => event.requestId === chat.requestId), false)
    assert.ok(f.audit().includes(first.requestId) && f.audit().includes(second.requestId))
  })

  test(`terminal owner ${shell}: shell and native process output preserve Hebrew and emoji`, { skip: !available(shell), timeout: 60000 }, async t => {
    const f = await fixture(t, shell), text = 'שלום🐙'
    const native = program(shell, `process.stdout.write(${JSON.stringify(text)})`)
    const command = powerShell(shell) ? `Write-Output ${quote(text, shell)}; ${native}` : `printf '%s\\n' ${quote(text, shell)}; ${native}`
    const request = f.request(command); f.send(request)
    assert.equal((await f.response(request)).code, 0)
    assert.equal(f.output(request).split(text).length - 1, 2, 'shell built-in and native program both retain exact Unicode')
  })

  test(`terminal owner ${shell}: wrong peer, stale grant, expired commands, remote grant, and replay cannot execute`, { skip: !available(shell), timeout: 60000 }, async t => {
    const f = await fixture(t, shell), sentinel = join(f.dir, 'execution-count')
    const command = program(shell, `require('node:fs').appendFileSync(${JSON.stringify(sentinel)},'x')`)
    const wrongPeer = f.request(command); f.send(wrongPeer, 'WRONG_PEER')
    f.send({ ...wrongPeer, requestId: termId(), type: 'grant' })
    const stale = f.request(command, { grantId: 'f'.repeat(32) }); f.send(stale)
    assert.equal((await f.response(stale)).type, 'refused')
    const expired = f.request(command, { expiresAt: Date.now() - 1 }); f.send(expired)
    assert.equal((await f.response(expired)).type, 'refused')
    assert.equal(existsSync(sentinel), false)
    assert.equal(f.sent.some(event => event.requestId === wrongPeer.requestId), false)
    const accepted = f.request(command); f.send(accepted)
    assert.equal((await f.response(accepted)).code, 0)
    f.send(accepted)
    await until(() => f.sent.some(event => event.requestId === accepted.requestId && event.type === 'refused'))
    assert.equal(readFileSync(sentinel, 'utf8'), 'x', 'replayed request must not run twice')
  })

  test(`terminal owner ${shell}: timeout kills the owned shell and revokes further execution`, { skip: !available(shell), timeout: 60000 }, async t => {
    const f = await fixture(t, shell)
    const pidFile = join(f.dir, 'owned-descendants.json')
    let descendants = null
    const script = `const child=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});require('node:fs').writeFileSync(${JSON.stringify(pidFile)},JSON.stringify({child:process.pid,grandchild:child.pid}));setInterval(()=>{},1000)`
    t.after(() => {
      for (const pid of Object.values(descendants || {})) {
        if (Number.isInteger(pid) && pid > 0) { try { process.kill(pid, 'SIGKILL') } catch {} }
      }
    })
    const request = f.request(program(shell, script), { timeoutMs: 3000, expiresAt: Date.now() + 5000 })
    f.send(request)
    await until(() => existsSync(pidFile), 4000)
    descendants = JSON.parse(readFileSync(pidFile, 'utf8'))
    assert.ok(Number.isInteger(descendants.child) && Number.isInteger(descendants.grandchild), 'real child and grandchild started before timeout')
    const result = await f.response(request)
    assert.equal(result.type, 'exit')
    assert.equal(result.timedOut, true)
    await f.runner
    const state = JSON.parse(readFileSync(join(f.dir, 'term-owner.json'), 'utf8'))
    assert.equal(state.active, false)
    assert.equal(existsSync(join(f.dir, 'term-owner.lock')), false)
    const after = f.request(program(shell, "require('node:fs').writeFileSync('after-revocation','bad')")); f.send(after)
    await sleep(100)
    assert.equal(existsSync(join(f.dir, 'after-revocation')), false)
    assert.throws(() => process.kill(f.info.shellPid, 0), 'owned shell process is gone after timeout')
    for (const [relationship, pid] of Object.entries(descendants)) {
      await until(() => { try { process.kill(pid, 0); return false } catch (error) { return error.code === 'ESRCH' } }, 3000)
      assert.throws(() => process.kill(pid, 0), `owned ${relationship} is gone after timeout`)
    }
  })

  test(`terminal owner ${shell}: output cap is enforced and secrets split across writes are redacted`, { skip: !available(shell), timeout: 60000 }, async t => {
    const secret = 'fixture-secret-value-927301'
    const f = await fixture(t, shell, { env: { P2P_TERMINAL_FIXTURE_SECRET: secret } })
    const script = "const s=process.env.P2P_TERMINAL_FIXTURE_SECRET;process.stdout.write(s.slice(0,9));setTimeout(()=>process.stdout.write(s.slice(9)),30)"
    const redacted = f.request(program(shell, script)); f.send(redacted)
    assert.equal((await f.response(redacted)).code, 0)
    assert.ok(f.output(redacted).includes('[REDACTED]'))
    assert.ok(!f.output(redacted).includes(secret) && !f.audit().includes(secret) && !f.localOutput.join('').includes(secret))
    const limited = f.request(program(shell, "process.stdout.write('z'.repeat(200000))"), { maxOutputBytes: 4096 })
    f.send(limited)
    const result = await f.response(limited)
    assert.equal(result.truncated, true)
    const emittedBytes = f.sent.filter(event => event.requestId === limited.requestId && event.type === 'data')
      .reduce((sum, event) => sum + Buffer.from(event.data, 'base64').length, 0)
    assert.ok(emittedBytes <= 4096)
    await f.runner
  })
}

test('terminal owner: disconnected or nonmatching authenticated peer cannot enable service', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'p2p-terminal-no-consent-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  for (const state of [{ connected: false, peerKey: allowed }, { connected: true, peerKey: 'WRONG_PEER' }]) {
    await assert.rejects(serveTerminal({ session: { dir, id: ownerGeneration, requireLive: () => state }, allowKey: allowed }), /currently authenticated connected peer/)
    assert.equal(existsSync(join(dir, 'term-owner.lock')), false)
  }
})

test('terminal owner: local stop or grant-bound cancellation revokes an active process while wrong cancel is ignored', { skip: !available(shells[0]), timeout: 60000 }, async t => {
  const shell = shells[0], f = await fixture(t, shell)
  const request = f.request(program(shell, 'setInterval(()=>{},1000)'))
  f.send(request)
  await until(() => f.audit().includes(request.requestId))
  f.send({ v: 1, type: 'cancel', requestId: request.requestId, grantId: 'f'.repeat(32), generation: ownerGeneration })
  await sleep(100)
  assert.equal(JSON.parse(readFileSync(join(f.dir, 'term-owner.json'), 'utf8')).active, true)
  f.send({ v: 1, type: 'cancel', requestId: request.requestId, grantId: f.info.grantId, generation: ownerGeneration })
  await f.runner
  assert.equal(JSON.parse(readFileSync(join(f.dir, 'term-owner.json'), 'utf8')).active, false)
  assert.equal(f.sent.find(event => event.requestId === request.requestId && event.type === 'exit').cancelled, true)
  const g = await fixture(t, shell)
  writeFileSync(join(g.dir, 'term-stop.json'), JSON.stringify({ grantId: g.info.grantId, generation: ownerGeneration }))
  await g.runner
  assert.equal(JSON.parse(readFileSync(join(g.dir, 'term-owner.json'), 'utf8')).active, false)
})
