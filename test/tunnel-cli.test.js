import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, existsSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const bin = fileURLToPath(new URL('../bin/p2p.js', import.meta.url))
const run = (home, args, timeout = 12000) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [bin, 'tunnel', ...args], { env: { ...process.env, P2P_HOME: home, P2P_RENDEZVOUS_DIR: '' }, stdio: ['ignore', 'pipe', 'pipe'] })
  let out = '', err = ''
  child.stdout.on('data', data => { out += data }); child.stderr.on('data', data => { err += data })
  const timer = setTimeout(() => { child.kill(); reject(new Error('CLI timeout: ' + args.join(' ') + '\n' + out + err)) }, timeout)
  child.on('error', reject)
  child.on('exit', code => { clearTimeout(timer); resolve({ code, out, err }) })
})
const rows = out => out.trim().split('\n').filter(Boolean).map(s => JSON.parse(s))
const state = (home, name = 'default') => {
  const root = join(home, 'tunnel', name), { id } = JSON.parse(readFileSync(join(root, 'current.json')))
  const dir = join(root, id)
  return { dir, ...JSON.parse(readFileSync(join(dir, 'state.json'))) }
}

test('tunnel: detached CLI, real private handshake, exact long UTF-8, isolation, stop', { timeout: 30000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'p2p-tunnel-cli-')), a = join(dir, 'a'), b = join(dir, 'b'), board = join(dir, 'board')
  const started = Date.now()
  try {
    const invite = await run(a, ['invite', '--ephemeral', '--rendezvous-dir', board])
    assert.equal(invite.code, 0, invite.err)
    const share = invite.out.match(/tunnel join ([A-Z0-9]+-[A-Z0-9]+)/i)?.[1]
    assert.ok(share, invite.out)
    const host = state(a)
    assert.equal(host.alive, undefined)
    assert.equal((await run(a, ['status'])).code, 0, 'daemon survives exited launcher')
    const duplicate = await run(a, ['invite', '--rendezvous-dir', board])
    assert.equal(duplicate.code, 2, duplicate.out + duplicate.err)
    assert.equal(state(a).id, host.id, 'duplicate start leaves original generation intact')
    const hello = 'hello from the isolated second agent'
    const joined = await run(b, ['join', share, '--say', hello, '--rendezvous-dir', board, '--connect-timeout', '5'])
    assert.equal(joined.code, 0, joined.err)
    const first = await run(a, ['recv', '--wait', '3'])
    assert.equal(first.code, 0, first.err)
    assert.equal(rows(first.out)[0].text, hello)
    assert.equal(rows(first.out)[0].from, state(b).self, 'sender matches authenticated peer')
    const text = 'שלום 🌻 " \\ \n'.repeat(1000)
    const send = await run(a, ['send', text, '--wait', '5'])
    assert.equal(send.code, 0, send.err)
    assert.equal(rows(send.out).at(-1).delivered, true)
    const received = await run(b, ['recv', '--wait', '3'])
    assert.equal(received.code, 0, received.err)
    assert.equal(rows(received.out)[0].text, text)
    assert.equal(rows(received.out)[0].from, state(a).self)
    assert.equal((await run(b, ['recv'])).out, '', 'cursor consumes message once')
    assert.equal(rows((await run(b, ['recv', '--all'])).out).length, 1, 'history stays readable')
    assert.equal((await run(b, ['stop'])).code, 0)
    assert.equal((await run(b, ['status'])).code, 5)
    assert.equal((await run(b, ['send', 'must not queue'])).code, 5)
    assert.equal((await run(a, ['stop'])).code, 0)
    const again = await run(a, ['invite', '--ephemeral', '--rendezvous-dir', board])
    assert.equal(again.code, 0, again.err)
    assert.notEqual(state(a).id, host.id, 'new session uses a new generation')
    assert.equal(existsSync(join(state(a).dir, 'outbox.jsonl')), false, 'old text is not replayed to a new peer')
    assert.ok(existsSync(join(host.dir, 'inbox.jsonl')), 'old history is retained separately')
    assert.ok(Date.now() - started < 20000)
  } finally {
    await Promise.all([run(a, ['stop']), run(b, ['stop'])])
    rmSync(dir, { recursive: true, force: true })
  }
})

test('tunnel: invalid names/shares fail before session writes; absent host is bounded', { timeout: 15000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'p2p-tunnel-negative-')), home = join(dir, 'home'), board = join(dir, 'board')
  try {
    assert.equal((await run(home, ['invite', '--name', '../../escape'])).code, 2)
    assert.equal(existsSync(home), false)
    assert.equal((await run(home, ['join', 'broken'])).code, 2)
    assert.equal(existsSync(home), false)
    const { generateIdentity } = await import('../src/key.js')
    const { mintInvite } = await import('../bin/lib.js')
    const share = mintInvite(generateIdentity()).share
    const result = await run(home, ['join', share, '--rendezvous-dir', board, '--connect-timeout', '1'])
    assert.equal(result.code, 3, result.out + result.err)
    const st = state(home)
    assert.ok(st.stopped)
    assert.equal(existsSync(join(home, 'tunnel', 'default', 'owner.json')), false)
  } finally { await run(home, ['stop']); rmSync(dir, { recursive: true, force: true }) }
})
