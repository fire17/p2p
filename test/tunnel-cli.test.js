import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const bin = fileURLToPath(new URL('../bin/p2p.js', import.meta.url))
const run = (home, args, timeout = 12000, extraEnv = {}) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [bin, 'tunnel', ...args], { env: { ...process.env, P2P_HOME: home, P2P_RENDEZVOUS_DIR: '', ...extraEnv }, stdio: ['ignore', 'pipe', 'pipe'] })
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
    const messagePath = join(dir, 'multiline message.txt')
    const fileText = 'RESULT: first line\r\nשלום 🌻 "quoted" %PATH% & | $()\n'.repeat(1500)
    writeFileSync(messagePath, fileText, 'utf8')
    const fileSent = await run(b, ['send', '--file', messagePath, '--wait', '5'])
    assert.equal(fileSent.code, 0, fileSent.err)
    assert.equal(rows(fileSent.out).at(-1).delivered, true)
    const fileReceived = await run(a, ['recv', '--wait', '3'])
    assert.equal(fileReceived.code, 0, fileReceived.err)
    assert.equal(rows(fileReceived.out)[0].text, fileText, 'file exceeds Windows argv limit and preserves exact multiline content')
    assert.equal(rows(fileReceived.out)[0].from, state(b).self)
    const beforeRejected = readFileSync(join(state(b).dir, 'outbox.jsonl'), 'utf8')
    assert.equal((await run(b, ['send', 'ambiguous', '--file', messagePath])).code, 2)
    assert.equal((await run(b, ['send', '--file', join(dir, 'missing.txt')])).code, 2)
    writeFileSync(messagePath, Buffer.from([0xff, 0xfe, 0, 0]))
    assert.equal((await run(b, ['send', '--file', messagePath])).code, 2, 'invalid UTF-8 is refused, never silently replaced')
    writeFileSync(messagePath, Buffer.alloc(1024 * 1024 + 1, 65))
    assert.equal((await run(b, ['send', '--file', messagePath])).code, 2, 'oversized file is refused')
    assert.equal(readFileSync(join(state(b).dir, 'outbox.jsonl'), 'utf8'), beforeRejected, 'rejected inputs never enter the outbox')
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

// ── --relay-only / P2P_TRANSPORT ────────────────────────────────────────────────────────────────
//
// The knob the 2026-09-13 VPS joins needed and did not have: dial over the public relay ALONE, so
// "is it the UDP leg?" becomes a question you can answer instead of a guess. These legs stay OFFLINE
// (--rendezvous-dir, a loopback board) — the relay-only DIAL itself is proven in
// test/transport-node-relay-only.test.js against the mock broker.

const session = (home, name = 'default') => {
  const root = join(home, 'tunnel', name), { id } = JSON.parse(readFileSync(join(root, 'current.json')))
  return JSON.parse(readFileSync(join(root, id, 'session.json'), 'utf8'))
}

test('tunnel: --relay-only persists transport before the dial, and a bad value writes nothing at all', { timeout: 30000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'p2p-tunnel-relayonly-'))
  const home = join(dir, 'home'), bogusHome = join(dir, 'bogus'), inviteHome = join(dir, 'invite')
  const board = join(dir, 'board')
  try {
    const { generateIdentity } = await import('../src/key.js')
    const { mintInvite } = await import('../bin/lib.js')
    const absent = generateIdentity().S                       // a well-formed contact key nobody answers

    // The session config is written by reserve() BEFORE the daemon launches, so the choice survives
    // even a dial that never connects. Offline here (--rendezvous-dir disables the relay leg), so the
    // daemon rejects LOUDLY instead of silently dialing UDP — which is the whole point of the knob.
    const relayOnly = await run(home, ['join', absent, '--relay-only', '--rendezvous-dir', board, '--connect-timeout', '2'], 20000)
    assert.equal(session(home).transport, 'relay', 'the dialer recorded relay-only in session.json')
    assert.notEqual(relayOnly.code, 0, relayOnly.out + relayOnly.err)
    assert.match(relayOnly.err + relayOnly.out, /relay-only needs the WSS relay/,
      'relay-only without a relay leg fails loud — it never quietly falls back to the UDP dial')

    // A bad value is refused BEFORE reserve(): no home, no session dir, no owner lock.
    const bogus = await run(bogusHome, ['join', absent], 12000, { P2P_TRANSPORT: 'bogus' })
    assert.equal(bogus.code, 2, bogus.out + bogus.err)
    assert.match(bogus.err, /P2P_TRANSPORT must be relay or auto \(got "bogus"\)/)
    assert.equal(existsSync(bogusHome), false, 'a rejected transport value leaves no session dir behind')

    // A private invite has no relay topic by design — relay-only there is refused on both verbs.
    const share = mintInvite(generateIdentity()).share
    const privateJoin = await run(inviteHome, ['join', share, '--relay-only'], 12000)
    assert.equal(privateJoin.code, 2, privateJoin.out + privateJoin.err)
    assert.match(privateJoin.err, /relay-only is not available for private invites/)
    assert.equal(existsSync(inviteHome), false)
    const privateInvite = await run(inviteHome, ['invite', '--relay-only', '--ephemeral'], 12000)
    assert.equal(privateInvite.code, 2, privateInvite.out + privateInvite.err)
    assert.match(privateInvite.err, /relay-only is not available for private invites/)
    assert.equal(existsSync(inviteHome), false)

    // Clean case: no flag, no env => transport 'auto', the path every existing test exercises.
    const plain = await run(home, ['join', absent, '--name', 'plain', '--rendezvous-dir', board, '--connect-timeout', '2'], 20000)
    assert.equal(session(home, 'plain').transport, 'auto')
    assert.notEqual(plain.code, 0, 'an absent peer still times out — unchanged')
    assert.doesNotMatch(plain.err + plain.out, /relay-only/, 'the default path never mentions the knob')

    assert.match((await run(home, ['--help'])).out, /--relay-only/, 'the flag is documented in help')
  } finally {
    await Promise.all([run(home, ['stop']), run(home, ['stop', '--name', 'plain'])])
    rmSync(dir, { recursive: true, force: true })
  }
})
