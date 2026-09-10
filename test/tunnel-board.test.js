// test/tunnel-board.test.js — the AGENT TUNNEL's offline acceptance carrier (src/tunnel-board.js).
//
// WHAT IS REAL HERE: real key.js identities, real invite.js (K_inv -> rid_inv / k_ip / psk), real
// noise.js IKpsk2, real wire.js, real rendezvous/race.js, real transport-node UDP sockets on
// 127.0.0.1. The ONLY substitution is the rendezvous CARRIER: a directory instead of a public
// tracker/DHT/mDNS. So these tests assert the invite property chain itself — LOCATE (rid_inv),
// OPEN (k_ip) and HANDSHAKE (psk) — while touching no network beyond loopback.
//
// P2P_LIVE is not read by anything in this file, and the spawned peers are given an env with it
// stripped: nothing here is live-gated and nothing here reaches the internet.
//
// The three assertions that make the seal path non-vacuous (drop `invite:` from createRace in
// src/tunnel-board.js and each one goes RED): the record IS at rid_inv, the record is NOT at
// deriveRid(S), and a second secret's rid finds nothing.

import test from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import { mkdtempSync, rmSync, readdirSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { listen } from '../src/node.js'
import { generateIdentity, encodeKey, deriveRid } from '../src/key.js'
import { createInvite, generateInviteSecret, formatShare, INVITE_FLAG, SEALED_LEN, openBlob } from '../src/invite.js'
import { fileRendezvousDeps, fileChannel, recordPath } from '../src/tunnel-board.js'

// Frozen rendezvous clock: midday UTC is >1h from rollover, so announceEpochs() yields exactly ONE
// epoch and the board holds exactly one record per publisher — a countable denominator.
const NOW_MS = Date.UTC(2026, 6, 12, 12, 0, 0)
const EPOCH = '2026-07-12'
const NOW = () => NOW_MS
const FIXTURE = fileURLToPath(new URL('./fixtures/tunnel-board-peer.mjs', import.meta.url))

const board = () => mkdtempSync(join(os.tmpdir(), 'p2p-tunnel-board-'))
const records = (dir) => readdirSync(dir).filter((f) => f.endsWith('.json')).sort()
const nextTick = () => new Promise((r) => setImmediate(r))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** Resolve to {ok,v}/{ok:false,e} or {timedOut:true} — a hang must FAIL, never wedge the suite. */
function settlesWithin(p, ms) {
  let t
  const timeout = new Promise((r) => { t = setTimeout(() => r({ timedOut: true }), ms) })
  return Promise.race([p.then((v) => ({ ok: true, v }), (e) => ({ ok: false, e })), timeout])
    .finally(() => clearTimeout(t))
}

/** One host identity + its one-time invite share string. */
function mintHost() {
  const id = generateIdentity()
  const secret = generateInviteSecret()
  const inv = createInvite(secret)
  const share = formatShare(encodeKey(id.edPub, id.xPub, INVITE_FLAG), secret)
  return { id, secret, inv, share, rid: inv.rid('tracker', EPOCH, 20) }
}

const hostDeps = (dir, over = {}) => fileRendezvousDeps(dir, { loopback: true, now: NOW, lookupTimeoutMs: 600, pollMs: 20, ...over })
const joinDeps = (dir, over = {}) => fileRendezvousDeps(dir, { loopback: true, now: NOW, announce: false, lookupTimeoutMs: 600, pollMs: 20, ...over })

// ── 1. the happy path: two REAL nodes meet over a directory ──────────────────────────────────────
test('file board: two real nodes meet over a directory — sealed at rid_inv, IKpsk2, both directions', async () => {
  const dir = board()
  const host = mintHost()
  const joiner = generateIdentity()
  const hd = hostDeps(dir, { invite: host.inv }), jd = joinDeps(dir)
  let A = null, B = null
  try {
    A = await listen(host.id, { invite: host.secret, wss: false, deps: hd, tickMs: 25 })
    // ZERO real channels: resolve+publishAll were injected, so mdns/dht/tracker were never built.
    assert.equal(A._channels.length, 0, 'listen constructed no real rendezvous channel')
    await nextTick()

    // WHERE: exactly one record, named by the K_inv rid — nothing at the reusable-S rid.
    const ridHex = host.rid.toString('hex')
    assert.deepEqual(records(dir), [ridHex + '.json'], 'exactly one record, at rid_inv = HKDF(K_inv,…)')
    assert.equal(records(dir).includes(deriveRid(host.id.S, 'tracker', EPOCH, 20).toString('hex') + '.json'), false,
      'nothing published at the S-derived rid')

    // WHAT: fixed-length ciphertext, no plaintext address anywhere in it.
    const body = JSON.parse(readFileSync(recordPath(dir, host.rid), 'utf8'))
    const sealed = Buffer.from(body.sealed, 'base64')
    assert.equal(sealed.length, SEALED_LEN, 'sealed blob is fixed-length (' + SEALED_LEN + ' B)')
    assert.equal(sealed.includes(Buffer.from('127.0.0.1')), false, 'no plaintext IP on the board')
    assert.equal(sealed.includes(Buffer.from('candidates')), false, 'no plaintext JSON on the board')
    // and it really does carry the loopback candidate for the endpoint's own udp4 port
    const opened = host.inv.codec.open(sealed, host.rid)
    assert.equal(opened.candidates.length, 1, 'one loopback candidate announced')
    assert.equal(opened.candidates[0].ip, '127.0.0.1')
    assert.equal(opened.candidates[0].port, A._ep ? A._ep.port4 || A._ep.port : opened.candidates[0].port)

    // WHO: the share-string holder locates it, opens it, punches loopback UDP, completes IKpsk2.
    B = await listen(joiner, { wss: false, deps: jd, tickMs: 25 })
    assert.equal(B._channels.length, 0, 'the joiner constructed no real rendezvous channel either')
    const gotHost = [], gotJoiner = []
    A.on('message', (p, d) => { gotHost.push(d.toString()); Promise.resolve(p.send('pong:' + d.toString())).catch(() => {}) })
    B.on('message', (_p, d) => gotJoiner.push(d.toString()))

    const t0 = Date.now()
    const r = await settlesWithin(B.connect(host.share), 3000)
    const ms = Date.now() - t0
    assert.equal(r.timedOut, undefined, 'connect settled')
    assert.equal(r.ok, true, 'connect resolved: ' + (r.e && r.e.message))
    assert.ok(ms < 3000, 'in-process connect took ' + ms + 'ms (< 3000)')
    assert.equal(r.v.connected, true)
    assert.equal(r.v.key, host.id.S, 'peer.key is the host BARE S — the invite is one-time')

    await r.v.send('ping from joiner')
    for (let i = 0; i < 100 && !gotJoiner.length; i++) await sleep(20)
    assert.deepEqual(gotHost, ['ping from joiner'], 'joiner -> host')
    assert.deepEqual(gotJoiner, ['pong:ping from joiner'], 'host -> joiner')
  } finally {
    if (A) A.close(); if (B) B.close(); hd.close(); jd.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

// ── 2. the negative the seal path rests on ───────────────────────────────────────────────────────
test('file board: a second secret computes a different rid, finds nothing, and cannot open the record', async () => {
  const dir = board()
  const host = mintHost()
  const hd = hostDeps(dir, { invite: host.inv })
  let A = null
  try {
    A = await listen(host.id, { invite: host.secret, wss: false, deps: hd, tickMs: 25 })
    await nextTick()
    assert.equal(records(dir).length, 1, 'the record is on the board')

    const wrong = createInvite(generateInviteSecret())
    const wrongRid = wrong.rid('tracker', EPOCH, 20)
    assert.notEqual(wrongRid.toString('hex'), host.rid.toString('hex'), 'a different K_inv = a different rid')

    // (a) cannot even LOCATE: the wrong rid names a file that does not exist.
    const seek = fileChannel(dir, wrong, { now: NOW, lookupTimeoutMs: 200, pollMs: 20 })
    const hits = []
    for await (const rec of seek.lookup(wrongRid)) hits.push(rec)
    assert.deepEqual(hits, [], 'lookup at the wrong rid yields nothing')

    // (b) even handed the right rid, the wrong k_ip cannot OPEN it.
    const sealed = Buffer.from(JSON.parse(readFileSync(recordPath(dir, host.rid), 'utf8')).sealed, 'base64')
    assert.equal(openBlob(wrong.kIp, sealed, host.rid), null, 'the wrong k_ip opens nothing')
    assert.equal(wrong.codec.open(sealed, host.rid), null, 'and neither does its codec')
    const viaChannel = []
    for await (const rec of seek.lookup(host.rid)) viaChannel.push(rec)
    assert.deepEqual(viaChannel, [], 'a channel holding the wrong invite ignores the record entirely')
    assert.notEqual(host.inv.codec.open(sealed, host.rid), null, 'control: the RIGHT key does open it')
  } finally {
    if (A) A.close(); hd.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

// ── 3. cross-process: two node PROCESSES sharing only a directory ────────────────────────────────
test('file board: two separate PROCESSES discover each other through the directory', async (t) => {
  const dir = board()
  const secret = generateInviteSecret()
  const env = { ...process.env }
  delete env.P2P_LIVE                                       // nothing here is live-gated
  const kids = []
  const spawnPeer = (args) => {
    const p = spawn(process.execPath, [FIXTURE, ...args], { env, stdio: ['ignore', 'pipe', 'pipe'] })
    kids.push(p)
    const events = []
    let buf = '', stderr = ''
    p.stdout.on('data', (d) => {
      buf += d.toString()
      const lines = buf.split(/\r?\n/); buf = lines.pop()
      for (const l of lines) { if (l.trim()) { try { events.push(JSON.parse(l)) } catch { events.push({ ev: 'unparsed', l }) } } }
    })
    p.stderr.on('data', (d) => { stderr += d.toString() })
    return { p, events, err: () => stderr }
  }
  /** wait for an event, or fail loudly with everything the child said. */
  const waitFor = async (peer, ev, ms) => {
    const deadline = Date.now() + ms
    while (Date.now() < deadline) {
      const hit = peer.events.find((e) => e.ev === ev)
      if (hit) return hit
      const bad = peer.events.find((e) => e.ev === 'error' || e.ev === 'timeout')
      if (bad) assert.fail('peer failed before ' + ev + ': ' + JSON.stringify(bad) + ' stderr=' + peer.err())
      await sleep(25)
    }
    assert.fail('timed out waiting for "' + ev + '"; events=' + JSON.stringify(peer.events) + ' stderr=' + peer.err())
  }

  try {
    const t0 = Date.now()
    const host = spawnPeer(['host', dir, secret.toString('hex'), String(NOW_MS)])
    const ready = await waitFor(host, 'ready', 8000)
    assert.equal(ready.realChannels, 0, 'the host process built no real rendezvous channel')
    assert.equal(records(dir).length, 1, 'one sealed record on the shared board')

    const join = spawnPeer(['join', dir, ready.share, String(NOW_MS)])
    const conn = await waitFor(join, 'connected', 8000)
    const ms = Date.now() - t0
    assert.ok(ms < 8000, 'two-process connect took ' + ms + 'ms (< 8000)')
    assert.equal(conn.realChannels, undefined)               // reported on 'ready', not here
    assert.equal((await waitFor(join, 'recv', 5000)).text, 'pong:ping from joiner', 'host -> joiner')
    assert.equal((await waitFor(host, 'recv', 5000)).text, 'ping from joiner', 'joiner -> host')
    t.diagnostic('cross-process connect ' + conn.ms + 'ms, total ' + ms + 'ms')
  } finally {
    for (const k of kids) { try { k.kill('SIGKILL') } catch { /* */ } }
    rmSync(dir, { recursive: true, force: true })
  }
})

// ── 4. sabotage, as permanent tests: every failure mode must be LOUD and BOUNDED ─────────────────
// A dial that hangs here would hang the tunnel daemon later, so each of these asserts BOTH that it
// failed and that it failed fast.

test('file board: the record deleted between announce and lookup — the dial fails fast, never hangs', async () => {
  const dir = board()
  const host = mintHost()
  const joiner = generateIdentity()
  const hd = hostDeps(dir, { invite: host.inv }), jd = joinDeps(dir)
  let A = null, B = null
  try {
    A = await listen(host.id, { invite: host.secret, wss: false, deps: hd, tickMs: 25 })
    await nextTick()
    assert.equal(records(dir).length, 1)
    unlinkSync(recordPath(dir, host.rid))                    // the board loses the record
    assert.deepEqual(records(dir), [])

    B = await listen(joiner, { wss: false, deps: jd, tickMs: 25 })
    const t0 = Date.now()
    const r = await settlesWithin(B.connect(host.share), 5000)
    assert.equal(r.timedOut, undefined, 'the dial SETTLED within 5s (a hang here would hang the daemon)')
    assert.equal(r.ok, false, 'and it failed — there was nothing to punch')
    assert.match(String(r.e.message), /no candidates/, 'failure class: ' + r.e.message)
    assert.ok(Date.now() - t0 < 5000, 'failed in ' + (Date.now() - t0) + 'ms')
  } finally {
    if (A) A.close(); if (B) B.close(); hd.close(); jd.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

test('file board: one tampered byte — codec.open returns null and the dial fails the same way', async () => {
  const dir = board()
  const host = mintHost()
  const joiner = generateIdentity()
  const hd = hostDeps(dir, { invite: host.inv }), jd = joinDeps(dir)
  let A = null, B = null
  try {
    A = await listen(host.id, { invite: host.secret, wss: false, deps: hd, tickMs: 25 })
    await nextTick()
    const path = recordPath(dir, host.rid)
    const sealed = Buffer.from(JSON.parse(readFileSync(path, 'utf8')).sealed, 'base64')
    sealed[40] ^= 0x01                                       // flip ONE bit inside the ciphertext
    writeFileSync(path, JSON.stringify({ v: 1, sealed: sealed.toString('base64') }))
    assert.equal(host.inv.codec.open(sealed, host.rid), null, 'the AEAD tag rejects the tampered record')

    B = await listen(joiner, { wss: false, deps: jd, tickMs: 25 })
    const r = await settlesWithin(B.connect(host.share), 5000)
    assert.equal(r.timedOut, undefined, 'the dial SETTLED')
    assert.equal(r.ok, false, 'a tampered record is ignored, so no candidate is found')
    assert.match(String(r.e.message), /no candidates/, 'failure class: ' + r.e.message)
  } finally {
    if (A) A.close(); if (B) B.close(); hd.close(); jd.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

test('file board: loopback OFF on a box with only internal interfaces — announces nothing, fails LOUDLY', async () => {
  // src/transport.js:339 candidates() skips `internal` interfaces. Stub the interface list down to
  // loopback-only (exactly what os.networkInterfaces() returns on an offline sandbox) and the
  // endpoint has NOTHING to advertise. This test exists so that case can never pass VACUOUSLY:
  // the record is still published, it is simply empty, and the dial says 'no candidates' out loud.
  const dir = board()
  const host = mintHost()
  const joiner = generateIdentity()
  const realNI = os.networkInterfaces
  os.networkInterfaces = () => ({ lo0: [{ address: '127.0.0.1', family: 'IPv4', internal: true }] })
  const hd = hostDeps(dir, { loopback: false, invite: host.inv })
  const jd = joinDeps(dir)
  let A = null, B = null
  try {
    A = await listen(host.id, { invite: host.secret, wss: false, deps: hd, tickMs: 25 })
    await nextTick()
    assert.equal(records(dir).length, 1, 'the record IS published…')
    const sealed = Buffer.from(JSON.parse(readFileSync(recordPath(dir, host.rid), 'utf8')).sealed, 'base64')
    assert.deepEqual(host.inv.codec.open(sealed, host.rid).candidates, [], '…and it carries ZERO candidates')

    B = await listen(joiner, { wss: false, deps: jd, tickMs: 25 })
    const r = await settlesWithin(B.connect(host.share), 5000)
    assert.equal(r.timedOut, undefined, 'the dial SETTLED')
    assert.equal(r.ok, false, 'an empty candidate set can never connect')
    assert.match(String(r.e.message), /no candidates/, 'and it says so: ' + r.e.message)
  } finally {
    os.networkInterfaces = realNI
    if (A) A.close(); if (B) B.close(); hd.close(); jd.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

// ── 5. carrier hygiene ───────────────────────────────────────────────────────────────────────────
test('file board: writes are atomic (no partial file is ever visible) and close() withdraws our records', async () => {
  const dir = board()
  const host = mintHost()
  const ch = fileChannel(dir, host.inv, { now: NOW })
  try {
    ch.announce(host.rid, { candidates: [{ proto: 'udp4', ip: '127.0.0.1', port: 41000, kind: 'host' }] })
    assert.deepEqual(records(dir), [host.rid.toString('hex') + '.json'])
    assert.deepEqual(readdirSync(dir).filter((f) => f.endsWith('.tmp')), [], 'no temp file left behind')
    ch.announce(host.rid, { candidates: [{ proto: 'udp4', ip: '127.0.0.1', port: 41001, kind: 'host' }] })
    assert.equal(records(dir).length, 1, 're-announce replaces in place')
    const got = []
    for await (const rec of ch.lookup(host.rid, { timeout: 200 })) got.push(rec)
    assert.equal(got[0].candidates[0].port, 41001, 'the reader sees the whole new record')
    ch.close()
    assert.deepEqual(records(dir), [], 'close() withdraws what this channel announced')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
