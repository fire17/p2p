// test/dos-meta-harden.test.js — DOS-1 (accept-path exhaustion) + META-1 (cleartext HELLO leak).
//
// wargame-findings §2:
//   DOS-1 — any remote sender who reaches the UDP port streams forged 21-byte PROBEs (fresh token /
//     source port each) and, pre-fix, each one minted a socketLike into transport `_peers` AND
//     `_accepted` (neither evicted, no cap, no rate limit) and fired onConnection → a node peer
//     record BEFORE the handshake authenticated. Zero-cost, remotely triggerable, unbounded memory.
//   META-1 — a well-formed PROBE fired onConnection → node.js immediately answered with a CLEARTEXT
//     HELLO carrying edPub‖xPub. Any off-path party reaching the socket harvested the pubkeys →
//     computed S → bound IP:port ↔ identity, an oracle that undercuts invite-mode metadata privacy.
//
// These drive the REAL transport over loopback (raw dgram forging the punch wire) and the REAL node
// accept path (mocked crypto seams, real wire.js), so the guards are exercised end-to-end, not by
// inspection. RED/GREEN is demonstrated by contrasting a guardless-config endpoint (unbounded) with
// the shipped bounds (bounded) — the guards are load-bearing.
//
// Zero deps, node:test.

import test from 'node:test'
import assert from 'node:assert/strict'
import dgram from 'node:dgram'
import { randomBytes } from 'node:crypto'
import { createEndpoint } from '../src/transport.js'
import { listen } from '../src/node.js'
import { generateIdentity, decodeKey, verifyCommitment, encodeKey } from '../src/key.js'
import { initiator, responder } from '../src/noise.js'
import { createInvite, generateInviteSecret, formatShare, INVITE_FLAG } from '../src/invite.js'
import { decodeFrame, TYPE } from '../src/wire.js'

// ── the punch wire (mirror transport.js exactly) ──────────────────────────────────────────────
const PUNCH_MAGIC = 0x50327050
const PROBE = 0x01
function probePkt(type, tok8, nonce8) {
  const b = Buffer.alloc(21)
  b.writeUInt32BE(PUNCH_MAGIC, 0)
  b[4] = type
  Buffer.from(tok8).copy(b, 5)
  Buffer.from(nonce8).copy(b, 13)
  return b
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms))

/** Fire one forged PROBE from a FRESH source socket (⇒ fresh source port, as the attack does). */
function forgeProbe(port, tok, nonce) {
  const s = dgram.createSocket('udp4')
  return new Promise((res) => {
    s.bind(0, () => { s.send(probePkt(PROBE, tok, nonce), port, '127.0.0.1', () => res(s)) })
  })
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// DOS-1 — transport accept table stays BOUNDED under a fresh-token/fresh-source PROBE flood
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('DOS-1 (transport): pending cap bounds _accepted/_peers under a PROBE flood — GREEN vs unguarded RED', async () => {
  let clock = 1_000_000                                   // fixed clock ⇒ token buckets never refill: deterministic
  const now = () => clock

  // RED baseline — an endpoint whose guards are effectively disabled (huge caps/buckets) behaves like
  // the pre-fix code: every distinct-token/source PROBE mints an accept, unbounded.
  const red = await createEndpoint({
    now, maxPending: 1e9, maxAccepted: 1e9, acceptBurst: 1e9, probeBurst: 1e9, acceptRate: 0, probeRate: 0,
  })
  let redConns = 0; red.onConnection(() => { redConns++ })
  const N = 40
  const redSocks = []
  for (let i = 0; i < N; i++) redSocks.push(await forgeProbe(red.port4, randomBytes(8), randomBytes(8)))
  await delay(150)
  assert.equal(red._accepted.size, N, `RED: unguarded endpoint minted one accept per PROBE (${red._accepted.size})`)
  assert.equal(redConns, N, 'RED: onConnection fired once per forged PROBE (peer records pre-auth)')
  redSocks.forEach((s) => s.close()); red.close()

  // GREEN — shipped bounds. pending cap = 8: after 8 un-handshaked accepts, every further forged
  // PROBE is dropped, so a flood can never crowd out the slots reserved for real, handshaked peers.
  clock = 2_000_000
  const green = await createEndpoint({ now, maxPending: 8, maxAccepted: 8, acceptBurst: 1e9, probeBurst: 1e9 })
  let greenConns = 0; green.onConnection(() => { greenConns++ })
  const greenSocks = []
  for (let i = 0; i < N; i++) greenSocks.push(await forgeProbe(green.port4, randomBytes(8), randomBytes(8)))
  await delay(150)
  assert.ok(green._accepted.size <= 8, `GREEN: _accepted bounded by the pending cap (${green._accepted.size} <= 8)`)
  assert.ok(green._peers.size <= 8, `GREEN: _peers bounded too (${green._peers.size} <= 8)`)
  assert.ok(greenConns <= 8, `GREEN: onConnection fired at most cap times, not once per PROBE (${greenConns} <= 8)`)
  greenSocks.forEach((s) => s.close()); green.close()
})

test('DOS-1 (transport): accepted-but-no-HS1 probes are idle-evicted after the pending TTL', async () => {
  let clock = 5_000_000
  const ep = await createEndpoint({ now: () => clock, maxPending: 100, maxAccepted: 100, acceptBurst: 1e9, probeBurst: 1e9, pendingTtlMs: 20_000 })
  ep.onConnection(() => {})
  const socks = []
  for (let i = 0; i < 6; i++) socks.push(await forgeProbe(ep.port4, randomBytes(8), randomBytes(8)))
  await delay(120)
  assert.equal(ep._accepted.size, 6, 'six distinct-source PROBEs => six pending accepts')

  clock += 20_001                                         // step past the pending TTL
  ep._sweepAccepts()                                     // the sweep timer also fires this on its own cadence
  assert.equal(ep._accepted.size, 0, 'all un-handshaked accepts evicted after the TTL — no permanent growth')
  socks.forEach((s) => s.close()); ep.close()
})

test('DOS-1 (transport): per-source PROBE rate-limit drops a same-IP flood before it allocates', async () => {
  let clock = 9_000_000                                   // fixed ⇒ no refill; probeBurst is the hard ceiling
  const ep = await createEndpoint({ now: () => clock, maxPending: 1e9, maxAccepted: 1e9, acceptBurst: 1e9, probeBurst: 5, probeRate: 0 })
  let conns = 0; ep.onConnection(() => { conns++ })
  const socks = []
  for (let i = 0; i < 30; i++) socks.push(await forgeProbe(ep.port4, randomBytes(8), randomBytes(8)))  // all from 127.0.0.1
  await delay(150)
  assert.ok(ep._accepted.size <= 5, `per-source token bucket capped the flood (${ep._accepted.size} <= 5)`)
  assert.ok(conns <= 5, `onConnection fired at most the burst allotment (${conns} <= 5)`)
  socks.forEach((s) => s.close()); ep.close()
})

// ── DOS-1 at the NODE layer: no peer record before HS1 authenticates; inbound table bounded ─────

// Minimal mocked crypto seam (mirrors node.test.js) so we drive the REAL accept path + real wire.js.
class TypoError extends Error {}
function mkIdentity(S, tag) {
  return { S, edPub: Buffer.from(tag + '-ed'), edPriv: Buffer.from(tag + '-edk'), xPub: Buffer.from(tag + '-x'), xPriv: Buffer.from(tag + '-xk') }
}
function baseNoise() {
  const cipher = (tag) => ({
    encrypt: (pt) => Buffer.concat([Buffer.from([tag]), Buffer.from(pt)]),
    decrypt: (ct) => { if (ct[0] !== tag) throw new Error('decrypt: bad tag'); return Buffer.from(ct.subarray(1)) },
  })
  return {
    initiator: () => ({
      writeMessage: (p) => Buffer.concat([Buffer.from('I1'), Buffer.from(p)]),
      readMessage: (b) => { if (b.subarray(0, 2).toString() !== 'R2') throw new Error('HandshakeError'); return Buffer.from(b.subarray(2)) },
      split: () => ({ tx: cipher(0x61), rx: cipher(0x62), handshakeHash: Buffer.alloc(32) }),
    }),
    responder: () => ({
      readMessage: (b) => { if (b.subarray(0, 2).toString() !== 'I1') throw new Error('HandshakeError'); return Buffer.from(b.subarray(2)) },
      writeMessage: (p) => Buffer.concat([Buffer.from('R2'), Buffer.from(p)]),
      split: () => ({ tx: cipher(0x62), rx: cipher(0x61), handshakeHash: Buffer.alloc(32) }),
    }),
  }
}
function makeBoard() {
  const eps = new Map(), registry = new Map()
  function sock(getPeer) {
    let handler = null; const inbox = []
    const s = {
      closed: false, rinfo: { address: 'mock', port: 0 },
      get onMessage() { return handler },
      set onMessage(fn) { handler = fn; if (fn) while (inbox.length) fn(inbox.shift()) },
      _recv(buf) { if (handler) handler(buf); else inbox.push(buf) },
      send(buf) { if (s.closed) return; const p = getPeer(); if (p && !p.closed) p._recv(Buffer.from(buf)) },
      close() { s.closed = true },
    }
    return s
  }
  return {
    eps, registry,
    makeEndpoint() {
      let onConn = null
      const ep = {
        onConnection(cb) { onConn = cb }, on() {}, close() {},
        deliver(s) { if (onConn) onConn(s) },
        punch(cands) { const target = eps.get(cands[0].to); const a = sock(() => b), b = sock(() => a); target.deliver(b); return Promise.resolve(a) },
      }
      return ep
    },
    register(S, ep) { eps.set(S, ep) },
  }
}
function baseDeps(board) {
  const noise = baseNoise()
  return {
    generateIdentity: () => mkIdentity('SELF', 'self'),
    decodeKey: (s) => { const id = board.registry.get(String(s).toUpperCase()); if (!id) throw new TypoError('bad key'); return { version: 0, flags: 0, commitment: id.xPub } },
    verifyCommitment: (c, _ed, x) => Buffer.compare(Buffer.from(c), Buffer.from(x)) === 0,
    encodeKey: (_ed, x) => { for (const [S, id] of board.registry) if (Buffer.from(id.xPub).equals(Buffer.from(x))) return S; return 'UNKNOWN' },
    createEndpoint: async () => board.makeEndpoint(),
    initiator: noise.initiator, responder: noise.responder,
    resolve: async (s) => [{ to: String(s).toUpperCase() }], publishAll: async () => {},
  }
}
async function buildListener(board, S, tag, listenOpts = {}) {
  const id = mkIdentity(S, tag); board.registry.set(S, id)
  const ep = board.makeEndpoint(); board.register(S, ep)
  const node = await listen(id, { endpoint: ep, deps: baseDeps(board), now: () => 0, keepaliveMs: 1e12, tickMs: 1e9, ...listenOpts })
  return { node, ep }
}
async function buildDialer(board, S, tag) {
  const id = mkIdentity(S, tag); board.registry.set(S, id)
  const ep = board.makeEndpoint(); board.register(S, ep)
  const node = await listen(id, { endpoint: ep, deps: baseDeps(board), now: () => 0, keepaliveMs: 1e12, tickMs: 1e9 })
  return node
}
const nextTick = () => new Promise((r) => setImmediate(r))

test('DOS-1 (node): a delivered accept that never sends HS1 creates NO peer record (deferred to auth)', async () => {
  const board = makeBoard()
  const { node, ep } = await buildListener(board, 'LISTEN', 'lis')
  // Simulate the transport handing up an inbound socket (a PROBE was accepted) that then goes silent:
  // acceptConnection sends its HELLO but no HS1 ever arrives.
  let handler = null
  const fake = {
    closed: false, rinfo: { address: 'x', port: 1 },
    get onMessage() { return handler }, set onMessage(fn) { handler = fn },
    send() {}, close() { this.closed = true },
    confirm() { this._confirmed = true },     // present on real accepts; never called here (no HS1)
  }
  ep.deliver(fake)
  await nextTick()
  assert.equal(node.peers().length, 0, 'no peer record exists before HS1 authenticates')
  node.close()
})

test('DOS-1 (node): inbound peer records are capped — a flood cannot exhaust memory or evict live peers', async () => {
  const board = makeBoard()
  const { node } = await buildListener(board, 'LISTEN', 'lis', { maxInboundPeers: 4 })
  // 12 distinct dialers (distinct statics ⇒ distinct peer keys) all handshake into ONE listener.
  const dialers = []
  for (let i = 0; i < 12; i++) dialers.push(await buildDialer(board, 'DIAL' + i, 'd' + i))
  await Promise.allSettled(dialers.map((d) => Promise.race([d.connect('LISTEN'), delay(100)])))
  await delay(50)
  assert.equal(node.peers().length, 4, 'inbound peer table capped at maxInboundPeers (4), extra dialers refused')
  node.close(); dialers.forEach((d) => d.close())
})

// ══════════════════════════════════════════════════════════════════════════════════════════════
// META-1 — the cleartext HELLO answers ONLY a prober that proves K_inv (invite mode); off-path
// scanners get silence. Reusable-S is unchanged (S is public — the pubkeys it commits to are not a
// secret worth gating).
// ══════════════════════════════════════════════════════════════════════════════════════════════

test('META-1 (transport): probeAuth gates the ACK+accept — a bad-proof PROBE gets NOTHING back', async () => {
  const ep = await createEndpoint({})
  const SECRET = Buffer.from('secret-8')
  let conns = 0
  ep.onConnection(() => { conns++ })
  ep.probeAuth((tok, nonce) => Buffer.from(nonce).equals(SECRET))   // only the exact proof passes

  // bad proof: expect NO datagram back (no PROBE_ACK, no accept)
  const bad = dgram.createSocket('udp4')
  const badGot = []
  bad.on('message', (m) => badGot.push(m))
  await new Promise((r) => bad.bind(0, r))
  bad.send(probePkt(PROBE, randomBytes(8), randomBytes(8)), ep.port4, '127.0.0.1')
  await delay(200)
  assert.equal(badGot.length, 0, 'scanner with no K_inv proof receives NOTHING (no ACK, no accept)')
  assert.equal(conns, 0, 'no onConnection for an unauthenticated prober')

  // good proof: PROBE_ACK comes back and onConnection fires
  const good = dgram.createSocket('udp4')
  const goodGot = []
  good.on('message', (m) => goodGot.push(m))
  await new Promise((r) => good.bind(0, r))
  good.send(probePkt(PROBE, randomBytes(8), SECRET), ep.port4, '127.0.0.1')
  await delay(200)
  assert.ok(goodGot.length >= 1, 'prover with the K_inv proof gets a PROBE_ACK')
  assert.equal(conns, 1, 'onConnection fires exactly once for the authenticated prover')
  bad.close(); good.close(); ep.close()
})

// node-level: real endpoint + real invite proof. A scanner never elicits the pubkey-bearing HELLO.
async function inviteListener(secret) {
  const id = generateIdentity()
  const ep = await createEndpoint({})
  const noopResolve = async function* () {}
  const node = await listen(id, {
    endpoint: ep, invite: secret, now: () => Date.now(), keepaliveMs: 1e12, tickMs: 1e9,
    deps: { generateIdentity, decodeKey, verifyCommitment, encodeKey, initiator, responder, resolve: noopResolve, publishAll: () => ({ stop() {} }) },
  })
  return { id, ep, node }
}
/** Collect datagrams on a fresh scanner socket; send one PROBE; return any HELLO frame seen. */
async function scan(port, tok, nonce, ms = 400) {
  const s = dgram.createSocket('udp4')
  const frames = []
  s.on('message', (m) => { const f = decodeFrame(m); if (f) frames.push(f) })
  await new Promise((r) => s.bind(0, r))
  s.send(probePkt(PROBE, tok, nonce), port, '127.0.0.1')
  await delay(ms)
  s.close()
  return frames.filter((f) => f.type === TYPE.HELLO)
}

test('META-1 (node): invite mode — a scanner without the K_inv proof never elicits the HELLO; the invitee does', async () => {
  const secret = generateInviteSecret()
  const inv = createInvite(secret)
  const { ep, node } = await inviteListener(secret)
  try {
    // scanner: correct token shape, WRONG nonce → no HELLO (the pubkeys never leak)
    const scannerHellos = await scan(ep.port4, randomBytes(8), randomBytes(8))
    assert.equal(scannerHellos.length, 0, 'off-path scanner harvests NO identity pubkeys (no HELLO)')

    // invitee: same token, nonce = the K_inv proof over it → HELLO is elicited
    const tok = randomBytes(8)
    const proof = inv.rid('probe', tok.toString('hex'), 8)
    const inviteeHellos = await scan(ep.port4, tok, proof)
    assert.ok(inviteeHellos.length >= 1, 'the K_inv-proving invitee DOES elicit the HELLO (still connects)')
  } finally { node.close(); ep.close() }
})

test('META-1 (e2e): the honest invitee completes a full IKpsk2 handshake THROUGH the live probeAuth gate (real UDP)', async () => {
  // The in-memory invite-mode.test.js board bypasses the transport (its punch delivers directly), so
  // it never exercises the K_inv proof gate. This runs two REAL endpoints over loopback: the invitee's
  // punch carries the K_inv-derived proof nonce, the listener's probeAuth verifies it, and only then
  // does first-contact proceed to a real Noise_IKpsk2 handshake. Reliability floor for META-1.
  const alice = generateIdentity(), bob = generateIdentity()
  const secret = generateInviteSecret()
  const inviteS = encodeKey(alice.edPub, alice.xPub, INVITE_FLAG)
  const share = formatShare(inviteS, secret)

  const epA = await createEndpoint({}), epB = await createEndpoint({})
  const realCrypto = { generateIdentity, decodeKey, verifyCommitment, encodeKey, initiator, responder }
  const noopRace = () => ({ resolve: async function* () {}, publishAll: () => ({ stop() {} }), channels: [] })
  // dialer's invite rendezvous resolves straight to Alice's loopback candidate (rendezvous is not
  // what META-1 is about; the punch-proof + probeAuth gate is).
  const dialRace = () => ({
    resolve: async function* () { yield { proto: 'udp4', ip: '127.0.0.1', port: epA.port4, kind: 'host' } },
    publishAll: () => ({ stop() {} }), channels: [],
  })

  const A = await listen(alice, {
    endpoint: epA, invite: secret, now: () => Date.now(), keepaliveMs: 1e12, tickMs: 100,
    deps: { ...realCrypto, resolve: async function* () {}, publishAll: () => ({ stop() {} }), makeRace: noopRace },
  })
  const B = await listen(bob, {
    endpoint: epB, now: () => Date.now(), keepaliveMs: 1e12, tickMs: 100,
    deps: { ...realCrypto, resolve: async function* () {}, publishAll: () => ({ stop() {} }), makeRace: dialRace },
  })
  try {
    const got = []
    A.on('message', (_p, d) => got.push(d.toString()))
    const peer = await Promise.race([B.connect(share), delay(6000).then(() => null)])
    assert.ok(peer && peer.connected, 'invitee completed the real IKpsk2 handshake through the proof gate')
    assert.equal(peer.key, alice.S, 'peer.key is Alice’s bare S (MITM-free first-ack)')
    await peer.send('hello through the gate')
    await delay(200)
    assert.deepEqual(got, ['hello through the gate'], 'application message delivered E2E over the gated channel')
  } finally { A.close(); B.close(); epA.close(); epB.close() }
})

test('META-1 (node): reusable-S mode is UNCHANGED — any PROBE still elicits the cleartext HELLO', async () => {
  const id = generateIdentity()
  const ep = await createEndpoint({})
  const noopResolve = async function* () {}
  const node = await listen(id, {
    endpoint: ep, now: () => Date.now(), keepaliveMs: 1e12, tickMs: 1e9,
    deps: { generateIdentity, decodeKey, verifyCommitment, encodeKey, initiator, responder, resolve: noopResolve, publishAll: () => ({ stop() {} }) },
  })
  try {
    const hellos = await scan(ep.port4, randomBytes(8), randomBytes(8))
    assert.ok(hellos.length >= 1, 'reusable-S: an ordinary PROBE elicits the HELLO exactly as before (no probeAuth installed)')
  } finally { node.close(); ep.close() }
})
