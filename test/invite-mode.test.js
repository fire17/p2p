// test/invite-mode.test.js — metadata-privacy v1 wired into the public API (task #23).
//
// The REAL stack runs here: real key.js (S, commitment gate), real invite.js (K_inv → rid_inv/k_ip/
// psk), real noise.js (IK and IKpsk2), real wire.js, real rendezvous/race.js. Only the transport and
// the rendezvous CHANNEL are in-memory — so what is asserted is exactly the property chain the design
// claims: only the K_inv holder can LOCATE the record (rid_inv), OPEN it (k_ip), and COMPLETE the
// handshake (psk). Zero deps.

import test from 'node:test'
import assert from 'node:assert/strict'
import { listen } from '../src/node.js'
import { generateIdentity, decodeKey, verifyCommitment, encodeKey, deriveRid } from '../src/key.js'
import { initiator, responder } from '../src/noise.js'
import { createRace } from '../src/rendezvous/race.js'
import { createInvite, generateInviteSecret, formatShare, INVITE_FLAG, SEALED_LEN } from '../src/invite.js'

// ── in-memory transport switchboard (endpoints keyed by port; punch dials cands[0].port) ─────────
function makeBoard() {
  const eps = new Map()
  let nextPort = 40000
  function sock(getPeer) {
    let handler = null; const inbox = []
    const s = {
      closed: false, rinfo: { address: '127.0.0.1', port: 0 },
      get onMessage() { return handler },
      set onMessage(fn) { handler = fn; if (fn) while (inbox.length) fn(inbox.shift()) },
      _recv(buf) { if (handler) handler(buf); else inbox.push(buf) },
      send(buf) { if (s.closed) return; const p = getPeer(); if (p && !p.closed) p._recv(Buffer.from(buf)) },
      close() { s.closed = true },
    }
    return s
  }
  return {
    makeEndpoint() {
      const port = nextPort++
      let onConn = null
      const ep = {
        port,
        candidates: () => [{ proto: 'udp4', ip: '127.0.0.1', port }],
        onConnection(cb) { onConn = cb },
        on() {}, off() {}, close() {},
        punch(cands) {
          const target = eps.get(cands[0].port)
          if (!target) return new Promise(() => {})            // nobody there: a real dial would keep trying
          const a = sock(() => b), b = sock(() => a)
          target._deliver(b)
          return Promise.resolve(a)
        },
        _deliver(s) { if (onConn) onConn(s) },
      }
      eps.set(port, ep)
      return ep
    },
  }
}

// ── in-memory rendezvous channel: carries OPAQUE BYTES, exactly like tracker.js ──────────────────
// With a codec it seals/opens (invite mode); without one it stores the plaintext blob (v0.1.0 wire).
function memChannel(net, codec = null) {
  return {
    name: 'tracker', ridLen: 20,
    announce(rid, info) {
      const blob = { v: 1, ts: 1, candidates: info.candidates }
      net.set(rid.toString('hex'), codec ? codec.seal(blob, rid) : blob)
    },
    async *lookup(rid) {
      const rec = net.get(rid.toString('hex'))
      if (!rec) return
      const blob = codec ? codec.open(rec, rid) : rec           // null on wrong key / tamper -> ignored
      if (blob) yield { candidates: blob.candidates, ts: blob.ts }
    },
    close() {},
  }
}

function depsFor(board, net, { omniscient = null } = {}) {
  const makeRace = (inv = null) => {
    // `omniscient` models an attacker that already knows the target's ip:port (a leaked candidate) —
    // it bypasses the rendezvous entirely, so what is left to stop it is the handshake alone.
    const ch = omniscient
      ? { name: 'tracker', ridLen: 20, announce() {}, async *lookup() { yield { candidates: omniscient(), ts: 1 } }, close() {} }
      : memChannel(net, inv ? inv.codec : null)
    const r = createRace({ channels: [ch], invite: inv, now: () => Date.UTC(2026, 6, 12), lanGraceMs: 20 })
    return { resolve: r.resolve, publishAll: r.publishAll, channels: [ch] }
  }
  const base = makeRace(null)
  return {
    generateIdentity, decodeKey, verifyCommitment, encodeKey, initiator, responder,
    createEndpoint: async () => board.makeEndpoint(),
    makeRace, resolve: base.resolve, publishAll: base.publishAll,
  }
}

const NOW = () => Date.UTC(2026, 6, 12)
const nextTick = () => new Promise((r) => setImmediate(r))
// NOTE: the timer is deliberately NOT unref'd — a dial that never settles (the whole point of the
// negative tests) would otherwise let the event loop drain and the runner bail out mid-file.
function settlesWithin(p, ms) {
  let t
  const timeout = new Promise((r) => { t = setTimeout(() => r({ timedOut: true }), ms) })
  return Promise.race([p.then((v) => ({ ok: true, v }), (e) => ({ ok: false, e })), timeout])
    .finally(() => clearTimeout(t))
}

const mkNode = (board, net, id, opts = {}, over = {}) =>
  listen(id, { endpoint: opts.endpoint, deps: depsFor(board, net, over), now: NOW, keepaliveMs: 1e12, tickMs: 25, ...opts })

// ── 1. the happy path: an invitee finds, decrypts and handshakes ─────────────────────────────────
test('invite mode: listener seals candidates under rid_inv; the share-string holder connects (IKpsk2)', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), bob = generateIdentity()
  const secret = generateInviteSecret()
  const inviteS = encodeKey(alice.edPub, alice.xPub, INVITE_FLAG)     // same keypair, INVITE flag set
  const share = formatShare(inviteS, secret)

  const A = await mkNode(board, net, alice, { invite: secret })       // publishes ONLY under rid_inv, sealed
  const B = await mkNode(board, net, bob)
  try {
    await nextTick()
    // WHERE: the record is not at any S-derived rid — a non-holder cannot even locate it.
    const inv = createInvite(secret)
    const ridInv = inv.rid('tracker', '2026-07-12', 20).toString('hex')
    assert.ok(net.has(ridInv), 'published at rid_inv = HKDF(K_inv, "p2p-rvk-tracker-v1", epoch)')
    for (const S of [alice.S, inviteS]) {
      assert.equal(net.has(deriveRid(S, 'tracker', '2026-07-12', 20).toString('hex')), false,
        'nothing published at the S-derived rid (' + S.slice(0, 6) + '…)')
    }
    // WHAT: fixed-length ciphertext, no IP anywhere in it.
    const sealed = net.get(ridInv)
    assert.ok(Buffer.isBuffer(sealed) && sealed.length === SEALED_LEN, 'sealed blob is fixed-length (' + SEALED_LEN + ' B)')
    assert.equal(sealed.includes(Buffer.from('127.0.0.1')), false, 'no plaintext IP on the wire')
    assert.equal(sealed.includes(Buffer.from('candidates')), false, 'no plaintext JSON on the wire')

    // WHO: the share-string holder locates it, opens it, punches, and completes Noise_IKpsk2.
    const got = []
    A.on('message', (_p, d) => got.push(d.toString()))
    const peer = await B.connect(share)
    assert.equal(peer.connected, true, 'invitee connected')
    assert.equal(peer.key, alice.S, 'peer.key is the BARE S — invites are one-time, the durable contact is S')
    await peer.send('hello from the invitee')
    await nextTick()
    assert.deepEqual(got, ['hello from the invitee'])
  } finally { A.close(); B.close() }
})

// ── 2. the negative the whole design rests on ────────────────────────────────────────────────────
test('invite mode: an S-holder WITHOUT K_inv can neither locate the record nor complete the handshake', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), mallory = generateIdentity()
  const secret = generateInviteSecret()

  const A = await mkNode(board, net, alice, { invite: secret })
  const M = await mkNode(board, net, mallory)                          // holds alice.S, never got K_inv
  try {
    await nextTick()
    // (a) cannot LOCATE: resolving the reusable S finds nothing — the record is at rid_inv. The dial
    // therefore never reaches a peer (it either fails for want of a candidate or waits forever).
    assert.equal(net.has(deriveRid(alice.S, 'tracker', '2026-07-12', 20).toString('hex')), false,
      'alice published NOTHING at her S-derived rid — only at rid_inv')
    const r = await settlesWithin(M.connect(alice.S), 400)
    assert.notEqual(r.ok, true, 'connect never SUCCEEDS for a non-holder (it fails or waits for a candidate that never comes)')
    assert.equal(M.peers().some((p) => p.connected), false, 'no connected peer')
  } finally { A.close(); M.close() }
})

test('invite mode: even with the IP leaked, a plain-IK dialer fails the handshake (psk is fail-closed)', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), mallory = generateIdentity()
  const secret = generateInviteSecret()

  const aEp = board.makeEndpoint()
  const A = await mkNode(board, net, alice, { invite: secret, endpoint: aEp })
  // Mallory already knows alice's ip:port (leaked/observed) and skips rendezvous entirely.
  const M = await listen(mallory, {
    deps: depsFor(board, net, { omniscient: () => aEp.candidates() }),
    now: NOW, keepaliveMs: 1e12, tickMs: 25,
  })
  try {
    const divergences = []
    A.on('divergence', (_p, d) => divergences.push(d.reason))
    const r = await settlesWithin(M.connect(alice.S), 600)             // plain IK: no psk, no prologue
    assert.ok(!r.ok, 'the handshake never completes for a non-holder of K_inv')
    assert.ok(divergences.includes('handshake'), 'listener rejected msg1 at the Noise layer (fail-closed): ' + JSON.stringify(divergences))
  } finally { A.close(); M.close() }
})

// ── 3. the regression bar: reusable-S mode is byte-for-byte unchanged ────────────────────────────
test('reusable-S mode: plain rid, PLAINTEXT blob, plain IK — unchanged by the invite feature', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), bob = generateIdentity()

  const A = await mkNode(board, net, alice)
  const B = await mkNode(board, net, bob)
  try {
    await nextTick()
    const rid = deriveRid(alice.S, 'tracker', '2026-07-12', 20).toString('hex')
    assert.ok(net.has(rid), 'published at the S-derived rid (v0.1.0 behaviour)')
    const rec = net.get(rid)
    assert.equal(Buffer.isBuffer(rec), false, 'the blob is plaintext JSON, not a sealed ciphertext')
    assert.equal(rec.candidates[0].ip, '127.0.0.1')

    const got = []
    A.on('message', (_p, d) => got.push(d.toString()))
    const peer = await B.connect(alice.S)
    assert.equal(peer.connected, true)
    assert.equal(peer.key, alice.S)
    await peer.send('plain IK still works')
    await nextTick()
    assert.deepEqual(got, ['plain IK still works'])
  } finally { A.close(); B.close() }
})

test('connect: a bare invite-flagged key without its tail is refused before any network work', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), bob = generateIdentity()
  const inviteS = encodeKey(alice.edPub, alice.xPub, INVITE_FLAG)
  const B = await mkNode(board, net, bob)
  try {
    await assert.rejects(() => B.connect(inviteS), /one-time invite key/)
  } finally { B.close() }
})

// ── 4. task #22 on the REAL stack: the 16-byte Noise tag is what makes the budget bite ───────────
test('send: oversized payload rejects (never hangs) over the REAL Noise/wire stack', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), bob = generateIdentity()
  const A = await mkNode(board, net, alice)
  const B = await mkNode(board, net, bob)
  try {
    await nextTick()
    const peer = await B.connect(alice.S)
    const limit = peer.maxMessage                                     // 1200 - 17 - 16 - 5 = 1162
    const got = []
    A.on('message', (_p, d) => got.push(d.length))

    const r = await settlesWithin(peer.send(Buffer.alloc(limit + 1, 0x41)), 1000)
    assert.equal(r.timedOut, undefined, 'send() SETTLED (the old bug hung here forever)')
    assert.ok(!r.ok && r.e instanceof RangeError && r.e.reason === 'oversize', 'rejected: ' + (r.e && r.e.message))

    // exactly at the limit still fits the real AEAD + wire budget end-to-end
    await peer.send(Buffer.alloc(limit, 0x42))
    await nextTick()
    assert.deepEqual(got, [limit], 'a payload exactly at the limit rides the real stack')
  } finally { A.close(); B.close() }
})
