// test/burn.test.js — metadata-privacy v2: burn-after-connect (the owner's "single connection then
// the route is gone, no re-use, no trail" — at the achievable, operational layer).
//
// Design: research/metadata-privacy.md §7 (the honest limit of "decrypt once") + §9 "v2", and the
// burn wiring in src/node.js. The REAL stack runs here (real key.js, invite.js, noise.js IKpsk2,
// wire.js, rendezvous/race.js); only the transport socket and the rendezvous CHANNEL are in-memory,
// so what is asserted is exactly the operational property chain the design claims:
//
//   1. STOP-REPUBLISH — once the invitee has connected, the invite's sealed record stops being
//      re-announced on every surface (epoch timer + BOTH netchange paths halt; the record ages off
//      via native TTL). Proven by spying the channel's announce count across a netchange.
//   2. LISTENER GOES DARK / K_inv RETIRED — a SECOND dial with the same share string (the captured/
//      leaked-share case: the attacker HOLDS K_inv) is refused even against a still-cached candidate,
//      because the listener retired the psk and answers nobody new.
//   3. DIALER SINGLE-USE — a second connect(share) of a spent invite is refused before any network.
//   4. REUSABLE-S UNAFFECTED — never burns: it re-announces on netchange and reconnects normally.
//
// Honest scope asserted by construction (not over-claimed): burn is OPERATIONAL and in-memory. It
// does NOT un-decrypt an already-captured blob (§7) and does NOT hide your IP from the peer (v3).
// Zero deps.

import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { listen } from '../src/node.js'
import { generateIdentity, decodeKey, verifyCommitment, encodeKey } from '../src/key.js'
import { initiator, responder } from '../src/noise.js'
import { createRace } from '../src/rendezvous/race.js'
import { createInvite, generateInviteSecret, formatShare, INVITE_FLAG } from '../src/invite.js'

const NOW = () => Date.UTC(2026, 6, 12) // fixed midday clock — far from rollover, so the epoch timer never fires in-test
const nextTick = () => new Promise((r) => setImmediate(r))

// A dial that never settles (the negative tests) must not let the loop drain and bail the runner out,
// so this timer is deliberately NOT unref'd.
function settlesWithin(p, ms) {
  let t
  const timeout = new Promise((r) => { t = setTimeout(() => r({ timedOut: true }), ms) })
  return Promise.race([p.then((v) => ({ ok: true, v }), (e) => ({ ok: false, e })), timeout])
    .finally(() => clearTimeout(t))
}

// ── in-memory transport switchboard; endpoints are EventEmitters so 'netchange' can be driven ──────
function makeBoard() {
  const eps = new Map()
  let nextPort = 41000
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
      const ep = Object.assign(new EventEmitter(), {
        port,
        _onConn: null,
        candidates: () => [{ proto: 'udp4', ip: '127.0.0.1', port }],
        onConnection(cb) { ep._onConn = cb },
        close() {},
        punch(cands) {
          const target = eps.get(cands[0].port)
          if (!target) return new Promise(() => {})            // nobody there: a real dial would keep trying
          const a = sock(() => b), b = sock(() => a)
          target._deliver(b)
          return Promise.resolve(a)
        },
        _deliver(s) { if (ep._onConn) ep._onConn(s) },
      })
      eps.set(port, ep)
      return ep
    },
  }
}

// ── in-memory rendezvous channel: OPAQUE BYTES exactly like tracker.js; records every announce ─────
function memChannel(net, codec, announces) {
  return {
    name: 'tracker', ridLen: 20,
    announce(rid, info) {
      if (announces) announces.push(rid.toString('hex'))
      const blob = { v: 1, ts: 1, candidates: info.candidates }
      net.set(rid.toString('hex'), codec ? codec.seal(blob, rid) : blob)
    },
    async *lookup(rid) {
      const rec = net.get(rid.toString('hex'))
      if (!rec) return
      const blob = codec ? codec.open(rec, rid) : rec            // null on wrong key / tamper -> ignored
      if (blob) yield { candidates: blob.candidates, ts: blob.ts }
    },
    close() {},
  }
}

function depsFor(board, net, { announces = null } = {}) {
  const makeRace = (inv = null) => {
    const ch = memChannel(net, inv ? inv.codec : null, announces)
    const r = createRace({ channels: [ch], invite: inv, now: NOW, lanGraceMs: 20 })
    return { resolve: r.resolve, publishAll: r.publishAll, channels: [ch] }
  }
  const base = makeRace(null)
  return {
    generateIdentity, decodeKey, verifyCommitment, encodeKey, initiator, responder,
    createEndpoint: async () => board.makeEndpoint(),
    makeRace, resolve: base.resolve, publishAll: base.publishAll,
  }
}

const mkNode = (board, net, id, opts = {}, over = {}) =>
  listen(id, { endpoint: opts.endpoint, deps: depsFor(board, net, over), now: NOW, keepaliveMs: 1e12, tickMs: 25, ...opts })

// ── 1. STOP-REPUBLISH — after the invitee connects, no further announce for that invite's rid ──────
test('burn: once the invitee connects, the invite record stops being re-announced (stop-republish)', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), bob = generateIdentity()
  const secret = generateInviteSecret()
  const inviteS = encodeKey(alice.edPub, alice.xPub, INVITE_FLAG)
  const share = formatShare(inviteS, secret)

  const aAnn = []                                                  // Alice's per-announce log (the surface's view)
  const aEp = board.makeEndpoint()
  const A = await mkNode(board, net, alice, { invite: secret, endpoint: aEp }, { announces: aAnn })
  const B = await mkNode(board, net, bob)
  try {
    await nextTick()
    assert.equal(A._inviteBurned, false, 'not burned before anyone connects')
    assert.ok(aAnn.length >= 1, 'listener announced the sealed record at least once')

    // netchange BEFORE connect still re-announces (the invite route is live until it is used)
    aEp.emit('netchange'); await nextTick()
    const beforeConnect = aAnn.length
    assert.ok(beforeConnect > 1, 'a pre-connect netchange re-announces (route is live): ' + beforeConnect)

    const got = []
    A.on('message', (_p, d) => got.push(d.toString()))
    const peer = await B.connect(share)
    assert.equal(peer.connected, true, 'invitee connected')
    assert.equal(A._inviteBurned, true, 'the invite is BURNED the moment the invitee connects')

    // The established session keeps working after burn (burn kills the ROUTE, not the connection).
    await peer.send('still alive after burn'); await nextTick()
    assert.deepEqual(got, ['still alive after burn'], 'the live peer is untouched by burn')

    // THE ASSERTION: no surface re-announces the burned invite, on any republish trigger.
    const afterConnect = aAnn.length
    for (let i = 0; i < 3; i++) { aEp.emit('netchange'); await nextTick() }
    await nextTick()
    assert.equal(aAnn.length, afterConnect, 'NO further announce for the burned invite across netchanges (stop-republish)')
  } finally { A.close(); B.close() }
})

// ── 2. LISTENER DARK — a captured share (holds K_inv) cannot re-open the route after burn ──────────
test('burn: after the invitee connects, a SECOND dialer with the same share string is refused (route dead)', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), bob = generateIdentity(), carol = generateIdentity()
  const secret = generateInviteSecret()
  const inviteS = encodeKey(alice.edPub, alice.xPub, INVITE_FLAG)
  const share = formatShare(inviteS, secret)

  const aEp = board.makeEndpoint()
  const A = await mkNode(board, net, alice, { invite: secret, endpoint: aEp })
  const B = await mkNode(board, net, bob)
  const C = await mkNode(board, net, carol)                        // the "captured share" attacker — a FRESH node (empty burn set)
  try {
    await nextTick()
    const peer = await B.connect(share)
    assert.equal(peer.connected, true, 'the legitimate invitee connects first')
    assert.equal(A._inviteBurned, true, 'burned')

    // The sealed record is STILL cached in `net` (a not-yet-expired surface). Carol holds the full
    // share (K_inv and all), finds the cached candidate, punches to Alice — and is refused: Alice
    // retired the psk and answers no new invite handshake. (C's own burn set is empty, proving it is
    // the LISTENER's darkness — not the dialer guard — that closes the route.)
    const ridHex = createInvite(secret).rid('tracker', '2026-07-12', 20).toString('hex')
    assert.ok(net.has(ridHex), 'the captured route is still cached on the surface (models a live TTL window)')

    const r = await settlesWithin(C.connect(share), 500)
    assert.notEqual(r.ok, true, 'the captured share cannot re-open the route — the listener is dark')
    assert.equal(C.peers().some((p) => p.connected), false, 'attacker got no connected peer')
  } finally { A.close(); B.close(); C.close() }
})

// ── 3. DIALER SINGLE-USE — a second connect(share) of a spent invite is refused before any network ─
test('burn: a second connect(share) of an already-used invite is refused on the dialer (single-use)', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), bob = generateIdentity()
  const secret = generateInviteSecret()
  const inviteS = encodeKey(alice.edPub, alice.xPub, INVITE_FLAG)
  const share = formatShare(inviteS, secret)

  const A = await mkNode(board, net, alice, { invite: secret })
  const B = await mkNode(board, net, bob)
  try {
    await nextTick()
    const peer = await B.connect(share)
    assert.equal(peer.connected, true)
    peer.close()                                                    // the session ended; the invite is spent
    await nextTick()

    await assert.rejects(() => B.connect(share), /burned|already used/i,
      'a re-dial of the spent one-time invite is refused before any network work')
  } finally { A.close(); B.close() }
})

// ── 4. REGRESSION BAR — reusable-S mode never burns: it re-announces + reconnects normally ─────────
test('reusable-S mode: unaffected by burn — re-announces on netchange, never marks _inviteBurned', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), bob = generateIdentity()

  const aAnn = []
  const aEp = board.makeEndpoint()
  const A = await mkNode(board, net, alice, { endpoint: aEp }, { announces: aAnn })   // NO invite
  const B = await mkNode(board, net, bob)
  try {
    await nextTick()
    const got = []
    A.on('message', (_p, d) => got.push(d.toString()))
    const peer = await B.connect(alice.S)
    assert.equal(peer.connected, true)
    assert.equal(A._inviteBurned, false, 'reusable-S mode is never burned')

    const baseline = aAnn.length
    for (let i = 0; i < 2; i++) { aEp.emit('netchange'); await nextTick() }
    await nextTick()
    assert.ok(aAnn.length > baseline, 'reusable-S KEEPS re-announcing on netchange (unaffected): ' + baseline + ' -> ' + aAnn.length)

    await peer.send('reusable still flows'); await nextTick()
    assert.deepEqual(got, ['reusable still flows'])
  } finally { A.close(); B.close() }
})
