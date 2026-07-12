// test/peer-dedup.test.js — one record per peer, whichever direction it arrived from.
//
// THE BUG (latent; tui-group hit its consequence). node._peers is keyed TWO ways and cannot be keyed
// one way: a DIALED peer by its 26-char S (all we know before the handshake), an ACCEPTED one by
// 'static:'+xPub (all we know after it). They are not interconvertible at dial time — decodeKey(S)
// yields a 110-bit COMMITMENT, not the pubkeys — so `_peers.get(S)` structurally MISSES a peer that
// reached us inbound, and connect(S) minted a SECOND record and ran a whole SECOND dial (rendezvous +
// punch + a second Noise session) against someone we were already talking to.
//
// THE FIX. The commitment is the bridge: verifyCommitment tests a KNOWN pubkey pair against it, and an
// accepted record has stored the peer's Noise-authenticated remoteEd/remoteStatic since its handshake.
// findPeer() asks each record "are you the peer S names?" — the same check the HELLO gate trusts.
//
// The REAL stack runs here (real key.js, invite.js, noise.js, wire.js, race.js); only the transport
// socket and the rendezvous channel are in-memory. So verifyCommitment under test is the REAL one, not
// a mock that would happily agree with itself. Zero deps, zero network.

import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { listen } from '../src/node.js'
import { generateIdentity, decodeKey, verifyCommitment, encodeKey } from '../src/key.js'
import { initiator, responder } from '../src/noise.js'
import { createRace } from '../src/rendezvous/race.js'
import { createInvite, generateInviteSecret, formatShare, INVITE_FLAG } from '../src/invite.js'

const NOW = () => Date.UTC(2026, 6, 12)
const nextTick = () => new Promise((r) => setImmediate(r))
const settle = async (n = 12) => { for (let i = 0; i < n; i++) await nextTick() }

// ── in-memory transport switchboard; counts every punch, so a duplicate DIAL cannot hide ───────────
function makeBoard() {
  const eps = new Map()
  let nextPort = 43000
  const punches = []                                     // every dial that reached the transport
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
    punches,
    makeEndpoint() {
      const port = nextPort++
      const ep = Object.assign(new EventEmitter(), {
        port,
        _onConn: null,
        candidates: () => [{ proto: 'udp4', ip: '127.0.0.1', port }],
        onConnection(cb) { ep._onConn = cb },
        close() {},
        punch(cands) {
          punches.push(cands && cands[0] && cands[0].port)
          const target = eps.get(cands[0].port)
          if (!target) return new Promise(() => {})       // nobody there — a real dial would keep trying
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

function memChannel(net, codec) {
  return {
    name: 'tracker', ridLen: 20,
    announce(rid, info) {
      const blob = { v: 1, ts: 1, candidates: info.candidates }
      net.set(rid.toString('hex'), codec ? codec.seal(blob, rid) : blob)
    },
    async *lookup(rid) {
      const rec = net.get(rid.toString('hex'))
      if (!rec) return
      const blob = codec ? codec.open(rec, rid) : rec
      if (blob) yield { candidates: blob.candidates, ts: blob.ts }
    },
    close() {},
  }
}

function depsFor(board, net) {
  const makeRace = (inv = null) => {
    const ch = memChannel(net, inv ? inv.codec : null)
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

const mkNode = (board, net, id, opts = {}) =>
  listen(id, { deps: depsFor(board, net), now: NOW, keepaliveMs: 1e12, tickMs: 25, ...opts })

/** A dials B and B accepts — so B holds an INBOUND ('static:'+xPub) record for A, and A an S-keyed one. */
async function linked() {
  const board = makeBoard(), net = new Map()
  const idA = generateIdentity(), idB = generateIdentity()
  const A = await mkNode(board, net, idA)
  const B = await mkNode(board, net, idB)
  const gotB = []
  B.on('message', (_p, m) => gotB.push(m.toString()))
  const aToB = await A.connect(idB.S)
  await settle()
  assert.equal(B.peers().length, 1, 'B holds exactly one (inbound) record for A')
  assert.equal(B.peers()[0].connected, true)
  return { board, net, idA, idB, A, B, aToB, gotB }
}

// ── 1. the duplicate is never created ──────────────────────────────────────────────────────────────

test('dedup: connect(S) on a peer that reached us INBOUND returns the live peer — no 2nd record, no 2nd dial', async () => {
  const { board, idA, A, B } = await linked()
  const punchesBefore = board.punches.length

  const back = await B.connect(idA.S)                     // pre-fix: MISS -> new record + a whole new dial
  await settle()

  assert.equal(B.peers().length, 1, 'still exactly ONE record for A — the inbound one was reused')
  assert.equal(back, B.peers()[0], 'connect() handed back the record we already had')
  assert.equal(back.connected, true)
  assert.equal(board.punches.length, punchesBefore, 'and NOT ONE new punch was fired')
  A.close(); B.close()
})

test('dedup: the adopted record is the live session — B can talk to A on it', async () => {
  const { idA, A, B } = await linked()
  const gotA = []
  A.on('message', (_p, m) => gotA.push(m.toString()))

  const back = await B.connect(idA.S)
  await back.send('over the link that already existed')
  await settle()

  assert.deepEqual(gotA, ['over the link that already existed'])
  A.close(); B.close()
})

// ── 2. the negative control: dedup must not over-match ──────────────────────────────────────────────

test('dedup: a DIFFERENT peer is not matched — its S still gets its own record and a real dial', async () => {
  const { board, net, A, B } = await linked()
  const idC = generateIdentity()
  const C = await mkNode(board, net, idC)
  const punchesBefore = board.punches.length

  const bToC = await B.connect(idC.S)                     // C is a stranger: this MUST dial
  await settle()

  assert.equal(bToC.connected, true)
  assert.equal(B.peers().length, 2, 'A (adopted-able) + C (new) — the scan matched only the right one')
  assert.equal(board.punches.length, punchesBefore + 1, 'the stranger was really dialed')
  A.close(); B.close(); C.close()
})

// ── 3. DOS-1: an adopt-dial must not be shed out from under itself ─────────────────────────────────

test('dedup: adopting an inbound record clears _inbound — DOS-1 cannot shed the peer we are dialing', async () => {
  const { board, net, idA, A, B } = await linked()
  A.close()                                              // A goes away: B's record for A is now disconnected
  await settle()
  const recBefore = B.peers()[0]
  assert.equal(recBefore.connected, false, 'the inbound record is disconnected — i.e. DOS-1 shed bait')

  const A2 = await mkNode(board, net, idA)               // A comes back on a fresh endpoint
  await settle()
  const back = await B.connect(idA.S)                    // adopts the disconnected inbound record
  await settle()

  assert.equal(back.connected, true, 'the adopted record carried the new session')
  assert.equal(B.peers().length, 1, 'adopted, not duplicated')
  // The record is no longer inbound, so admitInbound() can never pick it as the "worthless" one to
  // shed (inbound + disconnected + empty outbox) while a dial is in flight on it.
  const inbound = [...B._peers.values()].filter((r) => r._inbound)
  assert.equal(inbound.length, 0, 'the adopted record no longer counts as inbound')
  A2.close(); B.close()
})

// ── 4. INVITE / BURN interaction — the one the lead most wanted proven ─────────────────────────────
//
// Case 1 broadens the connected-peer short-circuit, so the question is whether burn is weakened or
// double-spent. It is neither: a re-dial of a STILL-LIVE peer returns the live peer and never reaches
// the burn guard (identical to the S-keyed short-circuit that already existed), and a re-dial after the
// session ENDED still hits the guard and is refused — an adopted record does not smuggle it past.

test('burn + dedup: re-dialing a STILL-CONNECTED invite peer returns the live peer and does NOT spend the invite', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), bob = generateIdentity()
  const secret = generateInviteSecret()
  const share = formatShare(encodeKey(alice.edPub, alice.xPub, INVITE_FLAG), secret)
  const fp = createInvite(secret).fp.toString('hex')

  const A = await mkNode(board, net, alice, { invite: secret })
  const B = await mkNode(board, net, bob)
  try {
    const first = await B.connect(share)
    await settle()
    assert.equal(first.connected, true)
    assert.equal(B._burnedInvites.has(fp), true, 'the first connect SPENT the invite (unchanged)')
    const punchesBefore = board.punches.length

    // Re-dial while the session is STILL LIVE. This is the case dedup broadens: it must hand back the
    // live peer, not throw 'already used' and not open a second session.
    const again = await B.connect(share)
    await settle()

    assert.equal(again, first, 'the live peer came back — no second session')
    assert.equal(board.punches.length, punchesBefore, 'and no second dial')
    assert.equal(B.peers().length, 1, 'still one record')
    assert.equal(A._inviteBurned, true, 'the listener burned exactly once, on the first connect')
  } finally { A.close(); B.close() }
})

test('burn + dedup: after the session ENDS, a re-dial of the spent invite is still REFUSED (burn not bypassed)', async () => {
  const board = makeBoard(), net = new Map()
  const alice = generateIdentity(), bob = generateIdentity()
  const secret = generateInviteSecret()
  const share = formatShare(encodeKey(alice.edPub, alice.xPub, INVITE_FLAG), secret)

  const A = await mkNode(board, net, alice, { invite: secret })
  const B = await mkNode(board, net, bob)
  try {
    const peer = await B.connect(share)
    await settle()
    assert.equal(peer.connected, true)

    A.close()                                            // the session ends
    await settle()
    assert.equal(B.peers()[0].connected, false, 'B still HOLDS the (now disconnected) record — the adopt bait')

    // The record is adoptable and the peer is knowable, but the invite is SPENT. The guard must fire.
    await assert.rejects(
      B.connect(share),
      /already used|burned/i,
      'a spent invite must stay refused — an adoptable record must not smuggle a re-dial past burn',
    )
  } finally { A.close(); B.close() }
})

test('burn + dedup: the REUSABLE-S path still reconnects after a session ends (burn is invite-only)', async () => {
  const { board, net, idA, A, B } = await linked()
  A.close()
  await settle()
  assert.equal(B.peers()[0].connected, false)

  const A2 = await mkNode(board, net, idA)               // same identity, fresh process
  await settle()
  const back = await B.connect(idA.S)                    // reusable S: never burns, must reconnect
  await settle()

  assert.equal(back.connected, true, 'reusable-S reconnect is unaffected by dedup')
  assert.equal(B.peers().length, 1)
  A2.close(); B.close()
})
