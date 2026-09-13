// test/split-commit.test.js — THE SPLIT-COMMIT RIG.
//
// WHY THIS FILE EXISTS (P2P-SERVER-LINK, 2026-09-13): a Debian VPS joined the Agent Tunnel three
// times and the link carried no data on at least one side, then died at ~70s (wire liveness 25s x3).
// One hypothesis on the table was a SPLIT COMMIT — the two ends committing to DIFFERENT legs of the
// raced transport (UDP vs the WSS relay), so each end talks into a pipe the other never reads.
//
// This rig is the MEASUREMENT for that hypothesis, not a fix for it. Reading the code first
// (src/compose.js send()/commit(), src/node.js dial + acceptConnection) says a split cannot happen
// at this commit: the dialer commits on the first well-formed inbound frame, sends HS1 to the
// WINNER ONLY, and the listener attaches on the very socket that delivered that HS1 — so the ends
// land on the same leg BY CONSTRUCTION. The honest thing to do with that reading is to EXECUTE it
// against real transports with one direction of UDP genuinely dropped, and report the result
// either way.
//
// EXPECTED: all four scenarios GREEN on 1cb873a. A GREEN run here is the datum that falsifies the
// split-commit hypothesis for this codebase — it is not a no-op test. Its teeth are proven by two
// sabotages recorded in the WI2 report: (A) compose.js routing HS1 to EVERY leg instead of the
// winner, (B) the rig's drop wrapper turned into a pass-through.
//
// WHAT IS REAL HERE: real key.js / noise.js / wire.js / transport.js (real loopback UDP sockets) and
// the real composite. The only fake is the MQTT broker (test/fixtures/mock-relay.mjs) — NO network,
// NO mDNS, NO LAN traffic, nothing that can disturb a live session on this machine.
//
// THE DROP SEAM needs no production code: a directional UDP outage is a wrapper around the dgram
// socket's own send(). It COUNTS every attempt and forwards none — so "attempted >= 1, delivered 0"
// is an assertion about the outage itself, and a pass-through wrapper makes it RED (sabotage B).

import test from 'node:test'
import assert from 'node:assert/strict'
import { listen } from '../src/node.js'
import * as nodeTransport from '../src/transport-node.js'
import * as key from '../src/key.js'
import * as noise from '../src/noise.js'
import { mockRelay } from './fixtures/mock-relay.mjs'

const RELAYS = ['ws://mock-relay']
const delay = (ms) => new Promise((r) => setTimeout(r, ms))
const race = (p, ms, what) => Promise.race([p, delay(ms).then(() => { throw new Error('timed out: ' + what) })])

const crypto = () => ({
  generateIdentity: key.generateIdentity, decodeKey: key.decodeKey,
  verifyCommitment: key.verifyCommitment, encodeKey: key.encodeKey,
  initiator: noise.initiator, responder: noise.responder,
})

/** A TUI-shaped peer: the DEFAULT composed endpoint (real UDP + the mock relay). */
async function tuiPeer(relay, { resolve = async () => [], wssDelayMs = 100 } = {}) {
  const id = await key.generateIdentity()
  let ep = null
  const node = await listen(id, {
    deps: {
      ...crypto(),
      createEndpoint: async (o) => (ep = await nodeTransport.createEndpoint({
        ...o, relays: RELAYS, WebSocket: relay.WebSocket, wssDelayMs,
      })),
      resolve: async (S) => resolve(String(S)),
      publishAll: () => ({ stop() {} }),          // no mDNS / DHT / tracker — nothing announced
    },
  })
  const got = []
  node.on('message', (_p, m) => got.push(m.toString()))
  return { id, node, ep, got }
}

/**
 * Tap this endpoint's UDP sockets.
 * `drop:true`  => count the attempt and SWALLOW it (a one-directional UDP outage).
 * `drop:false` => count it and forward (the positive control: proves UDP really carried the dial).
 * @returns {{attempted:number, delivered:number, restore:Function}}
 */
function tapUdp(ep, { drop }) {
  const undone = []
  const c = { attempted: 0, delivered: 0, restore: () => undone.forEach((f) => f()) }
  const udp = ep && ep.udp
  assert.ok(udp, 'tapUdp: endpoint has no .udp (not a composed endpoint)')
  for (const name of ['sock4', 'sock6']) {
    const s = udp[name]
    if (!s) continue
    const orig = s.send.bind(s)
    s.send = (...args) => {
      c.attempted++
      if (drop) return                            // the outage: nothing leaves this host on UDP
      c.delivered++
      return orig(...args)
    }
    undone.push(() => { s.send = orig })
  }
  assert.ok(undone.length > 0, 'tapUdp: no UDP socket to tap')
  return c
}

/** The peer record the LISTENER ends up with. */
function listenerPeer(node, ms) {
  const live = node.peers().find((p) => p.connected)
  if (live) return Promise.resolve(live)
  return new Promise((res, rej) => {
    const t = setTimeout(() => rej(new Error('listener never established a peer')), ms)
    node.on('peer', (p) => { clearTimeout(t); res(p) })
  })
}

/**
 * One scenario. `dropDialer`/`dropListener` name the UDP direction(s) that are down.
 * Asserts: both ends connect, a message + its ack flows BOTH ways, and — the point of the file —
 * the two ends report the SAME committed transport leg.
 */
async function scenario({ name, dropDialer, dropListener, expectProto }) {
  const relay = mockRelay({ hopMs: 15 })
  const eps = new Map()                                    // S -> endpoint, for loopback candidates
  const resolve = (S) => {
    const ep = eps.get(S)
    return ep ? [{ proto: 'udp4', ip: '127.0.0.1', port: ep.port4, kind: 'lan' }] : []
  }
  const listener = await tuiPeer(relay, { resolve })
  eps.set(listener.id.S, listener.ep)
  const dialer = await tuiPeer(relay, { resolve })
  eps.set(dialer.id.S, dialer.ep)

  // Install BOTH taps before the dial: an outage that starts mid-dial is a different experiment.
  const lTap = tapUdp(listener.ep, { drop: dropListener })
  const dTap = tapUdp(dialer.ep, { drop: dropDialer })

  try {
    const dPeer = await race(dialer.node.connect(listener.id.S), 8000, name + ': connect')
    const lPeer = await race(listenerPeer(listener.node, 8000), 8000, name + ': listener accept')

    await race(dPeer.send('a2b'), 3000, name + ': dialer -> listener msg+ack')
    await race(lPeer.send('b2a'), 3000, name + ': listener -> dialer msg+ack')
    await delay(60)

    assert.deepEqual(listener.got, ['a2b'], name + ': listener received the dialer message')
    assert.deepEqual(dialer.got, ['b2a'], name + ': dialer received the listener message')
    assert.equal(listener.node._peers.size, 1, name + ': one dial => one peer record on the listener')

    // VALIDITY FIRST, THEN THE MEASUREMENT. The counters say whether this scenario was the
    // experiment it claims to be; an invalid experiment must not be judged on its outcome, so a
    // broken drop seam has to trip HERE and not further down as a confusing "wrong leg" verdict.
    if (dropDialer) {
      assert.ok(dTap.attempted >= 1, name + ': dialer UDP outage saw no attempt (vacuous)')
      assert.equal(dTap.delivered, 0, name + ': dialer UDP outage leaked ' + dTap.delivered + ' datagrams')
    }
    if (dropListener) {
      assert.equal(lTap.delivered, 0, name + ': listener UDP outage leaked ' + lTap.delivered + ' datagrams')
      // The vacuity guard is DIRECTIONAL. A listener only sends UDP in ANSWER to a PROBE, so it has
      // something to drop only while the dialer's UDP still arrives. With both directions down
      // (S3) nothing ever reaches it and its attempt count is 0 BY CONSTRUCTION — asserted exactly,
      // not skipped, so a future change that makes the listener speak UDP unprompted shows up here.
      if (dropDialer) {
        assert.equal(lTap.attempted, 0,
          name + ': with the dialer UDP dead the listener has nothing to answer; got ' + lTap.attempted + ' attempts')
      } else {
        assert.ok(lTap.attempted >= 1, name + ': listener UDP outage saw no attempt (vacuous)')
      }
    }
    if (!dropDialer && !dropListener) {
      assert.equal(dTap.delivered + lTap.delivered, dTap.attempted + lTap.attempted,
        name + ': control dropped datagrams it should have forwarded')
      assert.ok(dTap.delivered > 0 && lTap.delivered > 0, name + ': control carried no real UDP traffic')
      assert.equal(relay.published, 0, name + ': UDP won, so the relay must have carried nothing (got ' + relay.published + ')')
    } else {
      assert.ok(relay.published > 0, name + ': the relay was expected to carry this dial')
    }

    // THE MEASUREMENT: the leg each end actually rides. A split commit is exactly these two
    // strings disagreeing — which is the whole question this file was built to answer.
    assert.equal(dPeer.transport, expectProto, name + ': dialer committed leg')
    assert.equal(lPeer.transport, expectProto, name + ': listener committed leg')
    assert.equal(dPeer.transport, lPeer.transport, name + ': both ends on the SAME leg (no split commit)')
  } finally {
    dTap.restore(); lTap.restore()
    dialer.node.close(); listener.node.close(); relay.close()
  }
}

// ── S0 — positive control: nothing dropped, UDP must win ─────────────────────────────────────────
test('split-commit S0 (control): no drop => both ends commit to udp4, messages both ways', async () => {
  await scenario({ name: 'S0', dropDialer: false, dropListener: false, expectProto: 'udp4' })
})

// ── S1 — the VPS->Mac shape: the dialer's UDP never leaves the box ───────────────────────────────
test('split-commit S1: dialer->listener UDP dropped => both ends commit to wss', async () => {
  await scenario({ name: 'S1', dropDialer: true, dropListener: false, expectProto: 'wss' })
})

// ── S2 — the Mac->VPS shape: the listener's UDP (PROBE_ACK + HELLO) never leaves ─────────────────
test('split-commit S2: listener->dialer UDP dropped => both ends commit to wss', async () => {
  await scenario({ name: 'S2', dropDialer: false, dropListener: true, expectProto: 'wss' })
})

// ── S3 — UDP fully dead in both directions ───────────────────────────────────────────────────────
test('split-commit S3: UDP dropped both ways => both ends commit to wss', async () => {
  await scenario({ name: 'S3', dropDialer: true, dropListener: true, expectProto: 'wss' })
})

// ── S4 — the clause S0..S3 CANNOT reach ──────────────────────────────────────────────────────────
//
// MEASURED, not assumed: sabotage A (compose.js routing every outbound frame to `subs` instead of
// the winner) leaves S0..S3 all GREEN. The reason is structural, and it bounds what those four
// scenarios prove: in each of them only ONE leg is ever live when the commit happens — in S0 the
// relay leg is skipped outright because UDP already won, and in S1..S3 the UDP punch never resolves
// a socket at all, so `subs` has exactly one entry and "broadcast to subs" IS "send to the winner".
// A sabotage that cannot change behaviour proves nothing about the rig.
//
// So the two-live-leg routing clause — the one a split commit would actually live in — gets its own
// deterministic case, driven straight against composePunch with two synthetic legs and no timing.
// (test/browser-raced-transport.test.js also covers this clause and also goes RED on sabotage A;
// this case is kept here so the rig that carries the split-commit question owns its own teeth.)
test('split-commit S4: with TWO live legs, every post-commit frame goes to the WINNER only', async () => {
  const { composePunch } = await import('../src/compose.js')
  const { encodeFrame, TYPE } = await import('../src/wire.js')

  // The leg records EVERY send, closed or not — deliberately unguarded. A real socket refuses to
  // send once closed, which would mask a routing leak behind the socket's own self-defence; this
  // case is about compose.js's routing decision, so the leg must not do compose.js's job for it.
  const mkLeg = (proto) => {
    const leg = { proto, closed: false, sent: [], rinfo: { address: proto, port: 0 }, onMessage: null }
    leg.send = (b) => { leg.sent.push(Buffer.from(b)) }
    leg.close = () => { leg.closed = true }
    return leg
  }
  const a = mkLeg('udp4')      // the leg that will stay silent
  const b = mkLeg('wss')       // the leg the peer actually answers on
  const composite = await composePunch([Promise.resolve(a), Promise.resolve(b)])

  // Before any inbound the route is unknown, so an offer legitimately fans out to both.
  composite.send(Buffer.from('offer'))
  assert.equal(a.sent.length, 1, 'pre-commit offer must reach leg a')
  assert.equal(b.sent.length, 1, 'pre-commit offer must reach leg b')
  assert.equal(composite.winnerProto, null, 'no commit before a well-formed inbound frame')

  // The peer answers on b with a well-formed HELLO: that commits the composite to b.
  b.onMessage(encodeFrame(TYPE.HELLO, Buffer.alloc(8), 0, 0, Buffer.alloc(4)), b.rinfo)
  assert.equal(composite.winnerProto, 'wss', 'committed leg is the one that delivered the frame')
  assert.ok(a.closed, 'the loser leg must be CLOSED, not merely ignored')
  assert.ok(!b.closed, 'the winner stays open')

  // THE CLAUSE: HS1 and everything after it ride the winner alone. Broadcasting here is exactly the
  // shape that would mint a second responder on the listener — the split-commit failure mode.
  composite.send(Buffer.from('HS1'))
  assert.equal(b.sent.length, 2, 'post-commit frame must reach the winner')
  assert.equal(a.sent.length, 1, 'post-commit frame LEAKED to the loser leg (split commit)')

  // A leg that arrives AFTER the race is won must be closed on arrival, never wired in — otherwise
  // it mints a duplicate accept on the listener. Executed here so that branch (and its trace line)
  // is proven to run, not merely to exist.
  const late = mkLeg('udp6')
  composite.addLeg(Promise.resolve(late))
  await delay(0)
  assert.ok(late.closed, 'a late leg must be closed on arrival once the race is already won')
  composite.send(Buffer.from('after'))
  assert.equal(late.sent.length, 0, 'a late leg must never carry a frame')
  assert.equal(b.sent.length, 3, 'the winner keeps carrying frames after a late leg arrives')

  composite.close()
})
