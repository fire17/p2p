// test/transport-node-relay-only.test.js — the `--relay-only` / P2P_TRANSPORT=relay knob.
//
// WHY IT EXISTS: on 2026-09-13 a Debian VPS joined the Agent Tunnel three times and the link carried
// no data on at least one side, dying at ~70s on wire liveness. With the raced ladder there is no way
// to ask "was it the UDP leg?" — the dial silently picks whichever path answers. This knob makes the
// question askable: dial over the relay ALONE, deterministically, and see whether the link lives.
//
// What relay-only must mean, exactly (and what these legs assert):
//   • the UDP leg is NEVER punched — ep.udp._punch stays null, and the LISTENER's accept table never
//     sees a PROBE (a listener that accepted one would prove we dialed UDP after all);
//   • the committed leg is 'wss';
//   • the endpoint advertises NO udp candidates (we will not dial that way, so we do not invite it);
//   • a bad value or a missing relay FAILS LOUD — never a silent fall-back to the UDP dial, which is
//     the exact failure mode this knob exists to rule out;
//   • the default ('auto') path is untouched.
//
// Zero network: the relay is test/fixtures/mock-relay.mjs and UDP is loopback-only with explicit
// 127.0.0.1 candidates — this suite must never disturb a live tunnel on this machine.

import test from 'node:test'
import assert from 'node:assert/strict'
import { listen } from '../src/node.js'
import * as nodeTransport from '../src/transport-node.js'
import * as key from '../src/key.js'
import * as noise from '../src/noise.js'
import { mockRelay } from './fixtures/mock-relay.mjs'
import { parseArgs } from '../bin/p2p-tunnel.js'

const RELAYS = ['ws://mock-relay']
const delay = (ms) => new Promise((r) => setTimeout(r, ms))
const race = (p, ms, what) => Promise.race([p, delay(ms).then(() => { throw new Error('timed out: ' + what) })])
const crypto = () => ({
  generateIdentity: key.generateIdentity, decodeKey: key.decodeKey,
  verifyCommitment: key.verifyCommitment, encodeKey: key.encodeKey,
  initiator: noise.initiator, responder: noise.responder,
})

/**
 * A TUI peer on node.js's DEFAULT endpoint (UDP + WSS composed), relay pointed at the mock.
 * `punched` captures the COMPOSITE returned by ep.punch — that is how we read the committed leg
 * without depending on any other work item's getter.
 */
async function peer(relay, { resolve, transport, wssDelayMs = 700, relayGraceMs } = {}) {
  const id = await key.generateIdentity()
  let ep = null
  const punched = []
  const node = await listen(id, {
    transport,
    deps: {
      ...crypto(),
      createEndpoint: async (o) => {
        ep = await nodeTransport.createEndpoint({
          ...o, relays: RELAYS, WebSocket: relay.WebSocket, wssDelayMs,
          ...(relayGraceMs === undefined ? {} : { relayGraceMs }),
        })
        const realPunch = ep.punch.bind(ep)
        ep.punch = (c, p) => { const r = realPunch(c, p); r.then((s) => punched.push(s), () => {}); return r }
        return ep
      },
      resolve: async (S) => resolve(String(S)),
      publishAll: () => ({ stop() {} }),        // no mDNS / DHT / tracker — nothing announced
    },
  })
  const got = []
  node.on('message', (_p, m) => got.push(m.toString()))
  return { id, node, get ep() { return ep }, got, punched }
}

function listenerPeer(node, ms = 8000) {
  const liveP = node.peers().find((p) => p.connected)
  if (liveP) return Promise.resolve(liveP)
  return new Promise((res, rej) => {
    const t = setTimeout(() => rej(new Error('listener never established a peer')), ms)
    node.on('peer', (p) => { clearTimeout(t); res(p) })
  })
}

// ── (a) the knob does what it says ───────────────────────────────────────────────────────────────

test('relay-only: the dialer never punches UDP even with a live loopback candidate in hand', async () => {
  const relay = mockRelay({ hopMs: 15 })
  const eps = new Map()
  const resolve = (S) => {
    const e = eps.get(S)
    return e ? [{ proto: 'udp4', ip: '127.0.0.1', port: e.port4, kind: 'lan' }] : []
  }
  // The LISTENER is ordinary 'auto' and genuinely punchable on loopback — so if relay-only leaked a
  // UDP dial, UDP would WIN this race (it is ms against two broker hops plus a 700ms head start).
  const b = await peer(relay, { resolve })
  eps.set(b.id.S, b.ep)
  const a = await peer(relay, { resolve, transport: 'relay' })

  try {
    assert.equal(a.ep.transport, 'relay')
    assert.deepEqual(a.ep.candidates(), [], 'a relay-only endpoint advertises no UDP path')
    assert.ok(b.ep.candidates().length > 0, 'positive control: the auto listener DOES advertise UDP')

    const p = await race(a.node.connect(b.id.S), 12000, 'relay-only connect')
    const bSide = await race(listenerPeer(b.node), 8000, 'listener accept')
    await race(p.send('a2b over the relay'), 8000, 'a -> b')
    await race(bSide.send('b2a over the relay'), 8000, 'b -> a')
    await delay(80)

    assert.deepEqual(b.got, ['a2b over the relay'])
    assert.deepEqual(a.got, ['b2a over the relay'])
    assert.equal(a.ep.udp._punch, null, 'the UDP leg was never punched')
    assert.equal(b.ep.udp._accepted.size, 0, 'the listener never saw a UDP PROBE from the dialer')
    assert.equal(a.punched.length, 1, 'one dial => one composite')
    assert.equal(a.punched[0].winner && a.punched[0].winner.proto, 'wss', 'the committed leg is the relay')
    assert.ok(relay.published > 0, 'the relay actually carried this dial')
  } finally { a.node.close(); b.node.close(); relay.close() }
})

test('relay-only: a LATE udp candidate does not sneak the UDP leg back into the race', async () => {
  // The raced ladder deliberately re-enters a candidate discovery finds AFTER the punch (see
  // transport-node.js's late-candidate leg) — the one path that could punch UDP behind relay-only's
  // back. It only reaches udp.punch while the composite has NOT yet committed, so the relay here is
  // DEAD (every publish dropped): the wss leg comes up, never delivers a frame, and the late loopback
  // candidate lands with the race still open. Under 'auto' this is exactly the dial that succeeds
  // over UDP (test/interop-tui-web.test.js's late-candidate leg). Under relay-only it must NOT
  // connect at all — a relay-only dial that quietly completes over UDP is the failure this knob
  // exists to rule out, and it would be indistinguishable from a working relay.
  const relay = mockRelay({ hopMs: 15, drop: () => true })
  const b = await peer(relay, { resolve: () => [], relayGraceMs: 200 })
  const slow = (S) => (S === b.id.S
    ? (async function* () { await delay(300); yield { proto: 'udp4', ip: '127.0.0.1', port: b.ep.port4, kind: 'lan' } })()
    : [])
  const a = await peer(relay, { resolve: slow, transport: 'relay', relayGraceMs: 200 })
  try {
    await assert.rejects(() => race(a.node.connect(b.id.S), 3500, 'relay-only late-candidate connect'),
      /timed out/, 'relay-only must not complete a dial over the late UDP candidate')
    assert.equal(a.ep.udp._punch, null, 'the late udp candidate never punched')
    assert.equal(b.ep.udp._accepted.size, 0, 'the listener never saw a UDP PROBE')
    assert.deepEqual(b.got, [])
  } finally { a.node.close(); b.node.close(); relay.close() }
})

// ── the clean case: 'auto' is untouched (this is the assertion the knob must not break) ──────────

test('auto (default): UDP still wins on loopback and nothing is published to the relay', async () => {
  const relay = mockRelay({ hopMs: 15 })
  const eps = new Map()
  const resolve = (S) => {
    const e = eps.get(S)
    return e ? [{ proto: 'udp4', ip: '127.0.0.1', port: e.port4, kind: 'lan' }] : []
  }
  const b = await peer(relay, { resolve }); eps.set(b.id.S, b.ep)
  const a = await peer(relay, { resolve }); eps.set(a.id.S, a.ep)
  try {
    assert.equal(a.ep.transport, 'auto')
    const p = await race(a.node.connect(b.id.S), 12000, 'auto connect')
    const bSide = await race(listenerPeer(b.node), 8000, 'listener accept')
    await race(p.send('over udp'), 8000, 'a -> b')
    await race(bSide.send('over udp back'), 8000, 'b -> a')
    await delay(80)
    assert.deepEqual(b.got, ['over udp'])
    assert.deepEqual(a.got, ['over udp back'])
    assert.equal(a.punched[0].winner.proto, 'udp4', 'auto commits to the UDP leg')
    assert.equal(relay.published, 0, `auto published ${relay.published} frames to the relay (must be 0)`)
  } finally { a.node.close(); b.node.close(); relay.close() }
})

// ── (b) loud rejections ─────────────────────────────────────────────────────────────────────────

test('relay-only: a bad P2P_TRANSPORT value and a missing relay leg both reject LOUDLY', async () => {
  const relay = mockRelay()
  const id = await key.generateIdentity()
  await assert.rejects(
    () => nodeTransport.createEndpoint({ S: id.S, transport: 'bogus', relays: RELAYS, WebSocket: relay.WebSocket }),
    /P2P_TRANSPORT must be relay or auto \(got "bogus"\)/)
  // wss:false is invite mode / tui-only — relay-only there would silently be a UDP dial.
  await assert.rejects(
    () => nodeTransport.createEndpoint({ S: id.S, wss: false, transport: 'relay', relays: RELAYS, WebSocket: relay.WebSocket }),
    /relay-only needs the WSS relay/)
  await assert.rejects(
    () => nodeTransport.createEndpoint({ S: null, transport: 'relay', relays: RELAYS, WebSocket: relay.WebSocket }),
    /relay-only needs the WSS relay/)
  relay.close()
})

// ── (c) env plumbing, and opts winning over env ─────────────────────────────────────────────────

test('P2P_TRANSPORT: env selects the mode, an explicit opt overrides it, auto is unchanged', async () => {
  const relay = mockRelay()
  const id = await key.generateIdentity()
  const prev = process.env.P2P_TRANSPORT
  const made = []
  try {
    process.env.P2P_TRANSPORT = 'relay'
    const fromEnv = await nodeTransport.createEndpoint({ S: id.S, relays: RELAYS, WebSocket: relay.WebSocket })
    made.push(fromEnv)
    assert.equal(fromEnv.transport, 'relay', 'env alone selects relay-only')
    const optWins = await nodeTransport.createEndpoint({ S: id.S, transport: 'auto', relays: RELAYS, WebSocket: relay.WebSocket })
    made.push(optWins)
    assert.equal(optWins.transport, 'auto', 'an explicit opt beats the env')

    process.env.P2P_TRANSPORT = 'auto'
    const autoEnv = await nodeTransport.createEndpoint({ S: id.S, relays: RELAYS, WebSocket: relay.WebSocket })
    made.push(autoEnv)
    assert.equal(autoEnv.transport, 'auto')
    assert.ok(autoEnv.candidates().length > 0, 'P2P_TRANSPORT=auto advertises UDP exactly as before')

    process.env.P2P_TRANSPORT = 'bogus'
    await assert.rejects(() => nodeTransport.createEndpoint({ S: id.S, relays: RELAYS, WebSocket: relay.WebSocket }),
      /P2P_TRANSPORT must be relay or auto \(got "bogus"\)/)
  } finally {
    if (prev === undefined) delete process.env.P2P_TRANSPORT; else process.env.P2P_TRANSPORT = prev
    for (const e of made) { try { e.close() } catch { /* */ } }
    relay.close()
  }
})

// ── (e) the CLI flag parses ─────────────────────────────────────────────────────────────────────

test('parseArgs: --relay-only is a boolean flag; --relay-only=x is still an unknown flag', () => {
  assert.equal(parseArgs(['join', 'KEY', '--relay-only']).flags['relay-only'], true)
  assert.deepEqual(parseArgs(['join', 'KEY', '--relay-only']).pos, ['join', 'KEY'])
  assert.equal(parseArgs(['join', 'KEY']).flags['relay-only'], undefined)
  assert.throws(() => parseArgs(['join', 'KEY', '--relay-only=x']), /unknown flag: --relay-only=x/)
})
