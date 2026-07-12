// test/transport-wss-dos.test.js — DOS-1-WSS accept-path exhaustion guards.
//
// The WSS relay is a GUARANTEED on-path attacker: it can inject unlimited PUBLISHes carrying fresh
// attacker-chosen 16-byte senderIds, each of which (pre-fix) minted a socketLike + fired onConnection
// (→ a node peer-record) with NO cap, NO eviction, NO rate limit. This drives the endpoint at the
// MQTT layer (a fake WS speaking raw MQTT packets) and asserts the accept path is bounded:
//   • rate-limit  — a burst of distinct senders admits only ~burst, not all of them;
//   • cap+evict   — a sustained flood keeps `accepted` within maxAccepted (stalest evicted);
//   • idle-evict  — silent accepts are swept out after the idle window;
//   • dials leak  — a completed dial is removed from `dials` on close (LOW sibling).
//
// Deterministic: injected clock + a fake MQTT WebSocket. No network, no real broker.

import test from 'node:test'
import assert from 'node:assert/strict'
import { createEndpoint } from '../src/transport-wss.js'

const delay = (ms) => new Promise((r) => setTimeout(r, ms))

// ── minimal MQTT packet builders (mirror the module's own wire format) ────────────────────────
const remlen = (n) => { const o = []; do { let b = n % 128; n = (n / 128) | 0; if (n > 0) b |= 0x80; o.push(b) } while (n > 0); return o }
const mstr = (s) => { const b = Buffer.from(s); return [b.length >> 8, b.length & 255, ...b] }
const mqtt = (type, flags, body) => Uint8Array.from([(type << 4) | flags, ...remlen(body.length), ...body])
const CONNACK = mqtt(2, 0, [0, 0])
const SUBACK = mqtt(9, 0, [0, 1, 0])
const publishPkt = (topic, payload) => mqtt(3, 0, [...mstr(topic), ...payload])

/** A p2p WSS envelope [1B ver][16B senderId][8B msgId][>=1B frame] with distinct sender + msgId. */
function envelope(senderIdx, msgIdx) {
  const e = new Uint8Array(26)
  const dv = new DataView(e.buffer)
  e[0] = 1                    // VER
  dv.setUint32(1, senderIdx)  // 4 of the 16 sender bytes → distinct sender key
  dv.setUint32(17, msgIdx)    // 4 of the 8 msgId bytes → distinct dedup key
  return e                    // e[25] is the (1-byte) frame
}

/** Fake MQTT WebSocket: fires onopen next tick, ignores writes, lets the test push inbound packets. */
function makeFakeWS(reg) {
  return class FakeWS {
    constructor(url) {
      this.url = url; this.binaryType = ''
      this.onopen = this.onmessage = this.onclose = this.onerror = null
      reg.sockets.push(this)
      setTimeout(() => { this.onopen && this.onopen() }, 0)
    }
    send() { /* CONNECT / SUBSCRIBE / PING — ignored */ }
    close() { this.onclose && this.onclose() }
    deliver(bytes) { this.onmessage && this.onmessage({ data: bytes }) }
  }
}

test('DOS-1-WSS rate-limit: a burst of distinct attacker senderIds admits only ~burst, not all', async () => {
  const reg = { sockets: [] }
  let onConnCount = 0
  const ep = createEndpoint({
    relays: ['ws://r'], WebSocket: makeFakeWS(reg), now: () => 1_000_000, // fixed clock → no token refill
    maxAccepted: 100000, acceptRate: 20, acceptBurst: 40, idleSweepMs: 100000,
  })
  ep.onConnection(() => onConnCount++)
  await delay(5)
  const ws = reg.sockets[0]
  ws.deliver(CONNACK)

  for (let i = 1; i <= 1000; i++) ws.deliver(publishPkt('p2p1/t', envelope(i, i)))

  assert.equal(onConnCount, 40, `only the burst budget is admitted (onConnection fired ${onConnCount}× of 1000)`)
  assert.equal(ep._debug.acceptedCount(), 40, `accepted set holds only the admitted (${ep._debug.acceptedCount()})`)
  ep.close()
})

test('DOS-1-WSS cap+evict: a sustained flood keeps `accepted` within maxAccepted', async () => {
  const reg = { sockets: [] }
  let onConnCount = 0
  const ep = createEndpoint({
    relays: ['ws://r'], WebSocket: makeFakeWS(reg), now: () => 1_000_000,
    maxAccepted: 50, acceptRate: 1e9, acceptBurst: 1e9, idleSweepMs: 100000, // rate wide open → test the CAP
  })
  ep.onConnection(() => onConnCount++)
  await delay(5)
  const ws = reg.sockets[0]
  ws.deliver(CONNACK)

  for (let i = 1; i <= 1000; i++) ws.deliver(publishPkt('p2p1/t', envelope(i, i)))

  assert.ok(onConnCount > 100, `the flood was admitted at the transport (fired ${onConnCount}×)`)
  assert.ok(ep._debug.acceptedCount() <= 50, `accepted map stays within the cap (saw ${ep._debug.acceptedCount()})`)
  ep.close()
})

test('DOS-1-WSS idle-evict: silent accepts are swept out after the idle window', async () => {
  const reg = { sockets: [] }
  let clock = 1_000_000
  const ep = createEndpoint({
    relays: ['ws://r'], WebSocket: makeFakeWS(reg), now: () => clock,
    maxAccepted: 100, acceptRate: 1e9, acceptBurst: 1e9, acceptIdleMs: 5000, idleSweepMs: 25,
  })
  ep.onConnection(() => {})
  await delay(5)
  const ws = reg.sockets[0]
  ws.deliver(CONNACK)

  for (let i = 1; i <= 5; i++) ws.deliver(publishPkt('p2p1/t', envelope(i, i)))
  assert.equal(ep._debug.acceptedCount(), 5, 'five inbound peers tracked')

  clock += 6000 // advance past the idle window
  await delay(60) // let the sweep interval fire
  assert.equal(ep._debug.acceptedCount(), 0, 'idle accepts are evicted by the sweep')
  ep.close()
})

test('DOS-1-WSS: a completed dial is removed from `dials` on close (no self-leak)', async () => {
  const reg = { sockets: [] }
  const ep = createEndpoint({ relays: ['ws://r'], WebSocket: makeFakeWS(reg), now: () => 1_000_000 })
  await delay(5)
  const ws = reg.sockets[0]
  ws.deliver(CONNACK)

  const dialP = ep.punch([{ proto: 'wss', topic: 'p2p1/peertopic' }])
  await delay(5)
  ws.deliver(SUBACK) // let the dial's subscribe resolve so punch returns promptly
  const sock = await dialP
  assert.equal(ep._debug.dialsCount(), 1, 'the live dial is tracked')

  sock.close()
  assert.equal(ep._debug.dialsCount(), 0, 'closing the dial removes it from `dials`')
  ep.close()
})
