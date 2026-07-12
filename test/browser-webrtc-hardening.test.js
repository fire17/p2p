// test/browser-webrtc-hardening.test.js — leak/exhaustion guards for the browser WebRTC transport.
//
//  • BRW-4 (HIGH, live in v0.2.0): the listener parked one RTCPeerConnection per announced offer and
//    freed it ONLY on dc.onopen or node.close() — so unanswered offers accumulated (~12 PCs/10s) and
//    a long-lived listener exhausted the browser. The fix TTL-reaps and caps parked offers. This is a
//    SOAK: drive many announce cycles with fake PCs that NEVER open, assert the live/parked count
//    stays bounded (not ~ the number created). Plus: an answered offer STILL connects (path intact).
//  • BRW-5 (MED): the chunk-reassembly buffer was keyed by a sender-chosen msgId and never bounded —
//    endless distinct partial-chunk starts exhaust memory pre-Noise. The fix caps concurrent partials
//    and total buffered bytes; assert a flood stays bounded and delivers nothing.
//
// Deterministic: fake RTCPeerConnection + fake WebSocket + injected clock. No browser, no network.

import test from 'node:test'
import assert from 'node:assert/strict'
import { createBrowserTransport, socketFromChannel } from '../src/browser/webrtc.js'

const FIXED = Date.UTC(2026, 0, 1, 12, 0, 0) // midday → one announce epoch (deterministic)
const S26 = 'S'.repeat(26)
const delay = (ms) => new Promise((r) => setTimeout(r, ms))

/** Fake RTCPeerConnection: offers/answers resolve instantly, ICE is "complete", dc never opens itself. */
function makeFakePC(reg) {
  return class FakePC {
    constructor() {
      this.iceGatheringState = 'complete'
      this.localDescription = { sdp: 'sdp' }
      this.closed = false
      this.ondatachannel = null
      reg.created++
      reg.pcs.add(this)
    }
    createDataChannel() {
      const dc = { onopen: null, onclose: null, onmessage: null, readyState: 'connecting', binaryType: '', send() {}, close() {} }
      reg.channels.push({ pc: this, dc })
      return dc
    }
    async createOffer() { return { type: 'offer', sdp: 'sdp' } }
    async createAnswer() { return { type: 'answer', sdp: 'sdp' } }
    async setLocalDescription() {}
    async setRemoteDescription() {}
    addEventListener() {}
    removeEventListener() {}
    close() { if (this.closed) return; this.closed = true; reg.closed++; reg.pcs.delete(this) }
  }
}

/** Fake WebSocket: fires onopen next tick, records sent JSON, can inject inbound tracker messages. */
function makeFakeWS(reg) {
  return class FakeWS {
    constructor(url) {
      this.url = url; this.readyState = 0
      this.onopen = this.onmessage = this.onclose = this.onerror = null
      reg.sockets.push(this)
      setTimeout(() => { this.readyState = 1; this.onopen && this.onopen(this) }, 0)
    }
    send(str) { try { reg.sent.push(JSON.parse(str)) } catch { /* */ } }
    close() { this.readyState = 3; this.onclose && this.onclose() }
    inject(obj) { this.onmessage && this.onmessage({ data: JSON.stringify(obj) }) }
  }
}

test('BRW-4 soak: a long-lived listener does NOT leak RTCPeerConnections (parked offers stay bounded)', async () => {
  const reg = { created: 0, closed: 0, pcs: new Set(), channels: [], sent: [], sockets: [] }
  const t = createBrowserTransport({
    trackers: ['ws://t1'],
    RTCPeerConnection: makeFakePC(reg),
    WebSocket: makeFakeWS(reg),
    now: () => FIXED,
    announceIntervalMs: 10, // fast cadence: many cycles in the soak window
    offerTtlMs: 30, // short park-TTL so reaping is observable
    maxPendingOffers: 8, // hard cap
  })
  await t.createEndpoint()
  t.endpoint.onConnection(() => {})
  const handle = t.publishAll(S26)

  await delay(400)
  const live1 = t._debug.liveCount(), pend1 = handle.pendingCount()
  await delay(300)
  const live2 = t._debug.liveCount(), pend2 = handle.pendingCount()
  handle.stop()
  t.close()

  // OLD code: `created` PCs would ALL stay live. The soak ran enough cycles that created ≫ any bound.
  assert.ok(reg.created > 60, `soak drove many announce cycles (created ${reg.created})`)
  assert.ok(pend1 <= 8 && pend2 <= 8, `parked offers stay within the cap (saw ${pend1}, ${pend2})`)
  assert.ok(live2 <= 20, `live RTCPeerConnections stay BOUNDED — not ~${reg.created} (saw ${live2})`)
  assert.ok(reg.closed >= reg.created - 20, `evicted offers are actually closed (created ${reg.created}, closed ${reg.closed})`)
  // teardown frees everything
  assert.equal(t._debug.liveCount(), 0, 'close() frees every RTCPeerConnection')
})

test('BRW-4: an answer within the window STILL connects — the real accept path is not broken', async () => {
  const reg = { created: 0, closed: 0, pcs: new Set(), channels: [], sent: [], sockets: [] }
  const t = createBrowserTransport({
    trackers: ['ws://t1'],
    RTCPeerConnection: makeFakePC(reg),
    WebSocket: makeFakeWS(reg),
    now: () => FIXED,
    announceIntervalMs: 100000, // only the initial announce fires in-window
    offerTtlMs: 2000,
    maxPendingOffers: 8,
  })
  await t.createEndpoint()
  let connected = 0
  t.endpoint.onConnection(() => connected++)
  const handle = t.publishAll(S26)

  await delay(20) // onopen → announce → 4 offers park
  const ann = reg.sent.find((m) => m.offers && m.offers.length)
  assert.ok(ann, 'the listener parked offers')
  const offerId = ann.offers[0].offer_id
  const ws = reg.sockets[0]

  // A dialer answers offer 0.
  ws.inject({ answer: { type: 'answer', sdp: 'sdp' }, offer_id: offerId, peer_id: 'dialer' })
  await delay(5)
  // ICE then "connects" → the DataChannel opens.
  const ch = reg.channels[0]
  ch.dc.readyState = 'open'
  ch.dc.onopen && ch.dc.onopen()

  assert.equal(connected, 1, 'the answered offer was promoted to a live connection')
  assert.equal(ch.pc.closed, false, 'the connected pc is NOT reaped')
  handle.stop()
  t.close()
})

test('BRW-5: reassembly is bounded — a flood of distinct partial-chunk starts cannot exhaust memory', () => {
  const dc = { binaryType: '', readyState: 'open', onmessage: null, onclose: null, send() {}, close() {} }
  const sock = socketFromChannel(dc, { close() {} })
  let delivered = 0
  sock.onMessage = () => delivered++

  // Each message declares total=2 (stays incomplete after chunk 0), a DISTINCT msgId, ~15 KB payload.
  const CHUNK = 15000
  for (let id = 1; id <= 5000; id++) {
    const msg = new Uint8Array(8 + CHUNK)
    const dv = new DataView(msg.buffer)
    dv.setUint32(0, id)   // msgId
    dv.setUint16(4, 0)    // index 0
    dv.setUint16(6, 2)    // of 2 → never completes
    dc.onmessage({ data: msg.buffer })
  }

  assert.equal(delivered, 0, 'no partial message ever completes')
  assert.ok(sock._debug.reasmCount() <= 256, `concurrent partials capped (saw ${sock._debug.reasmCount()})`)
  assert.ok(sock._debug.reasmBytes() <= 8 * 1024 * 1024, `buffered bytes capped ≤8 MiB (saw ${sock._debug.reasmBytes()})`)

  // The socket is not wedged: a fresh complete (single-chunk) message still delivers.
  const one = new Uint8Array(8 + 5)
  new DataView(one.buffer).setUint16(6, 1) // total=1 → fast path
  one.set(Buffer.from('hello'), 8)
  dc.onmessage({ data: one.buffer })
  assert.equal(delivered, 1, 'a complete message still delivers after the flood (cap did not wedge the socket)')
})
