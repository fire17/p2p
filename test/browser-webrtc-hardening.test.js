// test/browser-webrtc-hardening.test.js — leak/exhaustion guards for the browser WebRTC transport.
//
//  • BRW-4 / BRW-4b (HIGH, live in v0.2.0): the listener minted fresh RTCPeerConnections every
//    announce. a84345e capped how many sat PARKED, but a REAL browser caps CUMULATIVE constructions
//    (~500/page, non-reclaimable) — so bounding the parked set was not enough; the CONSTRUCTION RATE
//    itself sank a long-lived tab (test/browser-pc-soak.mjs proves it in real Chromium). The fix holds
//    a small REUSED pool and re-publishes the SAME offers, so constructions track connections, not
//    time. This SOAK drives many announce cycles with fake PCs that NEVER open and asserts the
//    cumulative-construction count stays ~the pool size (NOT ~ the number of cycles). Plus: an
//    answered offer STILL connects (path intact).
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

test('BRW-4b soak: a long-lived listener does NOT churn RTCPeerConnections (constructions ~ pool size, not ~ cycles)', async () => {
  const reg = { created: 0, closed: 0, pcs: new Set(), channels: [], sent: [], sockets: [] }
  const t = createBrowserTransport({
    trackers: ['ws://t1', 'ws://t2', 'ws://t3'], // 3 trackers, like the shipped TRACKERS
    RTCPeerConnection: makeFakePC(reg),
    WebSocket: makeFakeWS(reg),
    now: () => FIXED,
    announceIntervalMs: 5, // very fast cadence: MANY announce cycles in the soak window
    offerRefreshMs: 20, // re-offer often (on the SAME pc — must NOT construct new PCs)
    maxPendingOffers: 8, // hard cap
    targetParkedOffers: 6, // pool size
    pcCreateBurst: 20, // enough tokens to fill the pool at once
    pcCreatesPerMin: 6,
  })
  await t.createEndpoint()
  t.endpoint.onConnection(() => {})
  const handle = t.publishAll(S26)

  await delay(400)
  const created1 = reg.created, pend1 = handle.pendingCount(), live1 = t._debug.liveCount()
  await delay(400)
  const created2 = reg.created, pend2 = handle.pendingCount(), live2 = t._debug.liveCount()
  const announces = reg.sent.filter((m) => m.offers && m.offers.length).length
  handle.stop()
  t.close()

  // THE POINT (BRW-4b): the soak drove MANY announce cycles across 3 trackers…
  assert.ok(announces > 60, `soak drove many announce cycles (published ${announces} offer-announces)`)
  // …yet the CUMULATIVE construction count barely moved — constructions track the pool, not the clock.
  // (OLD code would have constructed ~4 × 3 × cycles ≈ hundreds; the reuse pool constructs ~6.)
  assert.ok(created2 <= 12, `cumulative RTCPeerConnection constructions stay ~pool-size, NOT ~cycles (saw ${created2} over ${announces} announces)`)
  assert.equal(created1, created2, `no new PCs are constructed during steady-state re-offering (was ${created1}, now ${created2})`)
  assert.ok(pend1 <= 8 && pend2 <= 8, `parked offers stay within the cap (saw ${pend1}, ${pend2})`)
  assert.ok(live2 <= 12, `live RTCPeerConnections stay BOUNDED and constant (saw ${live2})`)
  // teardown frees everything
  assert.equal(t._debug.liveCount(), 0, 'stop()+close() frees every RTCPeerConnection')
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
