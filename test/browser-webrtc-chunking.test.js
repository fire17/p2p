// test/browser-webrtc-chunking.test.js — DataChannel frames are chunked to ≤16 KiB and reassembled
// byte-exact. A reliable+ordered channel has no spec cap, but the cross-browser safe per-message size
// is ~16 KiB (Chromium closes the channel above ~256 KiB) — so socketFromChannel splits and rebuilds.
// Symmetric: both peers run this module, so the framing is understood on both ends. Deterministic —
// a fake DataChannel pair, no browser.

import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { socketFromChannel } from '../src/browser/webrtc.js'

/** A pair of fake RTCDataChannels wired to each other: a.send(x) → b.onmessage({data:x}). */
function channelPair() {
  const mk = () => ({ binaryType: '', readyState: 'open', onmessage: null, onclose: null, send() {}, close() {} })
  const a = mk()
  const b = mk()
  a.send = (msg) => b.onmessage && b.onmessage({ data: msg.buffer.slice(msg.byteOffset, msg.byteOffset + msg.byteLength) })
  b.send = (msg) => a.onmessage && a.onmessage({ data: msg.buffer.slice(msg.byteOffset, msg.byteOffset + msg.byteLength) })
  return [a, b]
}
const fakePc = () => ({ close() {} })

function roundTrip(bytes) {
  const [dcA, dcB] = channelPair()
  const A = socketFromChannel(dcA, fakePc())
  const B = socketFromChannel(dcB, fakePc())
  const got = []
  B.onMessage = (buf) => got.push(buf)
  A.send(bytes)
  return got
}

test('small frame (< 16 KiB) round-trips in one message, byte-exact', () => {
  const msg = Buffer.from('the first ack is the MITM proof')
  const got = roundTrip(msg)
  assert.equal(got.length, 1, 'one message')
  assert.equal(got[0].toString(), msg.toString())
})

test('large frame (> 16 KiB) is chunked and reassembled byte-exact', () => {
  const big = randomBytes(100_000) // ~7 chunks
  const got = roundTrip(big)
  assert.equal(got.length, 1, 'reassembled into exactly one delivered frame')
  assert.equal(Buffer.compare(got[0], big), 0, 'reassembled bytes must equal the original')
})

test('boundary sizes round-trip exactly (15992, 15993, 32000, empty)', () => {
  for (const n of [0, 15992, 15993, 31984, 32000, 250_000]) {
    const buf = randomBytes(n)
    const got = roundTrip(buf)
    assert.equal(got.length, 1, `n=${n}: one delivered frame`)
    assert.equal(Buffer.compare(got[0], buf), 0, `n=${n}: byte-exact`)
  }
})

test('each DataChannel message stays within the 16 KiB cross-browser limit', () => {
  const [dcA, dcB] = channelPair()
  const sizes = []
  const realSend = dcA.send
  dcA.send = (msg) => { sizes.push(msg.byteLength); realSend(msg) }
  const A = socketFromChannel(dcA, fakePc())
  const B = socketFromChannel(dcB, fakePc())
  B.onMessage = () => {}
  A.send(randomBytes(200_000))
  assert.ok(sizes.length > 1, 'a 200KB frame must be split into multiple messages')
  for (const s of sizes) assert.ok(s <= 16000, `every DataChannel message ≤16000B, saw ${s}`)
})

test('reassembly normalizes both ArrayBuffer (browser) and Buffer (werift) dc.onmessage payloads', () => {
  // werift hands dc.onmessage a Node Buffer; browsers hand an ArrayBuffer. The merged module runs
  // under BOTH, so socketFromChannel must accept either. Drive the receiver with each shape.
  const big = randomBytes(50_000)
  for (const shape of ['arraybuffer', 'buffer']) {
    const [dcA, dcB] = channelPair()
    // re-wire A→B to hand B the chosen shape
    dcA.send = (msg) => {
      const copy = msg.slice() // own bytes
      const data = shape === 'buffer' ? Buffer.from(copy) : copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength)
      dcB.onmessage && dcB.onmessage({ data })
    }
    const A = socketFromChannel(dcA, fakePc())
    const B = socketFromChannel(dcB, fakePc())
    const got = []
    B.onMessage = (buf) => got.push(buf)
    A.send(big)
    assert.equal(got.length, 1, `${shape}: one reassembled frame`)
    assert.equal(Buffer.compare(got[0], big), 0, `${shape}: byte-exact reassembly`)
  }
})

test('a runt (< header) is dropped, not delivered', () => {
  const [dcA, dcB] = channelPair()
  const B = socketFromChannel(dcB, fakePc())
  let delivered = 0
  B.onMessage = () => delivered++
  dcB.onmessage({ data: new Uint8Array(3).buffer }) // shorter than the 8-byte header
  assert.equal(delivered, 0, 'a sub-header runt must be dropped')
})
