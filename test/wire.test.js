// test/wire.test.js — deterministic ARQ tests for src/wire.js.
// Native node:test runner, zero deps. All randomness is a SEEDED PRNG (mulberry32) —
// no Math.random anywhere, so every run is byte-for-byte reproducible.

import test from 'node:test'
import assert from 'node:assert/strict'
import {
  createChannel, seqCmp, encodeFrame, decodeFrame, TYPE, HEADER_LEN,
} from '../src/wire.js'

/** Seeded PRNG — deterministic float in [0,1). */
function mulberry32(seed) {
  let a = seed >>> 0
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const CONNID = Buffer.from('0011223344556677', 'hex')
const idxBuf = (i) => { const b = Buffer.allocUnsafe(4); b.writeUInt32BE(i >>> 0); return b }

// ---------------------------------------------------------------------------
test('seqCmp is rollover-safe (RFC1982 serial arithmetic)', () => {
  assert.equal(seqCmp(5, 5), 0)
  assert.equal(seqCmp(6, 5), 1)
  assert.equal(seqCmp(5, 6), -1)
  // wraparound: 0 is "just after" 0xFFFFFFFF
  assert.equal(seqCmp(0, 0xffffffff), 1)
  assert.equal(seqCmp(0xffffffff, 0), -1)
  assert.equal(seqCmp(2, 0xfffffffe), 1)          // 2 is after (max-1) across the wrap
  assert.equal(seqCmp(0xfffffffe, 2), -1)
})

test('encodeFrame / decodeFrame round-trip', () => {
  const payload = Buffer.from('opaque-aead-frame')
  const f = decodeFrame(encodeFrame(TYPE.DATA, CONNID, 0x01020304, 0x0a0b0c0d, payload))
  assert.equal(f.type, TYPE.DATA)
  assert.ok(f.connId.equals(CONNID))
  assert.equal(f.seq, 0x01020304)
  assert.equal(f.ack, 0x0a0b0c0d)
  assert.ok(f.payload.equals(payload))
  assert.equal(decodeFrame(Buffer.alloc(HEADER_LEN - 1)), null)   // runt -> null
})

// ---------------------------------------------------------------------------
// Lossy / reordering / duplicating in-memory pipe over a virtual clock.
function makeNet(rng, cfg) {
  const q = []                                     // {dueAt, buf, deliver}
  const link = (deliver) => (buf) => {
    if (rng() < cfg.loss) return                   // drop
    const copy = Buffer.from(buf)
    q.push({ dueAt: cfg.T() + Math.floor(rng() * cfg.maxDelay), buf: copy, deliver })
    if (rng() < cfg.dupProb) {                      // duplicate with independent delay
      q.push({ dueAt: cfg.T() + Math.floor(rng() * cfg.maxDelay), buf: copy, deliver })
    }
  }
  const flush = (T) => {
    const due = q.filter((e) => e.dueAt <= T)
    if (!due.length) return
    const keep = q.filter((e) => e.dueAt > T)
    q.length = 0; q.push(...keep)
    for (const e of due) e.deliver(e.buf)          // insertion order among due => reorder
  }
  return { link, flush, size: () => q.length }
}

test('1000 msgs each way under 20% loss + reorder + dup arrive exactly-once in-order', () => {
  let T = 0
  const rng = mulberry32(0xc0ffee)
  const cfg = { loss: 0.2, maxDelay: 18, dupProb: 0.1, T: () => T }
  const net = makeNet(rng, cfg)

  const rinfoA = { address: '10.0.0.1', port: 4001, family: 'IPv4' }
  const rinfoB = { address: '10.0.0.2', port: 4002, family: 'IPv4' }

  let chA, chB
  const optsCommon = {
    connId: CONNID, mtu: 1200, window: 256,
    rtoMin: 15, rtoMax: 300, keepaliveMs: 1e12, now: () => T,
  }
  chA = createChannel({ ...optsCommon, send: net.link((buf) => chB.onDatagram(buf, rinfoA)) })
  chB = createChannel({ ...optsCommon, send: net.link((buf) => chA.onDatagram(buf, rinfoB)) })

  const aRecv = [], bRecv = []
  chA.onReliable((b) => aRecv.push(b.readUInt32BE(0)))
  chB.onReliable((b) => bRecv.push(b.readUInt32BE(0)))

  const N = 1000
  for (let i = 0; i < N; i++) { chA.sendReliable(idxBuf(i)); chB.sendReliable(idxBuf(i)) }

  let iter = 0
  const MAX = 300000
  const pending = () =>
    aRecv.length < N || bRecv.length < N || chA.stats().inflight > 0 || chB.stats().inflight > 0
  while (pending() && iter++ < MAX) {              // settle acks too, not just delivery
    T += 5
    net.flush(T)
    chA.tick(T); chB.tick(T)
  }

  assert.equal(aRecv.length, N, `A got ${aRecv.length}/${N}`)
  assert.equal(bRecv.length, N, `B got ${bRecv.length}/${N}`)
  for (let i = 0; i < N; i++) {
    assert.equal(aRecv[i], i, `A out-of-order/dup at ${i}: ${aRecv[i]}`)
    assert.equal(bRecv[i], i, `B out-of-order/dup at ${i}: ${bRecv[i]}`)
  }
  // resends actually happened (loss was real), and no unacked data left behind.
  assert.ok(chA.stats().resends > 0 && chB.stats().resends > 0)
  assert.equal(chA.stats().inflight, 0)
  assert.equal(chB.stats().inflight, 0)
})

test('connId roaming mid-stream: peer IP change keeps delivery flowing (D9)', () => {
  let T = 0
  const rng = mulberry32(42)
  const cfg = { loss: 0.05, maxDelay: 10, dupProb: 0, T: () => T }
  const net = makeNet(rng, cfg)

  let chA, chB
  const opts = { connId: CONNID, rtoMin: 15, rtoMax: 300, keepaliveMs: 1e12, now: () => T }

  // B's datagrams to A start from one address, then migrate mid-stream.
  let bAddr = { address: '198.51.100.7', port: 5000, family: 'IPv4' }
  const roams = []
  chA = createChannel({ ...opts, send: net.link((buf) => chB.onDatagram(buf, { address: '203.0.113.9', port: 6000, family: 'IPv4' })) })
  chB = createChannel({ ...opts, send: net.link((buf) => chA.onDatagram(buf, bAddr)) })
  chA.onRoam((r) => roams.push(r.address))

  const aRecv = []
  chA.onReliable((b) => aRecv.push(b.readUInt32BE(0)))

  const drive = (untilLen, cap) => {
    let iter = 0
    while (aRecv.length < untilLen && iter++ < cap) { T += 5; net.flush(T); chA.tick(T); chB.tick(T) }
  }

  // First half arrives from the original address.
  for (let i = 0; i < 100; i++) chB.sendReliable(idxBuf(i))
  drive(100, 50000)
  assert.ok(aRecv.length >= 100, `pre-roam delivered ${aRecv.length}`)
  assert.equal(chA.peerRinfo.address, '198.51.100.7')

  // Peer migrates to a new ip:port mid-stream; second half must still flow.
  bAddr = { address: '192.0.2.222', port: 7777, family: 'IPv4' }
  for (let i = 100; i < 200; i++) chB.sendReliable(idxBuf(i))
  drive(200, 100000)

  assert.equal(aRecv.length, 200, `A got ${aRecv.length}/200 after roam`)
  for (let i = 0; i < 200; i++) assert.equal(aRecv[i], i)   // still exactly-once in-order
  assert.equal(chA.peerRinfo.address, '192.0.2.222')        // followed the migration
  assert.ok(roams.includes('192.0.2.222'), 'onRoam fired for new address')
})

test('keepalive PING emitted from tick after idle interval', () => {
  let T = 0
  const frames = []
  const ch = createChannel({
    connId: CONNID, keepaliveMs: 1000, now: () => T,
    send: (buf) => frames.push(decodeFrame(buf)),
  })
  ch.tick(T)                                        // fresh -> no ping
  assert.equal(frames.filter((f) => f.type === TYPE.PING).length, 0)
  T = 1000
  ch.tick(T)                                        // idle >= keepaliveMs -> ping
  assert.equal(frames.filter((f) => f.type === TYPE.PING).length, 1)
  T = 1500
  ch.tick(T)                                        // not yet idle again since last send
  assert.equal(frames.filter((f) => f.type === TYPE.PING).length, 1)
  T = 2500
  ch.tick(T)                                        // idle again -> second ping
  assert.equal(frames.filter((f) => f.type === TYPE.PING).length, 2)
})

test('liveness: channel dies after livenessMs of inbound silence; a frame resets it', () => {
  let T = 0
  const closes = []
  const ch = createChannel({ connId: CONNID, now: () => T, keepaliveMs: 100, livenessMs: 300, send: () => {} })
  ch.onClose((why) => closes.push(why))
  ch.onDatagram(encodeFrame(TYPE.PING, CONNID, 0, 0, null), {})   // inbound at T=0 sets lastRecvAt
  T = 250; ch.tick(T); assert.equal(closes.length, 0, 'within livenessMs -> alive')
  ch.onDatagram(encodeFrame(TYPE.PONG, CONNID, 0, 0, null), {})   // fresh inbound at 250 resets liveness
  T = 500; ch.tick(T); assert.equal(closes.length, 0, 'reset kept it alive (500-250 < 300)')
  T = 560; ch.tick(T); assert.deepEqual(closes, ['timeout'], 'silence 250->560 = 310 >= 300 -> dead')
  assert.equal(ch.closed, true)
})

test('PING is answered with PONG', () => {
  let T = 0
  const frames = []
  const ch = createChannel({ connId: CONNID, now: () => T, send: (buf) => frames.push(decodeFrame(buf)) })
  const ping = encodeFrame(TYPE.PING, CONNID, 0, 0, null)
  ch.onDatagram(ping, { address: '1.2.3.4', port: 9 })
  assert.equal(frames.filter((f) => f.type === TYPE.PONG).length, 1)
})

test('exactly-once under pure duplication (no loss)', () => {
  let T = 0
  let chA, chB
  const dup = (deliver) => (buf) => { deliver(Buffer.from(buf)); deliver(Buffer.from(buf)) } // every frame twice
  chA = createChannel({ connId: CONNID, now: () => T, send: dup((b) => chB.onDatagram(b, {})) })
  chB = createChannel({ connId: CONNID, now: () => T, send: dup((b) => chA.onDatagram(b, {})) })
  const got = []
  chB.onReliable((b) => got.push(b.readUInt32BE(0)))
  for (let i = 0; i < 50; i++) chA.sendReliable(idxBuf(i))
  for (let k = 0; k < 20; k++) { T += 20; chA.tick(T); chB.tick(T) }
  assert.deepEqual(got, Array.from({ length: 50 }, (_, i) => i))  // no duplicates delivered
})

test('CLOSE shuts both ends', () => {
  let T = 0
  let chA, chB
  chA = createChannel({ connId: CONNID, now: () => T, send: (b) => chB.onDatagram(Buffer.from(b), {}) })
  chB = createChannel({ connId: CONNID, now: () => T, send: (b) => chA.onDatagram(Buffer.from(b), {}) })
  let bClosedReason = null
  chB.onClose((why) => { bClosedReason = why })
  chA.close()
  assert.equal(chA.closed, true)
  assert.equal(chB.closed, true)
  assert.equal(bClosedReason, 'peer')
  assert.throws(() => chA.sendReliable(idxBuf(0)), /closed/)
})

test('foreign connId datagrams are ignored', () => {
  let T = 0
  const got = []
  const ch = createChannel({ connId: CONNID, now: () => T, send: () => {} })
  ch.onReliable((b) => got.push(b))
  const wrong = encodeFrame(TYPE.DATA, Buffer.alloc(8, 0xaa), 0, 0, idxBuf(1))
  ch.onDatagram(wrong, {})
  assert.equal(got.length, 0)
})

test('backpressure: sends past window queue, then drain (stats reflect it)', () => {
  let T = 0
  // Black-hole send (no peer -> no acks) so the window fills and excess queues.
  const sink = []
  const chA = createChannel({ connId: CONNID, window: 8, rtoMin: 1e9, now: () => T, send: (b) => sink.push(b) })
  for (let i = 0; i < 40; i++) chA.sendReliable(idxBuf(i))
  assert.equal(chA.stats().inflight, 8, 'window cap respected')
  assert.equal(chA.stats().queued, 32, 'excess queued behind the window')
  assert.equal(sink.length, 8, 'only window worth actually put on the wire')

  // Now drain by feeding cumulative acks from a real peer, verifying in-order delivery.
  let T2 = 0
  let a, b
  a = createChannel({ connId: CONNID, window: 8, rtoMin: 15, now: () => T2, send: (x) => b.onDatagram(Buffer.from(x), {}) })
  b = createChannel({ connId: CONNID, window: 8, rtoMin: 15, now: () => T2, send: (x) => a.onDatagram(Buffer.from(x), {}) })
  const got = []
  b.onReliable((x) => got.push(x.readUInt32BE(0)))
  for (let i = 0; i < 40; i++) a.sendReliable(idxBuf(i))
  for (let k = 0; k < 30; k++) { T2 += 20; a.tick(T2); b.tick(T2) }
  assert.deepEqual(got, Array.from({ length: 40 }, (_, i) => i))
  assert.equal(a.stats().inflight, 0)
  assert.equal(a.stats().queued, 0)
})
