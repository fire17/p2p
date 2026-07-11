// src/wire.js — transport-agnostic framing + reliability channel for p2p (v1).
//
// Frame: [1B type][8B connId][4B seq][4B ack][payload]. Types below. DATA payloads are
// OPAQUE (an AEAD frame from noise split states) — NO crypto happens here.
//
// Provides: sliding-window ARQ (ordered, exactly-once via seq dedup), cumulative ack
// (piggybacked + standalone ACK), RTT-adaptive resend (RFC6298 srtt/rttvar + Karn +
// exponential backoff), PING/PONG keepalive emitted from tick(), QUIC-style connId
// roaming (D9 — accept any rinfo carrying my connId), CLOSE, backpressure via stats().
//
// Zero deps, ESM. No Math.random / no Date.now in the hot path — all time comes from the
// injected `now` clock, so callers/tests stay deterministic. connId (if not supplied) is
// drawn from node:crypto randomBytes, which is fine (not a determinism concern).
//
// Contract: docs/INTERFACES.md §src/wire.js. Semantics: DESIGN.md D8/D9.

import { randomBytes } from 'node:crypto'

/** @enum {number} Frame type tags (order per DESIGN/INTERFACES). */
export const TYPE = Object.freeze({
  HELLO: 0, HS1: 1, HS2: 2, DATA: 3, ACK: 4, PING: 5, PONG: 6, CLOSE: 7,
})
const TYPE_NAME = Object.freeze(
  Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k])),
)

export const HEADER_LEN = 17            // 1 + 8 + 4 + 4
const OFF_TYPE = 0
const OFF_CONNID = 1
const OFF_SEQ = 9
const OFF_ACK = 13
const OFF_PAYLOAD = 17

const SEQ_MOD = 0x1_0000_0000          // 2^32
const SEQ_HALF = 0x8000_0000           // 2^31

/**
 * RFC1982 / TCP serial-number comparison over uint32 (rollover-safe).
 * @param {number} a
 * @param {number} b
 * @returns {number} -1 if a<b, 0 if equal, 1 if a>b (in the wraparound sense)
 */
export function seqCmp(a, b) {
  a >>>= 0; b >>>= 0
  if (a === b) return 0
  return ((a - b) >>> 0) < SEQ_HALF ? 1 : -1
}
const seqGt = (a, b) => seqCmp(a, b) > 0
const seqLte = (a, b) => seqCmp(a, b) <= 0

/**
 * Encode a frame.
 * @param {number} type
 * @param {Buffer} connId  8 bytes
 * @param {number} seq     uint32
 * @param {number} ack     uint32
 * @param {Buffer|Uint8Array} [payload]
 * @returns {Buffer}
 */
export function encodeFrame(type, connId, seq, ack, payload) {
  const plen = payload ? payload.length : 0
  const buf = Buffer.allocUnsafe(HEADER_LEN + plen)
  buf[OFF_TYPE] = type & 0xff
  connId.copy(buf, OFF_CONNID, 0, 8)
  buf.writeUInt32BE(seq >>> 0, OFF_SEQ)
  buf.writeUInt32BE(ack >>> 0, OFF_ACK)
  if (plen) Buffer.from(payload).copy(buf, OFF_PAYLOAD)
  return buf
}

/**
 * Decode a frame header + payload view. Returns null on a runt buffer.
 * @param {Buffer} buf
 * @returns {{type:number, connId:Buffer, seq:number, ack:number, payload:Buffer}|null}
 */
export function decodeFrame(buf) {
  if (!buf || buf.length < HEADER_LEN) return null
  return {
    type: buf[OFF_TYPE],
    connId: buf.subarray(OFF_CONNID, OFF_CONNID + 8),
    seq: buf.readUInt32BE(OFF_SEQ),
    ack: buf.readUInt32BE(OFF_ACK),
    payload: buf.subarray(OFF_PAYLOAD),
  }
}

const noop = () => {}

/**
 * Create a reliability channel over an abstract datagram transport.
 *
 * @param {object} opts
 * @param {(datagram:Buffer)=>void} opts.send  sends one datagram to the current peer.
 * @param {Buffer} [opts.connId]      8-byte connection id; both peers MUST share it.
 *                                    Generated from crypto.randomBytes if omitted.
 * @param {number} [opts.mtu=1200]    max datagram size; sendReliable throws if exceeded.
 * @param {number} [opts.window=256]  max in-flight reliable frames (backpressure).
 * @param {number} [opts.keepaliveMs=25000]  idle interval before a PING is emitted.
 * @param {number} [opts.rtoMin=200]  RTO floor (ms).
 * @param {number} [opts.rtoMax=60000] RTO ceiling (ms).
 * @param {()=>number} [opts.now]     monotonic clock (ms). Default () => Date.now().
 * @returns {object} channel
 */
export function createChannel(opts = {}) {
  if (typeof opts.send !== 'function') throw new TypeError('createChannel: opts.send required')
  const send = opts.send
  const now = opts.now || (() => Date.now())
  const connId = opts.connId ? Buffer.from(opts.connId) : randomBytes(8)
  if (connId.length !== 8) throw new RangeError('connId must be 8 bytes')
  const mtu = opts.mtu ?? 1200
  const window = opts.window ?? 256
  const keepaliveMs = opts.keepaliveMs ?? 25000
  const rtoMin = opts.rtoMin ?? 200
  const rtoMax = opts.rtoMax ?? 60000
  const maxPayload = mtu - HEADER_LEN

  // ---- send (reliable, outbound) state ----
  let sndNext = 0                  // next seq to assign
  let sndUna = 0                   // oldest unacked seq (sndNext once all acked)
  const inflight = new Map()       // seq -> {seq, frame, firstSentAt, tries, deadline}
  const sendQueue = []             // Buffer[] awaiting a window slot

  // ---- receive (reliable, inbound) state ----
  let rcvNext = 0                  // next in-order seq expected
  const reorder = new Map()        // seq -> payload Buffer (future, buffered)

  // ---- RTT / RTO (RFC6298) ----
  let srtt = 0, rttvar = 0, rto = 1000
  let rttInit = false

  // ---- liveness / keepalive ----
  let lastSentAt = now()
  let lastRecvAt = now()

  // ---- stats ----
  let sentFrames = 0, resends = 0
  let peerRinfo = null
  let closed = false

  // ---- callbacks ----
  let onReliableCb = noop
  let onCloseCb = noop
  let onRoamCb = noop

  /** cumulative ack we advertise = highest in-order seq we've delivered. */
  const ackField = () => (rcvNext - 1) >>> 0

  function rawSend(type, seq, payload) {
    if (closed && type !== TYPE.CLOSE) return
    const frame = encodeFrame(type, connId, seq, ackField(), payload)
    lastSentAt = now()
    sentFrames++
    send(frame)
  }

  /** Standalone ACK (no payload) — recovers lost piggybacked acks. */
  function sendAck() { rawSend(TYPE.ACK, 0, null) }

  function updateRto(rttSample) {
    if (!rttInit) { srtt = rttSample; rttvar = rttSample / 2; rttInit = true }
    else {
      rttvar = (1 - 0.25) * rttvar + 0.25 * Math.abs(srtt - rttSample)
      srtt = (1 - 0.125) * srtt + 0.125 * rttSample
    }
    rto = clampRto(srtt + 4 * rttvar)
  }
  const clampRto = (v) => Math.max(rtoMin, Math.min(rtoMax, Math.round(v)))

  /** Move queued reliable frames into the window while a slot is free. */
  function pump() {
    while (sendQueue.length && inflight.size < window && !closed) {
      const payload = sendQueue.shift()
      const seq = sndNext; sndNext = (sndNext + 1) >>> 0
      const t = now()
      const frame = encodeFrame(TYPE.DATA, connId, seq, ackField(), payload)
      inflight.set(seq, { seq, payload, firstSentAt: t, tries: 1, deadline: t + rto })
      lastSentAt = t; sentFrames++
      send(frame)
    }
  }

  /**
   * Queue application bytes for ordered, reliable, exactly-once delivery.
   * @param {Buffer|Uint8Array} bytes
   * @returns {void}
   */
  function sendReliable(bytes) {
    if (closed) throw new Error('channel closed')
    const payload = Buffer.from(bytes)
    if (payload.length > maxPayload) {
      throw new RangeError(`payload ${payload.length} > mtu budget ${maxPayload}`)
    }
    sendQueue.push(payload)
    pump()
  }

  /** Process a cumulative ack: drop acked inflight, sample RTT (Karn), slide window. */
  function onAck(ack) {
    let advanced = false
    for (const seg of [...inflight.values()]) {
      // ack is cumulative: seg acked iff seg.seq <= ack (wraparound-safe) and seg.seq
      // is at/after sndUna (guards a stale wrapped ack from acking future segs).
      if (seqLte(seg.seq, ack) && seqCmp(seg.seq, sndUna) >= 0) {
        if (seg.tries === 1) updateRto(now() - seg.firstSentAt)  // Karn: skip retransmits
        inflight.delete(seg.seq)
        advanced = true
      }
    }
    if (advanced) {
      sndUna = (ack + 1) >>> 0
      pump()
    }
  }

  /** Deliver an inbound DATA payload, buffering out-of-order, draining contiguous runs. */
  function onData(seq, payload) {
    const rel = seqCmp(seq, rcvNext)
    if (rel < 0) { sendAck(); return }                 // already delivered -> re-ack, drop
    if (rel > 0) {                                      // future within window -> buffer
      if (seqCmp(seq, (rcvNext + window) >>> 0) < 0 && !reorder.has(seq)) {
        reorder.set(seq, Buffer.from(payload))
      }
      sendAck()
      return
    }
    // in-order: deliver, then drain any buffered contiguous successors.
    onReliableCb(Buffer.from(payload))
    rcvNext = (rcvNext + 1) >>> 0
    while (reorder.has(rcvNext)) {
      const p = reorder.get(rcvNext); reorder.delete(rcvNext)
      onReliableCb(p)
      rcvNext = (rcvNext + 1) >>> 0
    }
    sendAck()
  }

  /**
   * Feed every incoming datagram here.
   * @param {Buffer} buf
   * @param {object} [rinfo]  transport address; used for connId roaming (D9).
   */
  function onDatagram(buf, rinfo) {
    const f = decodeFrame(buf)
    if (!f) return
    if (!f.connId.equals(connId)) return               // not my connection — ignore
    lastRecvAt = now()

    // QUIC-style migration: any datagram bearing my connId is authoritative for the
    // peer address, whatever the source rinfo. (Real auth is the AEAD layer above.)
    if (rinfo && (peerRinfo === null || !sameRinfo(peerRinfo, rinfo))) {
      peerRinfo = rinfo
      onRoamCb(rinfo)
    }

    // Every frame piggybacks the peer's cumulative ack.
    onAck(f.ack)

    switch (f.type) {
      case TYPE.DATA:
        if (!closed) onData(f.seq, f.payload)
        break
      case TYPE.PING:
        rawSend(TYPE.PONG, 0, null)
        break
      case TYPE.ACK:
      case TYPE.PONG:
        break                                          // ack already applied above
      case TYPE.CLOSE:
        if (!closed) { closed = true; onCloseCb('peer'); }
        break
      default:
        break                                          // HELLO/HS1/HS2 handled elsewhere
    }
  }

  /**
   * Drive timers: RTO-based resend (exponential backoff) + keepalive PING emission.
   * @param {number} [nowMs]  optional explicit clock read.
   */
  function tick(nowMs) {
    if (closed) return
    const t = nowMs ?? now()
    // Resend expired inflight segments (oldest first), backing off each retry.
    const segs = [...inflight.values()].sort((a, b) => seqCmp(a.seq, b.seq))
    for (const seg of segs) {
      if (t >= seg.deadline) {
        seg.tries++
        resends++
        const backoff = clampRto(rto * Math.pow(2, seg.tries - 1))
        seg.deadline = t + backoff
        rawSendData(seg)
      }
    }
    // Keepalive: if we haven't sent anything for keepaliveMs, emit a PING.
    if (t - lastSentAt >= keepaliveMs) rawSend(TYPE.PING, 0, null)
  }

  function rawSendData(seg) {
    const frame = encodeFrame(TYPE.DATA, connId, seg.seq, ackField(), seg.payload)
    lastSentAt = now()
    sentFrames++
    send(frame)
  }

  /** Send CLOSE and shut the channel; idempotent. */
  function close() {
    if (closed) return
    rawSend(TYPE.CLOSE, 0, null)
    closed = true
    inflight.clear()
    sendQueue.length = 0
    reorder.clear()
    onCloseCb('local')
  }

  /** @returns {{inflight:number, queued:number, rtt:number, rto:number, loss:number, sent:number, resends:number, closed:boolean}} */
  function stats() {
    return {
      inflight: inflight.size,
      queued: sendQueue.length,
      rtt: rttInit ? Math.round(srtt) : 0,
      rto,
      loss: sentFrames ? resends / sentFrames : 0,
      sent: sentFrames,
      resends,
      closed,
    }
  }

  return {
    connId,
    sendReliable,
    onReliable(cb) { onReliableCb = cb || noop },
    onDatagram,
    tick,
    stats,
    close,
    onClose(cb) { onCloseCb = cb || noop },
    onRoam(cb) { onRoamCb = cb || noop },
    get peerRinfo() { return peerRinfo },
    get closed() { return closed },
    // exposed for tests / diagnostics
    get _rcvNext() { return rcvNext },
    get _sndNext() { return sndNext },
  }
}

/** @param {object} a @param {object} b */
function sameRinfo(a, b) {
  return a.address === b.address && a.port === b.port && a.family === b.family
}

export default { createChannel, encodeFrame, decodeFrame, seqCmp, TYPE, TYPE_NAME, HEADER_LEN }
