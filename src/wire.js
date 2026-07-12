// src/wire.js — transport-agnostic framing + reliability channel for p2p (v1).
//
// Frame: [1B type][8B connId][4B seq][4B ack][payload][16B MAC]. Types below. DATA payloads
// are OPAQUE (an AEAD frame from noise split states) — no payload crypto happens here.
//
// CONTROL-PLANE AUTHENTICATION (WIRE-1/2/3, research/wargame-findings.md §2).
// Every channel frame carries a MAC over the WHOLE frame — `type‖connId‖seq‖ack‖payload` —
// keyed by a post-handshake secret (node.js derives it from the Noise handshake hash and
// hands it in as opts.mac). onDatagram VERIFIES before it touches any state: nothing —
// not the ack, not rcvNext, not roaming, not CLOSE — moves for a frame that does not
// authenticate. Before this, only DATA *payloads* were protected and the control plane was
// forgeable by anyone who read a cleartext connId off the wire (an on-path observer or a
// hostile WSS relay), yielding: a forged ack that drained the send window (silent message
// loss + a wedged sender), a forged CLOSE that tore the channel down, and a forged DATA
// that advanced rcvNext pre-AEAD so the REAL frame for that seq was later dropped as
// "already delivered" — permanent, silent, per-message loss.
// Keys are DIRECTIONAL (tx ≠ rx), so an attacker cannot reflect our own frames back at us
// (a reflected DATA would otherwise authenticate and re-open WIRE-3). Cross-session replay
// dies with the key: each handshake derives fresh MAC keys.
// The pre-handshake frames (HELLO/HS1/HS2) have no key yet — they are NOT channel frames and
// never reach onDatagram; their auth is the commitment gate + Noise itself (DESIGN D4).
//
// Provides: sliding-window ARQ (ordered, exactly-once via seq dedup), cumulative ack
// (piggybacked + standalone ACK), RTT-adaptive resend (RFC6298 srtt/rttvar + Karn +
// exponential backoff), PING/PONG keepalive emitted from tick(), QUIC-style connId
// roaming (D9 — accept any rinfo carrying my connId, now only on an AUTHENTICATED frame),
// CLOSE, backpressure via stats().
//
// Zero deps, ESM. No Math.random / no Date.now in the hot path — all time comes from the
// injected `now` clock, so callers/tests stay deterministic. connId (if not supplied) is
// drawn from node:crypto randomBytes, which is fine (not a determinism concern).
//
// Contract: docs/INTERFACES.md §src/wire.js. Semantics: DESIGN.md D8/D9.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

/** @enum {number} Frame type tags (order per DESIGN/INTERFACES). */
export const TYPE = Object.freeze({
  HELLO: 0, HS1: 1, HS2: 2, DATA: 3, ACK: 4, PING: 5, PONG: 6, CLOSE: 7,
})
const TYPE_NAME = Object.freeze(
  Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k])),
)

export const HEADER_LEN = 17            // 1 + 8 + 4 + 4
/** Bytes appended to every CHANNEL frame: truncated HMAC-SHA256 over the whole frame. */
export const MAC_LEN = 16
const OFF_TYPE = 0
const OFF_CONNID = 1
const OFF_SEQ = 9
const OFF_ACK = 13
const OFF_PAYLOAD = 17

/** Truncated HMAC-SHA256(key, bytes) — 128-bit tag (same strength class as the AEAD tag). */
const macTag = (key, bytes) => createHmac('sha256', key).update(bytes).digest().subarray(0, MAC_LEN)

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
 * Encode a frame. With `macKey`, a 16-byte MAC over `[header][payload]` is appended —
 * that is what makes the header (type/connId/seq/ack) unforgeable. Handshake frames
 * (HELLO/HS1/HS2) predate the key and are encoded WITHOUT one.
 * @param {number} type
 * @param {Buffer} connId  8 bytes
 * @param {number} seq     uint32
 * @param {number} ack     uint32
 * @param {Buffer|Uint8Array} [payload]
 * @param {Buffer} [macKey]  post-handshake send key; omit for pre-handshake frames
 * @returns {Buffer}
 */
export function encodeFrame(type, connId, seq, ack, payload, macKey) {
  const plen = payload ? payload.length : 0
  const tag = macKey ? MAC_LEN : 0
  const buf = Buffer.allocUnsafe(HEADER_LEN + plen + tag)
  buf[OFF_TYPE] = type & 0xff
  connId.copy(buf, OFF_CONNID, 0, 8)
  buf.writeUInt32BE(seq >>> 0, OFF_SEQ)
  buf.writeUInt32BE(ack >>> 0, OFF_ACK)
  if (plen) Buffer.from(payload).copy(buf, OFF_PAYLOAD)
  if (macKey) macTag(macKey, buf.subarray(0, HEADER_LEN + plen)).copy(buf, HEADER_LEN + plen)
  return buf
}

/**
 * Decode a frame header + payload view. Returns null on a runt buffer.
 *
 * With `macKey` this is an AUTHENTICATED decode: the trailing MAC must verify over the
 * whole frame or the frame is REJECTED (null) — a forged/tampered/reflected header never
 * becomes a `f` the caller can act on. Fail-closed by construction: every caller already
 * drops null.
 * @param {Buffer} buf
 * @param {Buffer} [macKey]  post-handshake receive key; omit to parse an unauthenticated frame
 * @returns {{type:number, connId:Buffer, seq:number, ack:number, payload:Buffer}|null}
 */
export function decodeFrame(buf, macKey) {
  const tag = macKey ? MAC_LEN : 0
  if (!buf || buf.length < HEADER_LEN + tag) return null
  const end = buf.length - tag
  if (macKey) {
    const want = macTag(macKey, buf.subarray(0, end))
    const got = Buffer.from(buf.subarray(end))          // copy: timingSafeEqual wants a real Buffer
    if (got.length !== MAC_LEN || !timingSafeEqual(want, got)) return null   // forged -> DROP
  }
  return {
    type: buf[OFF_TYPE],
    connId: buf.subarray(OFF_CONNID, OFF_CONNID + 8),
    seq: buf.readUInt32BE(OFF_SEQ),
    ack: buf.readUInt32BE(OFF_ACK),
    payload: buf.subarray(OFF_PAYLOAD, end),
  }
}

const noop = () => {}

/**
 * Create a reliability channel over an abstract datagram transport.
 *
 * @param {object} opts
 * @param {(datagram:Buffer)=>void} opts.send  sends one datagram to the current peer.
 * @param {{tx:Buffer, rx:Buffer}} opts.mac  REQUIRED post-handshake control-plane MAC keys
 *                                    (≥16 bytes each, DIRECTIONAL: my-send key ≠ my-receive
 *                                    key — see the WIRE-1/2/3 note in the file header).
 *                                    A channel cannot be built without them: an
 *                                    unauthenticated control plane is the vulnerability.
 * @param {Buffer} [opts.connId]      8-byte connection id; both peers MUST share it.
 *                                    Generated from crypto.randomBytes if omitted.
 * @param {number} [opts.mtu=1200]    max datagram size; sendReliable throws if exceeded.
 * @param {number} [opts.window=256]  max in-flight reliable frames (backpressure).
 * @param {number} [opts.keepaliveMs=25000]  idle interval before a PING is emitted.
 * @param {number} [opts.livenessMs]  silence (no inbound frame) before the peer is declared
 *                                    DEAD and the channel closes. Default keepaliveMs*3
 *                                    (~75s: survives a couple missed PONGs, dies on real silence).
 * @param {number} [opts.rtoMin=200]  RTO floor (ms).
 * @param {number} [opts.rtoMax=60000] RTO ceiling (ms).
 * @param {()=>number} [opts.now]     monotonic clock (ms). Default () => Date.now().
 * @returns {object} channel
 */
export function createChannel(opts = {}) {
  if (typeof opts.send !== 'function') throw new TypeError('createChannel: opts.send required')
  // FAIL CLOSED: no MAC keys, no channel. There is deliberately no "unauthenticated mode" —
  // that mode WAS the bug (WIRE-1/2/3). Keys are directional; the same key on both sides
  // would let an attacker reflect our own frames back at us and re-open WIRE-3.
  const mac = opts.mac
  const okKey = (k) => Buffer.isBuffer(k) && k.length >= MAC_LEN
  if (!mac || !okKey(mac.tx) || !okKey(mac.rx)) {
    throw new TypeError('createChannel: opts.mac {tx,rx} post-handshake MAC keys required (control-plane auth)')
  }
  if (mac.tx.equals(mac.rx)) throw new TypeError('createChannel: opts.mac tx and rx must differ (reflection guard)')
  const macTx = mac.tx, macRx = mac.rx
  const send = opts.send
  const now = opts.now || (() => Date.now())
  const connId = opts.connId ? Buffer.from(opts.connId) : randomBytes(8)
  if (connId.length !== 8) throw new RangeError('connId must be 8 bytes')
  const mtu = opts.mtu ?? 1200
  const window = opts.window ?? 256
  const keepaliveMs = opts.keepaliveMs ?? 25000
  const livenessMs = opts.livenessMs ?? keepaliveMs * 3
  const rtoMin = opts.rtoMin ?? 200
  const rtoMax = opts.rtoMax ?? 60000
  const maxPayload = mtu - HEADER_LEN - MAC_LEN      // the MAC rides in the datagram budget too

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
  let sentFrames = 0, resends = 0, authFails = 0
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
    const frame = encodeFrame(type, connId, seq, ackField(), payload, macTx)
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
      const frame = encodeFrame(TYPE.DATA, connId, seq, ackField(), payload, macTx)
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
   *
   * TWO GATES, cheap-before-expensive:
   *   1. connId — a memcmp; drops everything not aimed at this connection.
   *   2. the MAC — the SECURITY gate. Nothing below this line runs for a frame that does
   *      not authenticate: no lastRecvAt (no liveness extension), no roaming, no onAck (so
   *      a forged ack cannot drain the send window — WIRE-1), no onData (so a forged DATA
   *      cannot advance rcvNext and erase the real message for that seq — WIRE-3), no
   *      teardown (so a forged CLOSE is a no-op — WIRE-2).
   * @param {Buffer} buf
   * @param {object} [rinfo]  transport address; used for connId roaming (D9).
   */
  function onDatagram(buf, rinfo) {
    const hdr = decodeFrame(buf)                       // cheap, UNAUTHENTICATED header view
    if (!hdr || !hdr.connId.equals(connId)) return     // not my connection — ignore
    const f = decodeFrame(buf, macRx)                  // AUTHENTICATED decode (fail-closed)
    if (!f) { authFails++; return }                    // forged / tampered / reflected — DROP
    lastRecvAt = now()

    // QUIC-style migration: any AUTHENTICATED datagram bearing my connId is authoritative
    // for the peer address, whatever the source rinfo. (Pre-MAC, any on-path forger could
    // move it; now only the key holder can.)
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
    // Liveness death: no inbound frame (data/ack/PONG) for livenessMs => peer is gone.
    // Close so the owner (node.js) flips connected=false + emits 'disconnect', and a
    // redial re-handshakes instead of reusing the corpse. NAT expiry / real silence.
    if (t - lastRecvAt >= livenessMs) { closed = true; onCloseCb('timeout') }
  }

  function rawSendData(seg) {
    // Re-MAC on every resend: the ack field is refreshed here, so the tag must be too.
    const frame = encodeFrame(TYPE.DATA, connId, seg.seq, ackField(), seg.payload, macTx)
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

  /** @returns {{inflight:number, queued:number, rtt:number, rto:number, loss:number, sent:number, resends:number, authFails:number, closed:boolean}} */
  function stats() {
    return {
      inflight: inflight.size,
      queued: sendQueue.length,
      rtt: rttInit ? Math.round(srtt) : 0,
      rto,
      loss: sentFrames ? resends / sentFrames : 0,
      sent: sentFrames,
      resends,
      authFails,                                       // frames dropped by the MAC gate (forgery attempts)
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

export default { createChannel, encodeFrame, decodeFrame, seqCmp, TYPE, TYPE_NAME, HEADER_LEN, MAC_LEN }
