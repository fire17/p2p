// src/browser/webrtc.js — the browser's transport + rendezvous, behind the EXISTING seams.
//
// This is the only genuinely new protocol-adjacent module the browser needs. Everything else
// (key.js, noise.js, wire.js, node.js, group.js) is the TUI's own source, unchanged.
//
// It provides the three seams src/node.js injects (docs/API-SKETCH + src/node.js resolveDeps):
//
//   createEndpoint()      -> ep   with ep.punch(cands,{token}) and ep.onConnection(cb)
//   publishAll(S, ep)     -> stay reachable under rid(S)   (the LISTENER side)
//   resolve(S)            -> candidate stream               (the DIALER side)
//
// ...so src/node.js drives HELLO -> commitment gate -> Noise IK -> wire framing over a WebRTC
// DataChannel exactly as it does over UDP. node.js does not know or care which it is.
//
// WHY WebRTC: a browser has no raw UDP socket — no STUN of its own, no hole punch, no DHT, no
// listening socket. RTCDataChannel is the ONLY peer-to-peer primitive it has. (research/
// browser-client.md §5.1.)
//
// WHY THE TRACKERS: WebRTC needs an offer/answer exchange. We already have one — the public WSS
// trackers in src/rendezvous/tracker.js, keyed by rid = HKDF(S, "p2p-rv-tracker-v1", epoch, 20).
// The TUI currently posts a FAKE SDP there (an a=p2p-blob envelope for UDP candidates); the
// browser posts a REAL one. Same trackers, same infohash derivation, same message shape — so the
// browser reuses our rendezvous with ZERO new infrastructure and nothing of ours to run.
//
// SECURITY: none of this is trusted. The tracker is an untrusted matchmaker, STUN is untrusted,
// and WebRTC's DTLS is an untrusted outer wrapper — an attacker who rewrites the SDP owns the
// DTLS layer and still cannot pass the commitment gate or produce a decryptable Noise msg2. The
// security boundary is the Noise layer that node.js runs ON TOP of this. See §8/§9 of the study.
//
// ROLES (deliberately asymmetric, so a pair converges on ONE DataChannel instead of racing two):
//   LISTENER (publishAll): parks real WebRTC offers on the trackers under its rid, and CREATES
//                          the DataChannel. On answer -> channel opens -> onConnection -> HELLO.
//   DIALER   (punch):      announces under the target's rid WITHOUT offers, receives a parked
//                          offer, answers it, and receives the DataChannel via ondatachannel.
// This mirrors WebTorrent/trystero, and it lands the accepter on the side node.js expects to
// send HELLO.

import { deriveRid } from '../key.js'
import { TRACKERS, infoHashFor, randId20 } from '../rendezvous/tracker.js'
import { announceEpochs, resolveEpochs } from '../rendezvous/race.js'

/** Free public STUN — the same servers src/transport.js already uses. No TURN, none of ours. */
export const ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun.cloudflare.com:3478' },
]

const OFFERS_PER_ANNOUNCE = 4 // each parked offer is single-use; a few lets several dialers land
const ANNOUNCE_INTERVAL_MS = 10_000 // trystero cadence; parked offers expire ~120s
const RECONNECT_MS = 3000
const ICE_GATHER_MS = 3000 // cap on waiting for ICE gathering (we ship what we have)
const DIAL_TIMEOUT_MS = 30_000

// BRW-4 (leak fix): a parked, unanswered offer holds a whole RTCPeerConnection (ICE agent + STUN
// state). It was freed ONLY on dc.onopen or node.close() — so unanswered offers accumulated at
// ~12 PCs/10s and eventually exhausted a long-lived listener (research/wargame-findings §10.3).
// Bound BOTH how long one is parked and how many are parked at once.
const OFFER_TTL_MS = 120_000 // reap a parked offer unanswered this long (== tracker offer-expiry, so nothing still-serveable is dropped)
const CONNECT_TTL_MS = 30_000 // after an answer arrives, reap if the DataChannel never opens (ICE failed)
const MAX_PENDING_OFFERS = 64 // hard cap on simultaneously-parked offers; oldest evicted first

/** Wait for ICE gathering to finish (or the cap) — we send one complete SDP, no trickle. */
function whenIceGathered(pc, capMs = ICE_GATHER_MS) {
  if (pc.iceGatheringState === 'complete') return Promise.resolve()
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(timer)
      pc.removeEventListener('icegatheringstatechange', check)
      resolve()
    }
    const check = () => pc.iceGatheringState === 'complete' && done()
    const timer = setTimeout(done, capMs) // partial candidates are fine — ICE keeps working
    pc.addEventListener('icegatheringstatechange', check)
  })
}

/**
 * Wrap an open RTCDataChannel in the socket-like src/node.js + src/wire.js expect:
 * `.send(frame)` / `.onMessage(buf)` / `.close()` / `.closed` / `.rinfo`.
 * Frames are already <= node's mtu (1200 B default), far under the ~16 KiB DataChannel ceiling.
 */
// DataChannel message-size discipline (research/browser-client.md §5.2). A reliable+ordered channel
// has NO spec cap, but the cross-browser SAFE per-message size is ~16 KiB (Firefox→Chromium caps
// there; Chromium closes the channel above ~256 KiB; no browser implements SCTP ndata yet). node.js
// frames are ≤ mtu (1200 B default) today — but that is an accidental margin, not a designed one, so
// we chunk here: any frame is split into ≤16 KiB pieces and reassembled on the far side. Symmetric —
// both peers run THIS module (browser via global RTCPeerConnection, Node via an injected werift PC),
// so the framing is understood on both ends.
const CHUNK_HDR = 8 // msgId(4) | index(2) | total(2)
const CHUNK_MAX = 16000 // ≤16 KiB per DataChannel message
const CHUNK_PAYLOAD = CHUNK_MAX - CHUNK_HDR
const MAX_CHUNKS = 4096 // ≈64 MB ceiling per message — refuse anything larger (anti-OOM)
// BRW-5: the reassembly buffer is keyed by a SENDER-chosen msgId and was never bounded — a peer with
// an open channel (post-DTLS, pre-Noise) could stream endless partial messages (distinct ids) and
// exhaust memory before Noise gates anything (research/wargame-findings §10.3). Cap the concurrent
// partial count AND the total buffered bytes per channel; evict the oldest partials past the cap.
// Real traffic never touches this path (node frames are ≤ mtu ⇒ single-chunk fast path); it only
// bounds the >16 KiB / hostile case, so the caps sit far above any legitimate single message.
const MAX_REASM_BYTES = 8 * 1024 * 1024 // total in-flight partial bytes per channel
const MAX_REASM_ENTRIES = 256 // concurrent incomplete messages per channel

export function socketFromChannel(dc, pc) {
  dc.binaryType = 'arraybuffer'
  let sendId = 0
  const reasm = new Map() // msgId -> { parts, have, total, len }
  let reasmBytes = 0 // BRW-5: total payload bytes currently buffered across all partial reassemblies
  /** Evict the oldest partial (never `exceptId`) to reclaim reasm memory; returns false if none. */
  const evictOldestReasm = (exceptId) => {
    for (const k of reasm.keys()) {
      if (k === exceptId) continue
      reasmBytes -= reasm.get(k).len
      reasm.delete(k)
      return true
    }
    return false
  }
  const socket = {
    closed: false,
    rinfo: { address: 'webrtc', port: 0 }, // wire.js roams by connId, not by rinfo — this is inert
    onMessage: null,
    send(frame) {
      if (socket.closed || dc.readyState !== 'open') return
      const f = frame instanceof Uint8Array ? frame : new Uint8Array(frame)
      const total = Math.max(1, Math.ceil(f.length / CHUNK_PAYLOAD))
      const id = (sendId = (sendId + 1) >>> 0)
      try {
        for (let i = 0; i < total; i++) {
          const part = f.subarray(i * CHUNK_PAYLOAD, (i + 1) * CHUNK_PAYLOAD)
          const msg = new Uint8Array(CHUNK_HDR + part.length)
          const dv = new DataView(msg.buffer)
          dv.setUint32(0, id)
          dv.setUint16(4, i)
          dv.setUint16(6, total)
          msg.set(part, CHUNK_HDR)
          dc.send(msg)
        }
      } catch {
        /* channel died mid-send; wire's ARQ/keepalive will notice */
      }
    },
    close() {
      if (socket.closed) return
      socket.closed = true
      reasm.clear()
      reasmBytes = 0
      try { dc.close() } catch { /* */ }
      try { pc.close() } catch { /* */ }
    },
    _debug: { reasmCount: () => reasm.size, reasmBytes: () => reasmBytes }, // BRW-5 leak-monitor hook
  }
  dc.onmessage = (ev) => {
    if (!socket.onMessage) return
    const b = new Uint8Array(ev.data)
    if (b.length < CHUNK_HDR) return // malformed / runt — drop (matches wire.js decodeFrame guard)
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
    const id = dv.getUint32(0)
    const index = dv.getUint16(4)
    const total = dv.getUint16(6)
    const payload = b.subarray(CHUNK_HDR)
    if (total < 1 || total > MAX_CHUNKS || index >= total) return // refuse absurd framing (anti-OOM)
    if (total === 1) { socket.onMessage(Buffer.from(payload)); return } // fast path — unchunked
    let asm = reasm.get(id)
    if (!asm) { asm = { parts: new Array(total), have: 0, total, len: 0 }; reasm.set(id, asm) }
    if (asm.total !== total || asm.parts[index]) return // inconsistent / duplicate chunk — ignore
    asm.parts[index] = payload
    asm.have++
    asm.len += payload.length
    reasmBytes += payload.length
    if (asm.have === total) {
      reasm.delete(id)
      reasmBytes -= asm.len
      const out = new Uint8Array(asm.len)
      let off = 0
      for (const p of asm.parts) { out.set(p, off); off += p.length }
      socket.onMessage(Buffer.from(out))
      return
    }
    // BRW-5: still incomplete — enforce the caps. Evict oldest OTHER partials first; if the current
    // message alone blows the byte cap (only possible for an abusive >8 MB single message), drop it.
    while ((reasmBytes > MAX_REASM_BYTES || reasm.size > MAX_REASM_ENTRIES) && evictOldestReasm(id)) { /* reclaim */ }
    if (reasmBytes > MAX_REASM_BYTES) { reasmBytes -= asm.len; reasm.delete(id) }
  }
  dc.onclose = () => {
    socket.closed = true
  }
  return socket
}

/**
 * The browser rendezvous+transport. One object owns the tracker sockets, the peer connections
 * and the endpoint, so closing it tears everything down.
 * @param {object} [opts] {trackers, iceServers, RTCPeerConnection, WebSocket, now}
 */
export function createBrowserTransport(opts = {}) {
  const trackers = opts.trackers || TRACKERS
  const iceServers = opts.iceServers || ICE_SERVERS
  const PC = opts.RTCPeerConnection || globalThis.RTCPeerConnection
  const WS = opts.WebSocket || globalThis.WebSocket
  const now = opts.now || (() => Date.now())
  const offerTtlMs = opts.offerTtlMs || OFFER_TTL_MS
  const connectTtlMs = opts.connectTtlMs || CONNECT_TTL_MS
  const maxPendingOffers = opts.maxPendingOffers || MAX_PENDING_OFFERS
  const announceIntervalMs = opts.announceIntervalMs || ANNOUNCE_INTERVAL_MS
  const myPeerId = randId20()

  if (!PC) throw new Error('this browser has no RTCPeerConnection — WebRTC is required')
  if (!WS) throw new Error('this environment has no WebSocket')

  const conns = [] // open tracker sockets
  const live = new Set() // RTCPeerConnections we own (for close())
  let onConnectionCb = null
  let closed = false

  const newPc = () => {
    const pc = new PC({ iceServers })
    live.add(pc)
    return pc
  }
  const freePc = (pc) => { try { pc.close() } catch { /* */ } live.delete(pc) }

  /** Open (and keep) a tracker WebSocket, dispatching relayed offers/answers to `onMsg`. */
  function openTracker(url, { persistent, onOpen, onMsg, signal }) {
    let ws
    let reconnect
    let stopped = false
    const start = () => {
      if (stopped || closed) return
      try {
        ws = new WS(url)
      } catch {
        return schedule()
      }
      ws.onopen = () => onOpen && onOpen(ws)
      ws.onmessage = (ev) => {
        let m
        try {
          m = JSON.parse(typeof ev.data === 'string' ? ev.data : '')
        } catch {
          return
        }
        if (!m || m.peer_id === myPeerId) return // ignore our own echoes
        onMsg(m, ws)
      }
      ws.onclose = () => schedule()
      ws.onerror = () => { try { ws.close() } catch { /* */ } }
    }
    const schedule = () => {
      if (stopped || closed || !persistent) return
      reconnect = setTimeout(start, RECONNECT_MS)
    }
    const stop = () => {
      stopped = true
      clearTimeout(reconnect)
      try { ws && ws.close() } catch { /* */ }
    }
    signal?.addEventListener('abort', stop, { once: true })
    start()
    const handle = { stop, get ws() { return ws } }
    conns.push(handle)
    return handle
  }

  const send = (ws, obj) => {
    try {
      if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj))
    } catch {
      /* not open */
    }
  }

  // ── ENDPOINT ────────────────────────────────────────────────────────────────
  const endpoint = {
    /** src/node.js sets this; we fire it for every inbound DataChannel (the accepter path). */
    onConnection(cb) {
      onConnectionCb = cb
    },
    /** No local candidates to publish — a browser has no addressable ones. */
    candidates() {
      return []
    },

    /**
     * DIALER. `cands` come from resolve(S) below and carry the contact string. We join the
     * target's rid on the trackers, take a parked offer, answer it, and the DataChannel the
     * listener created arrives via ondatachannel.
     * @returns {Promise<object>} socket-like, once the channel is OPEN
     */
    punch(cands, _opts = {}) {
      const s = cands.map((c) => c && c.s).find(Boolean)
      if (!s) return Promise.reject(new Error('webrtc punch: no contact string in candidates'))

      // read-epochs: yesterday/today/tomorrow (the reader checks ±1 — src/rendezvous/race.js)
      const infoHashes = resolveEpochs(now()).map((ep) => infoHashFor(deriveRid(s, 'tracker', ep, 20)))
      const ac = new AbortController()

      return new Promise((resolve, reject) => {
        let settled = false
        const handles = []
        const finish = (err, socket) => {
          if (settled) return
          settled = true
          clearTimeout(timer)
          ac.abort()
          for (const h of handles) h.stop()
          err ? reject(err) : resolve(socket)
        }
        const timer = setTimeout(
          () => finish(new Error('webrtc punch: no peer answered within ' + DIAL_TIMEOUT_MS + 'ms')),
          DIAL_TIMEOUT_MS,
        )

        const onOffer = async (m, ws) => {
          if (settled) return
          const pc = newPc()
          // The listener created the channel; we receive it.
          pc.ondatachannel = (ev) => {
            const dc = ev.channel
            const deliver = () => finish(null, socketFromChannel(dc, pc))
            if (dc.readyState === 'open') deliver()
            else dc.onopen = deliver
          }
          try {
            await pc.setRemoteDescription({ type: 'offer', sdp: m.offer.sdp })
            const answer = await pc.createAnswer()
            await pc.setLocalDescription(answer)
            await whenIceGathered(pc)
            send(ws, {
              action: 'announce',
              info_hash: m.info_hash,
              peer_id: myPeerId,
              to_peer_id: m.peer_id,
              offer_id: m.offer_id,
              answer: { type: 'answer', sdp: pc.localDescription.sdp },
            })
          } catch (err) {
            freePc(pc)
            if (!settled) console.warn('[p2p] failed to answer an offer:', err.message)
          }
        }

        for (const url of trackers) {
          for (const infoHash of infoHashes) {
            handles.push(
              openTracker(url, {
                persistent: false,
                signal: ac.signal,
                // A dialer announces with NO offers — it wants to be handed a parked one.
                onOpen: (ws) =>
                  send(ws, {
                    action: 'announce',
                    info_hash: infoHash,
                    peer_id: myPeerId,
                    numwant: 10,
                    uploaded: 0,
                    downloaded: 0,
                    left: 0,
                  }),
                onMsg: (m, ws) => {
                  if (m.offer && m.offer_id && m.peer_id) onOffer(m, ws)
                },
              }),
            )
          }
        }
      })
    },

    close() {
      closed = true
      for (const h of conns) h.stop()
      for (const pc of live) { try { pc.close() } catch { /* */ } }
      live.clear()
    },
  }

  // ── LISTENER ────────────────────────────────────────────────────────────────
  /**
   * Stay reachable: park fresh WebRTC offers under rid(S) on every tracker, refresh on a timer,
   * and answer-match anything that answers. When a DataChannel opens, hand it to node.js's
   * accepter (which sends HELLO, then runs the Noise IK responder).
   * @param {string} S our own contact string
   */
  function publishAll(S) {
    const pending = new Map() // offer_id -> { pc, timer } (a parked, still-unanswered offer)

    /** Reap a parked offer that was never answered (or whose answer never opened a channel). */
    const evict = (offerId) => {
      const e = pending.get(offerId)
      if (!e) return
      clearTimeout(e.timer)
      pending.delete(offerId)
      freePc(e.pc)
    }

    /** Build one pc + its DataChannel + an SDP offer, ready to park on a tracker. */
    async function makeOffer() {
      const pc = newPc()
      // The LISTENER creates the channel — so the dialer gets it via ondatachannel, and we end up
      // on the side node.js expects to send HELLO.
      const dc = pc.createDataChannel('p2p', { ordered: true }) // reliable+ordered: SCTP does the ARQ
      const offerId = randId20()
      dc.onopen = () => {
        const e = pending.get(offerId)
        if (e) { clearTimeout(e.timer); pending.delete(offerId) } // promoted to a live connection; keep pc in `live` (freed at node.close)
        if (onConnectionCb && !closed) onConnectionCb(socketFromChannel(dc, pc))
      }
      const offer = await pc.createOffer()
      await pc.setLocalDescription(offer)
      await whenIceGathered(pc)
      if (closed) { freePc(pc); return null } // transport torn down mid-offer — don't park a dead pc
      // BRW-4: bound parked offers. Evict the oldest before parking a new one, and TTL-reap any that
      // is never answered. `unref` so a parked offer never keeps a Node werift process alive.
      while (pending.size >= maxPendingOffers) evict(pending.keys().next().value)
      const timer = setTimeout(() => evict(offerId), offerTtlMs)
      timer.unref?.()
      pending.set(offerId, { pc, timer })
      return { offer_id: offerId, offer: { type: 'offer', sdp: pc.localDescription.sdp } }
    }

    const announce = async (ws, infoHash) => {
      try {
        const offers = (await Promise.all(Array.from({ length: OFFERS_PER_ANNOUNCE }, makeOffer))).filter(Boolean)
        if (!offers.length) return
        send(ws, {
          action: 'announce',
          info_hash: infoHash,
          peer_id: myPeerId,
          numwant: 10,
          uploaded: 0,
          downloaded: 0,
          left: 0,
          offers,
        })
      } catch (err) {
        console.warn('[p2p] announce failed:', err.message)
      }
    }

    const stops = []
    for (const url of trackers) {
      // announce-epochs: today, plus tomorrow shortly before the UTC rollover (no blackout)
      const infoHashes = announceEpochs(now()).map((ep) => infoHashFor(deriveRid(S, 'tracker', ep, 20)))
      for (const infoHash of infoHashes) {
        let timer
        const h = openTracker(url, {
          persistent: true,
          onOpen: (ws) => {
            announce(ws, infoHash)
            clearInterval(timer)
            timer = setInterval(() => announce(h.ws, infoHash), announceIntervalMs)
          },
          onMsg: async (m) => {
            // Someone took one of our parked offers.
            if (m.answer && m.offer_id && pending.has(m.offer_id)) {
              const e = pending.get(m.offer_id)
              // This offer is no longer "parked unanswered" — a real dialer answered. Swap the park-TTL
              // for a shorter connect-TTL so a legit-but-slow answerer isn't reaped mid-ICE, yet a pc
              // whose ICE never opens the channel is still reclaimed (no leak on a failed answer).
              clearTimeout(e.timer)
              e.timer = setTimeout(() => evict(m.offer_id), connectTtlMs)
              e.timer.unref?.()
              try {
                await e.pc.setRemoteDescription({ type: 'answer', sdp: m.answer.sdp })
                // -> ICE connects -> dc.onopen -> onConnectionCb (above)
              } catch (err) {
                console.warn('[p2p] failed to accept an answer:', err.message)
              }
            }
          },
        })
        stops.push(() => {
          clearInterval(timer)
          h.stop()
        })
      }
    }
    return {
      stop() {
        for (const s of stops) s()
        for (const offerId of [...pending.keys()]) evict(offerId) // free every parked offer on teardown
      },
      pendingCount: () => pending.size, // BRW-4 leak-monitor hook (test/soak)
    }
  }

  /**
   * DIALER discovery. A browser has no candidates to gather (no UDP, no STUN of its own) — the
   * WebRTC/ICE machinery does all of that inside punch(). So resolve() yields ONE candidate that
   * simply carries the contact string through to punch(), which does the real work.
   * Shape matches what src/node.js's collectCandidates() expects (an async iterable).
   */
  async function* resolve(S) {
    yield { channel: 'webrtc', s: S, ts: now() }
  }

  return {
    endpoint,
    createEndpoint: async () => endpoint,
    publishAll,
    resolve,
    close: endpoint.close,
    _debug: { liveCount: () => live.size }, // BRW-4 leak-monitor hook: owned RTCPeerConnections
  }
}

export default { createBrowserTransport, ICE_SERVERS }
