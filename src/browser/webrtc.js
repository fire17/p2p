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

const ANNOUNCE_INTERVAL_MS = 10_000 // tracker keepalive cadence. NOT a PC-creation tick (see BRW-4b).
const RECONNECT_MS = 3000
const ICE_GATHER_MS = 3000 // cap on waiting for ICE gathering (we ship what we have)
const DIAL_TIMEOUT_MS = 30_000

// ── BRW-4 / BRW-4b: DO NOT CHURN RTCPeerConnections. ────────────────────────────────────────────
// BRW-4 (a84345e) capped how many offers sit PARKED (TTL + a cap) and its soak passed — but that
// soak ran on Node **werift** PCs, which have no per-page limit. A real browser does, and it is
// harsher than "how many are alive":
//
//   MEASURED, Chromium 141 (test/browser-pc-soak.mjs + its probes):
//     • `new RTCPeerConnection` throws "Cannot create so many PeerConnections" at the **500th
//       CONSTRUCTION on a page** — a CUMULATIVE limit, not a concurrent one.
//     • `pc.close()` + dropping every reference does NOT decrement it. Blink only decrements when
//       the object is destructed by an Oilpan GC, and that GC does **not** run on its own: 450
//       closed+dereferenced PCs, 30 s idle, still counted. Only a forced `gc()` reclaimed them —
//       which a real page cannot call.
//
// ⇒ ANY creation rate proportional to TIME eventually kills a long-lived listener tab. The old
//    listener minted OFFERS_PER_ANNOUNCE=4 fresh PCs per announce per tracker (3) every 10 s
//    ≈ 72 PCs/min → the 500-wall in ≈7 minutes. That is the console flood the owner hit.
//
// THE FIX: constructions must be proportional to REAL CONNECTIONS, not to time. We hold a small
// POOL of parked-offer PCs and RE-USE them: every announce re-publishes the SAME parked offers, and
// staleness is handled by re-offering ON THE SAME pc (`restartIce()` + a fresh SDP) — which costs
// ZERO new RTCPeerConnections. A pc is constructed only to fill an empty pool slot: at startup, or
// after a slot's offer was actually consumed by a peer (or its ICE died). Steady-state churn: 0/h.
const PARKED_OFFERS_PER_SLOT = 2 // per tracker × epoch: parked offers are single-use, 2 lets two dialers land
const OFFER_REFRESH_MS = 120_000 // re-offer (same pc, ICE restart) — SDP stays as fresh as the old code's, free
const CONNECT_TTL_MS = 30_000 // after an answer arrives, reap if the DataChannel never opens (ICE failed)
const MAX_PENDING_OFFERS = 16 // hard cap on simultaneously-parked offers; oldest evicted first
const MAX_LIVE_PCS = 32 // hard cap on RTCPeerConnections this transport owns at once
const MAX_TOTAL_PCS = 480 // hard stop BELOW the browser's ~500-construction wall: degrade, never throw
const PC_CREATE_BURST = 12 // token bucket over listener pc construction: enough to fill every pool slot at once…
const PC_CREATE_PER_MIN = 6 // …then a slow trickle, so answer-spam cannot burn the page's PC budget
const MAX_OFFERS_PER_PUNCH = 3 // a dial answers at most this many parked offers in parallel: a few for
// resilience (a dead parked pc doesn't strand the dial), bounded so a hostile/duplicating tracker can
// neither flood the dialer with answerer PCs nor make one dialer open a burst of connections to a peer.

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
  // `offerTtlMs` kept as an alias so the a84345e test/opts keep working; it drives the re-offer timer.
  const offerRefreshMs = opts.offerRefreshMs || opts.offerTtlMs || OFFER_REFRESH_MS
  const connectTtlMs = opts.connectTtlMs || CONNECT_TTL_MS
  const maxPendingOffers = opts.maxPendingOffers || MAX_PENDING_OFFERS
  const announceIntervalMs = opts.announceIntervalMs || ANNOUNCE_INTERVAL_MS
  const parkedPerSlot = opts.parkedOffersPerSlot || PARKED_OFFERS_PER_SLOT
  const maxLivePcs = opts.maxLivePcs || MAX_LIVE_PCS
  const maxTotalPcs = opts.maxTotalPcs || MAX_TOTAL_PCS
  const createPerMin = opts.pcCreatesPerMin || PC_CREATE_PER_MIN
  const createBurst = opts.pcCreateBurst || PC_CREATE_BURST
  const myPeerId = randId20()

  if (!PC) throw new Error('this browser has no RTCPeerConnection — WebRTC is required')
  if (!WS) throw new Error('this environment has no WebSocket')

  const conns = [] // open tracker sockets
  const live = new Set() // RTCPeerConnections we own (for close())
  let onConnectionCb = null
  let closed = false
  let totalPcs = 0 // BRW-4b: CUMULATIVE constructions this transport made — the browser's real limit

  // BRW-4b: token bucket bounding the RATE of listener PC construction, so a burst of hostile answers
  // (each frees a slot → wants a refill) cannot burn through the page's ~500-construction budget.
  // Dials do NOT draw from it — a user-initiated punch must always be able to build its answering pc.
  let tokens = createBurst
  let lastRefill = now()
  const takeToken = () => {
    const t = now()
    tokens = Math.min(createBurst, tokens + ((t - lastRefill) / 60_000) * createPerMin)
    lastRefill = t
    if (tokens >= 1) { tokens -= 1; return true }
    return false
  }

  // A pc is a scarce, non-reclaimable resource in a real browser (close() does NOT free the object —
  // only an Oilpan GC we can't trigger does). So construction is GATED: never past the cumulative wall,
  // never past the concurrent cap. `rated` = listener refills draw a token; dials pass `rated:false`.
  const newPc = ({ rated = false } = {}) => {
    if (closed) return null
    if (totalPcs >= maxTotalPcs) return null // hard stop below the browser's own throw — degrade, don't crash
    if (live.size >= maxLivePcs) return null
    if (rated && !takeToken()) return null
    const pc = new PC({ iceServers })
    live.add(pc)
    totalPcs++
    return pc
  }
  // FULLY release a pc so Blink can eventually reclaim it: close it AND null every handler we set, so
  // no closure keeps the object (or its DataChannel) reachable. Callers also drop it from pending/pool.
  const freePc = (pc) => {
    if (!pc) return
    try { pc.onicecandidate = pc.oniceconnectionstatechange = pc.onconnectionstatechange = pc.ondatachannel = pc.onnegotiationneeded = null } catch { /* */ }
    try { pc.close() } catch { /* */ }
    live.delete(pc)
  }

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
        const dialPcs = new Set() // every answerer pc this dial built; free the losers when one wins
        const finish = (err, socket, winner) => {
          if (settled) return
          settled = true
          clearTimeout(timer)
          ac.abort()
          for (const h of handles) h.stop()
          for (const pc of dialPcs) if (pc !== winner) freePc(pc) // release the racing-but-lost pcs
          dialPcs.clear()
          err ? reject(err) : resolve(socket)
        }
        const timer = setTimeout(
          () => finish(new Error('webrtc punch: no peer answered within ' + DIAL_TIMEOUT_MS + 'ms')),
          DIAL_TIMEOUT_MS,
        )

        let answered = 0
        const onOffer = async (m, ws) => {
          if (settled) return
          // BRW-4b: a hostile/duplicating tracker can rain parked offers at a dialer; each would mint an
          // answering pc. Bound how many one punch will answer — a real dial needs only a handful.
          if (answered >= MAX_OFFERS_PER_PUNCH) return
          answered++
          const pc = newPc() // NOT rated — a user dial must always be able to build its answerer
          if (!pc) return // at the concurrent/cumulative cap — skip this offer (the dial timer still guards)
          dialPcs.add(pc)
          // The listener created the channel; we receive it.
          pc.ondatachannel = (ev) => {
            const dc = ev.channel
            const deliver = () => { pc.ondatachannel = null; finish(null, socketFromChannel(dc, pc), pc) }
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
      for (const pc of [...live]) freePc(pc) // full release (close + null handlers) so Blink can reclaim
      live.clear()
    },
  }

  // ── LISTENER ────────────────────────────────────────────────────────────────
  /**
   * Stay reachable: hold a SMALL, REUSED pool of parked-offer RTCPeerConnections under rid(S) on
   * every tracker, and answer-match anything that answers. When a DataChannel opens, hand it to
   * node.js's accepter (which sends HELLO, then runs the Noise IK responder).
   *
   * BRW-4b — WHY A POOL AND NOT PER-ANNOUNCE OFFERS: a real browser caps CUMULATIVE
   * `new RTCPeerConnection` at ~500 per page and does not reclaim closed ones without a GC it won't
   * run (measured — see the constants block + test/browser-pc-soak.mjs). So the number of PCs we ever
   * CONSTRUCT must track the number of real CONNECTIONS, not the wall clock. We therefore build a
   * handful of parked-offer PCs ONCE and keep re-publishing THE SAME offers every announce; staleness
   * is refreshed by re-offering ON THE SAME pc (`iceRestart`), which costs zero new PCs. A new pc is
   * constructed only to refill a slot whose offer was actually consumed by a peer (or whose ICE died)
   * — and even those refills pass through a token bucket so answer-spam can't burn the page's budget.
   * Steady-state churn for an idle listener: ZERO new PCs per hour.
   * @param {string} S our own contact string
   */
  function publishAll(S) {
    const pool = new Set() // slots: { pc, dc, offerId, refreshTimer, connectTimer, consumed }
    const parked = new Map() // offer_id -> slot (a currently-parked, still-unanswered offer)
    const targetPool = Math.min(maxPendingOffers, opts.targetParkedOffers || parkedPerSlot * 3)
    let stopped = false
    const wsList = [] // (ws, infoHash) pairs to re-announce the current pool on refresh

    /** Fully retire a slot: stop its timers, unpark its offer, free its pc. */
    const dropSlot = (slot) => {
      if (slot.retired) return
      slot.retired = true
      clearTimeout(slot.refreshTimer)
      clearTimeout(slot.connectTimer)
      if (slot.offerId) parked.delete(slot.offerId)
      pool.delete(slot)
      freePc(slot.pc)
    }

    /** (Re-)create an SDP offer on a slot's EXISTING pc — no new RTCPeerConnection. */
    async function reoffer(slot) {
      if (stopped || closed || slot.consumed || slot.retired) return
      const pc = slot.pc
      const oldId = slot.offerId
      const offerId = randId20()
      try {
        const offer = await pc.createOffer(oldId ? { iceRestart: true } : undefined) // reuse the pc; refresh ICE
        await pc.setLocalDescription(offer)
        await whenIceGathered(pc)
      } catch (err) {
        dropSlot(slot)
        if (!closed) console.warn('[p2p] re-offer failed:', err.message)
        topUp()
        return
      }
      if (stopped || closed || slot.consumed || slot.retired) return
      if (oldId) parked.delete(oldId)
      slot.offerId = offerId
      parked.set(offerId, slot)
      clearTimeout(slot.refreshTimer)
      slot.refreshTimer = setTimeout(() => reoffer(slot), offerRefreshMs)
      slot.refreshTimer.unref?.()
      reannounce() // publish the refreshed offer set on every open tracker
    }

    /** Synchronously reserve+construct one pool slot (rate-limited); kick off its first offer. */
    const startSlot = () => {
      if (stopped || closed || pool.size >= targetPool) return false
      const pc = newPc({ rated: true }) // listener construction is rate-limited (token bucket + caps)
      if (!pc) return false // at the cap / no token — stop topping up for now
      const dc = pc.createDataChannel('p2p', { ordered: true }) // reliable+ordered: SCTP does the ARQ
      const slot = { pc, dc, offerId: null, refreshTimer: null, connectTimer: null, consumed: false, retired: false }
      dc.onopen = () => {
        // Promoted to a LIVE connection: this slot's pc now belongs to the socket (freed at socket.close /
        // node.close), so it leaves the pool WITHOUT being freed here. Refill the freed slot.
        slot.consumed = true
        clearTimeout(slot.refreshTimer)
        clearTimeout(slot.connectTimer)
        if (slot.offerId) parked.delete(slot.offerId)
        pool.delete(slot)
        if (onConnectionCb && !closed) onConnectionCb(socketFromChannel(dc, pc))
        topUp()
      }
      pool.add(slot)
      reoffer(slot) // async; the pc is already in the pool so topUp()'s size check is correct
      return true
    }

    /** Keep the pool full up to targetPool (bounded by the token bucket / caps inside startSlot). */
    function topUp() {
      while (startSlot()) { /* fill until target or the rate/cap gate stops us */ }
    }

    /** Publish the CURRENT parked-offer set on one tracker socket. Creates NO offers. */
    const announce = (ws, infoHash) => {
      const offers = []
      for (const slot of pool) {
        if (slot.offerId && !slot.consumed && !slot.retired && slot.pc.localDescription) {
          offers.push({ offer_id: slot.offerId, offer: { type: 'offer', sdp: slot.pc.localDescription.sdp } })
        }
      }
      if (!offers.length) return
      send(ws, { action: 'announce', info_hash: infoHash, peer_id: myPeerId, numwant: 10, uploaded: 0, downloaded: 0, left: 0, offers })
    }
    const reannounce = () => { for (const { ws, infoHash } of wsList) if (ws && ws.readyState === 1) announce(ws, infoHash) }

    const acceptAnswer = async (m) => {
      const slot = parked.get(m.offer_id)
      if (!slot || slot.consumed || slot.retired) return
      // A real dialer answered this parked offer — it is now single-use-consumed. Unpark it and stop
      // re-offering that pc; it is committing to THIS dialer. Guard with a connect-TTL: if ICE never
      // opens the channel, reclaim the slot (free the pc) and refill — so a failed answer is not a leak.
      parked.delete(m.offer_id)
      slot.offerId = null
      clearTimeout(slot.refreshTimer)
      slot.connectTimer = setTimeout(() => { if (!slot.consumed) { dropSlot(slot); topUp() } }, connectTtlMs)
      slot.connectTimer.unref?.()
      try {
        await slot.pc.setRemoteDescription({ type: 'answer', sdp: m.answer.sdp })
        // -> ICE connects -> dc.onopen -> onConnectionCb (above)
      } catch (err) {
        console.warn('[p2p] failed to accept an answer:', err.message)
        dropSlot(slot)
        topUp()
      }
    }

    const stops = []
    for (const url of trackers) {
      // announce-epochs: today, plus tomorrow shortly before the UTC rollover (no blackout)
      const infoHashes = announceEpochs(now()).map((ep) => infoHashFor(deriveRid(S, 'tracker', ep, 20)))
      for (const infoHash of infoHashes) {
        let timer
        const entry = { ws: null, infoHash }
        wsList.push(entry)
        const h = openTracker(url, {
          persistent: true,
          onOpen: (ws) => {
            entry.ws = ws
            topUp() // make sure the pool is full, then publish it (a keepalive re-announces the SAME offers)
            announce(ws, infoHash)
            clearInterval(timer)
            timer = setInterval(() => { entry.ws = h.ws; announce(h.ws, infoHash) }, announceIntervalMs)
          },
          onMsg: (m) => {
            if (m.answer && m.offer_id && parked.has(m.offer_id)) acceptAnswer(m)
          },
        })
        stops.push(() => { clearInterval(timer); h.stop() })
      }
    }
    topUp() // build the pool immediately (don't wait for the first tracker to open)
    return {
      stop() {
        stopped = true
        for (const s of stops) s()
        for (const slot of [...pool]) dropSlot(slot) // free every parked-offer pc on teardown
      },
      pendingCount: () => parked.size, // BRW-4 leak-monitor hook (test/soak): parked, still-unanswered offers
      poolCount: () => pool.size,
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
    _debug: { liveCount: () => live.size, totalCount: () => totalPcs }, // BRW-4/4b leak-monitor hooks
  }
}

export default { createBrowserTransport, ICE_SERVERS }
