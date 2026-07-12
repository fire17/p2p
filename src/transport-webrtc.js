// src/transport-webrtc.js — WebRTC DataChannel transport. Implements the SAME endpoint seam as
// src/transport.js and src/transport-wss.js (createEndpoint → ep.punch(cands,{token,signal}) /
// ep.onConnection(cb) → socketLike), so src/node.js consumes it UNCHANGED.
// research/browser-client.md §5 (transport), §5.2 (16KiB chunk limit), §5.4 (STUN), §6.2 (BC-6A).
//
// WHY IT EXISTS: a browser's ONLY P2P primitive is RTCPeerConnection/RTCDataChannel (no raw UDP,
// no listening socket — §5.1). This is the fast, direct path for browser↔browser and, optionally,
// browser↔TUI. It runs on the standard RTCPeerConnection API in both worlds:
//   - browser: the global RTCPeerConnection.
//   - Node: `await import('werift')` INSIDE a try/catch — an OPTIONAL dep, dynamically imported.
//     If it's not installed we throw one clear error and do NOT crash the zero-dep core; a caller
//     that never touches this module never pays for it (BC-6A). Do NOT add werift to
//     package.json "dependencies" — it belongs in optionalDependencies, if anywhere.
//
// SECURITY — the DataChannel is an UNTRUSTED PIPE, exactly like the UDP socket in transport.js and
// the relay in transport-wss.js. There is NO crypto in this file. WebRTC's own DTLS is a redundant
// outer layer we never rely on; src/node.js runs the identical Noise IK handshake + commitment
// gate ON TOP of whatever socketLike we hand it, so confidentiality/authenticity are IDENTICAL to
// the UDP transport's. A DataChannel just happens to also be reliable+ordered for free (SCTP),
// which is why the channel here is a dumb passthrough — no ARQ of our own is needed (§5.3).
//
// SIGNALING IS INJECTED, NOT INVENTED. WebRTC needs an offer/answer exchange over *some* channel
// before ICE can do anything — this module has no opinion on what that channel is and never
// hardcodes a server. `createEndpoint({ signal })` takes a minimal signaling object:
//
//   signal.onOffer(myId, async (offerSdp) => answerSdp)  -> unsubscribe()
//     Registered ONCE per endpoint. Called with an incoming offer aimed at `myId`; must resolve
//     with this endpoint's answer SDP (or throw — e.g. "not listening").
//   signal.signalOffer(remoteId, offerSdp) -> Promise<answerSdp>
//     Called by the dialer (inside punch()) to deliver its offer to `remoteId` and get back the
//     answer. One round trip; ICE is non-trickle (we wait out gathering before signaling once —
//     §ice-gather below — so the injected channel only ever needs to move two SDP blobs).
//
// A real deployment rides this over an existing rendezvous (tracker/WSS — another lane's job).
// `createLocalSignal()` below is a trivial in-process implementation for tests/same-process demos
// ONLY — no network, just a Map of direct function calls (mirrors transport-wss.js exporting its
// own createWssRendezvous alongside createEndpoint).
//
// Candidates here are NOT ICE candidates (those are gathered internally per-connection) — they are
// rendezvous-level addressing, same idea as transport-wss.js's `{proto:'wss',topic}`: just enough
// for a dialer to reach the right signaling mailbox. Shape: `{proto:'webrtc', id}`.
//
// Zero deps in the shipped core. ESM.

/** Free public STUN (no TURN of ours — research/browser-client.md §5.4). Same servers
 * src/transport.js already uses; user-overridable via createEndpoint({iceServers}). */
export const ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun.cloudflare.com:3478' },
]

// Cross-browser-safe DataChannel message size (research §5.2: 16 KiB is the practical ceiling;
// Chromium closes the channel outright well above it). Chat frames are ~1.2KB (mtu default) —
// this is a safety net for anything bigger, not the common case.
const CHUNK = 16000

const rnd = (n) => { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return b }
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')

/** Normalize whatever a DataChannel hands back (ArrayBuffer in a browser, Buffer in werift,
 * string in neither case we produce but tolerate) into bytes we can slice/copy uniformly. */
function toBytes(data) {
  if (typeof data === 'string') return new TextEncoder().encode(data)
  if (data instanceof Uint8Array) return data           // covers Buffer too (Buffer extends Uint8Array)
  return new Uint8Array(data)                            // ArrayBuffer / other ArrayBufferView
}

/** Resolve an RTCPeerConnection constructor: global (browser) first, else werift (Node, optional). */
async function resolveRTC(rtc) {
  if (rtc) return rtc
  if (typeof globalThis.RTCPeerConnection === 'function') return globalThis.RTCPeerConnection
  try {
    const werift = await import('werift')
    if (werift && werift.RTCPeerConnection) return werift.RTCPeerConnection
  } catch { /* not installed — fall through to the error below; core stays zero-dep */ }
  throw new Error('install werift for browser-interop WebRTC: npm i werift')
}

/** Wait for ICE gathering to finish (or time out and proceed with whatever we have) so the
 * SDP we hand to `signal` already embeds every candidate — non-trickle, one round trip, keeps
 * the injected signaling interface to exactly two messages (§header). */
function waitIceComplete(pc, timeoutMs = 4000) {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === 'complete') return resolve()
    let done = false
    const finish = () => { if (done) return; done = true; pc.onicegatheringstatechange = null; clearTimeout(t); resolve() }
    pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') finish() }
    const t = setTimeout(finish, timeoutMs) // partial candidates beat hanging forever
    if (t.unref) t.unref()
  })
}

/** Wait for a DataChannel to reach 'open', abortable — the WebRTC analogue of transport.js's
 * punch() resolving only once a 4-tuple validates. */
function waitOpen(dc, timeoutMs, abortSignal) {
  return new Promise((resolve, reject) => {
    if (dc.readyState === 'open') return resolve()
    let done = false
    const cleanup = () => { clearTimeout(timer); dc.onopen = null; abortSignal?.removeEventListener?.('abort', onAbort) }
    const finish = () => { if (done) return; done = true; cleanup(); resolve() }
    const fail = (e) => { if (done) return; done = true; cleanup(); reject(e) }
    const onAbort = () => fail(new Error('punch aborted'))
    dc.onopen = finish
    const timer = setTimeout(() => fail(new Error('webrtc datachannel open timeout')), timeoutMs)
    if (timer.unref) timer.unref()
    abortSignal?.addEventListener?.('abort', onAbort)
  })
}

/** socketLike over one RTCDataChannel — the src/transport.js seam: send/onMessage/close/closed/
 * rinfo/proto/remote. One pc+dc per punch()/accept, so unlike transport.js's UDP demux there is no
 * 4-tuple ambiguity to correlate — `token` (in punch opts) is accepted but unused here on purpose. */
function makeSocketLike(dc, pc, label) {
  let handler = () => {}
  let closed = false
  let reasm = []
  dc.binaryType = 'arraybuffer'   // browser default is 'blob'; werift ignores the extra prop
  const rinfo = { address: 'webrtc:' + String(label).slice(0, 16), port: 0, family: 4 }

  dc.onmessage = (ev) => {
    const u8 = toBytes(ev.data)
    if (u8.length < 1) return
    const more = u8[0]                  // chunk header: 1 = more chunks follow, 0 = last/only chunk
    reasm.push(Buffer.from(u8.subarray(1)))
    if (!more) {
      const frame = reasm.length === 1 ? reasm[0] : Buffer.concat(reasm)
      reasm = []
      try { handler(frame, rinfo) } catch { /* consumer handler threw */ }
    }
  }
  dc.onclose = () => { closed = true }

  return {
    proto: 'webrtc',
    get remote() { return { ...rinfo } },
    get rinfo() { return { ...rinfo } },
    get closed() { return closed },
    get onMessage() { return (cb) => { handler = typeof cb === 'function' ? cb : (() => {}) } },
    set onMessage(fn) { handler = typeof fn === 'function' ? fn : (() => {}) },
    /** Chunk any payload > CHUNK bytes (research §5.2); reassembled by the peer's onmessage above. */
    send(buf) {
      if (closed) return
      const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf)
      for (let i = 0; i < b.length || i === 0; i += CHUNK) {
        const part = b.subarray(i, i + CHUNK)
        const more = i + CHUNK < b.length ? 1 : 0
        const pkt = Buffer.allocUnsafe(1 + part.length)
        pkt[0] = more
        part.copy(pkt, 1)
        try { dc.send(pkt) } catch { /* channel closed mid-send */ }
        if (!more) break
      }
    },
    close() {
      if (closed) return
      closed = true
      try { dc.close() } catch { /* ignore */ }
      try { pc.close() } catch { /* ignore — may return a Promise (werift); fire-and-forget */ }
    },
  }
}

/**
 * Trivial in-process signaling — tests / same-process demos ONLY (no network at all: two endpoints
 * in one process exchange offer/answer via direct calls through a shared Map). A real deployment
 * injects something backed by an EXISTING rendezvous channel (tracker/WSS — another lane's job);
 * this transport never assumes which, and never invents one of its own.
 */
export function createLocalSignal() {
  const handlers = new Map() // id -> onOffer handler
  return {
    onOffer(id, handler) {
      handlers.set(id, handler)
      return () => { if (handlers.get(id) === handler) handlers.delete(id) }
    },
    async signalOffer(id, offerSdp) {
      const h = handlers.get(id)
      if (!h) throw new Error(`transport-webrtc: no listener for signaling id ${id}`)
      return await h(offerSdp)
    },
  }
}

/**
 * Create a WebRTC endpoint — a drop-in for transport.js's endpoint; src/node.js needs ZERO changes.
 * @param {object} opts
 * @param {{onOffer:Function, signalOffer:Function}} opts.signal  injected signaling channel (required — see header)
 * @param {Array<{urls:string}>} [opts.iceServers]  ICE server list (default: public STUN, no TURN)
 * @param {*} [opts.rtc]  RTCPeerConnection ctor override (tests); default resolves global/werift
 */
export async function createEndpoint({ signal, iceServers = ICE_SERVERS, rtc } = {}) {
  if (!signal || typeof signal.onOffer !== 'function' || typeof signal.signalOffer !== 'function')
    throw new Error('transport-webrtc: opts.signal.{onOffer,signalOffer} required — inject a signaling channel (see file header)')
  const RTCPeerConnection = await resolveRTC(rtc)

  const myId = hex(rnd(16))
  const sockets = new Set()
  let onConnCb = null

  // Listener side: answer an inbound offer aimed at our id. Registered unconditionally (matches
  // node.js calling ep.onConnection right after createNode) — if nobody ever calls onConnection,
  // the handler below rejects every offer, same "not listening — drop" posture as the other
  // two transports.
  const unlisten = signal.onOffer(myId, async (offerSdp) => {
    if (!onConnCb) throw new Error('transport-webrtc: not listening (ep.onConnection not set)')
    const pc = new RTCPeerConnection({ iceServers })
    pc.ondatachannel = (ev) => {
      const dc = ev.channel
      const sock = makeSocketLike(dc, pc, myId)
      sockets.add(sock)
      const fire = () => onConnCb(sock)
      if (dc.readyState === 'open') fire(); else dc.onopen = fire
    }
    await pc.setRemoteDescription({ type: 'offer', sdp: offerSdp })
    const answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    await waitIceComplete(pc)
    return pc.localDescription.sdp
  })

  return {
    /** Rendezvous-level address for THIS endpoint (not ICE candidates — see file header). */
    candidates() { return [{ proto: 'webrtc', id: myId }] },
    onConnection(cb) { onConnCb = cb },
    on() { /* no netchange: ICE renegotiates itself; nothing here for node.js to react to */ },

    /** Dialer side: offer -> (signal round trip) -> answer -> wait for the channel to open.
     * @param {Array} remoteCands  must contain a {proto:'webrtc', id} entry
     * @param {{signal?:AbortSignal, timeout?:number, token?:Buffer|string}} [opts] */
    async punch(remoteCands, { signal: abortSignal, timeout = 15000, token } = {}) {
      void token // no 4-tuple correlation needed — one pc/dc per punch() call, 1:1 by construction
      if (abortSignal?.aborted) throw new Error('punch aborted')
      const cand = (remoteCands || []).find((c) => c && c.proto === 'webrtc' && c.id)
      if (!cand) throw new Error('transport-webrtc: no webrtc candidate ({proto:"webrtc", id} required)')

      const pc = new RTCPeerConnection({ iceServers })
      const dc = pc.createDataChannel('p2p', { ordered: true }) // reliable + ordered (default)
      const sock = makeSocketLike(dc, pc, cand.id)
      sockets.add(sock)

      const offer = await pc.createOffer()
      await pc.setLocalDescription(offer)
      await waitIceComplete(pc)
      const answerSdp = await signal.signalOffer(cand.id, pc.localDescription.sdp)
      await pc.setRemoteDescription({ type: 'answer', sdp: answerSdp })
      await waitOpen(dc, timeout, abortSignal)
      return sock
    },

    close() {
      try { unlisten?.() } catch { /* ignore */ }
      for (const s of sockets) { try { s.close() } catch { /* ignore */ } }
      sockets.clear()
    },
  }
}

export default { createEndpoint, createLocalSignal, ICE_SERVERS }
