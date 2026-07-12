// src/node.js — public API + peer lifecycle (v1).
//
// Wires the stack per DESIGN §3 / API-SKETCH:
//   rendezvous.resolve -> transport.punch -> HELLO + commitment-gate -> Noise IK
//   -> wire channel -> app.  connect() resolves ONLY after the IK first-ack (msg2
//   decrypt) — that success IS the MITM proof the owner specified (DESIGN D4).
//
// Reliability has two layers: wire.js gives ordered/exactly-once WITHIN a session;
// node adds an app-level outbox (seq+ack) so buffered sends survive RECONNECTS and
// stay exactly-once across them. Peers are keyed by remote identity (S for the dialer,
// remote static X pubkey for the accepter) so a new socket after a drop RE-ATTACHES to
// the same peer and its outbox/delivered set — not a fresh peer.
//
// Seams (transport/noise/rendezvous/key) are injectable via opts.deps for testing;
// defaults lazy-import the real sibling modules. wire.js is imported directly (owned,
// pure, deterministic). Zero deps, ESM, JSDoc. No crypto here beyond routing Noise.
//
// SEAM NOTE (flagged to main): inbound accept uses ep.onConnection(socketLike) — not yet
// in docs/INTERFACES.md §src/transport.js. Needs main to ratify the seam.

import { hkdfSync, randomBytes } from 'node:crypto'
import { createChannel, encodeFrame, decodeFrame, TYPE, HEADER_LEN, MAC_LEN } from './wire.js'
import { createGroup } from './group.js'
import { parseShare, createInvite, hasInvite, equal, TypoError } from './invite.js'

/** App-layer message kinds (inside the encrypted DATA payload). */
const APP = Object.freeze({ MSG: 1, ACK: 2 })
const ZERO8 = Buffer.alloc(8)

/**
 * DOS-1 — cap the peer records the ACCEPT path may mint. A reusable-S HS1 needs no secret (our
 * static X pubkey is public inside S), so a flooder can complete handshake-shaped msg1s with a
 * fresh static each time and mint an unbounded number of records. Inbound records are counted and
 * capped SEPARATELY from dialed ones, so an inbound flood can never block the user's own connect().
 */
const MAX_INBOUND_PEERS = 256

/**
 * META-1 — the probe proof: HKDF(K_inv, salt="p2p-rvk-probe-v1", info=<token hex>, L=8).
 *
 * The listener's HELLO carries `edPub‖xPub` IN THE CLEAR — the full identity pubkeys that S only
 * COMMITS to. Pre-fix, any well-formed PROBE elicited it, so anyone who reached the socket could
 * harvest the pubkeys, recompute S, and bind IP:port ↔ identity — a confirmation oracle that
 * undercuts invite mode's whole point. In invite mode we now require the prober to PROVE K_inv:
 * only the invitee holds it, so only the invitee ever elicits the HELLO.
 *
 * It rides inside the EXISTING 21-byte PROBE — the proof IS the 8-byte nonce field, keyed to the
 * (random, per-dial) correlation token. No wire change, no new field, no length/shape signal: the
 * nonce was random bytes before and is pseudorandom bytes now. Binding the proof to the token also
 * denies a replaying on-path observer any DoS amplification — a captured (token, proof) pair
 * collapses to the ONE accept that token already owns.
 *
 * Residual, stated: an ON-PATH observer can copy a proof it saw. It gains nothing — the same
 * position already reads the cleartext HELLO it would be trying to elicit. What this closes is the
 * OFF-PATH prober (scanner / infra-collusion address holder), which is exactly META-1's adversary.
 * Reusable-S mode installs no authenticator (S is public by definition — nothing to protect).
 * @param {object} inv createInvite() context @param {Buffer} tok the 8-byte punch token
 */
const probeProof = (inv, tok) => inv.rid('probe', Buffer.from(tok).toString('hex'), 8)
/** Bytes an app payload loses on the way to the wire: app header [1B kind][4B seq] + Noise AEAD tag. */
const APP_HDR = 5
const AEAD_TAG = 16

/**
 * Post-handshake MAC keys for the wire CONTROL PLANE (WIRE-1/2/3 — see wire.js header).
 *
 * The Noise handshake hash `h` is the canonical binding of the whole handshake and is
 * IDENTICAL on both sides after split() — but it is NOT secret-key material, so we run it
 * through HKDF with the split() chaining key's sibling domain separation and derive two
 * INDEPENDENT directional keys. Directional matters: with one shared key, an attacker could
 * reflect our own frames back at us and they would authenticate (re-opening WIRE-3).
 * Fresh per handshake => a captured frame from a previous session can never replay into a
 * new one. Same derivation on both peers, opposite roles => my tx == your rx.
 * @param {Buffer} handshakeHash  from noise split()
 * @param {'initiator'|'responder'} role
 * @returns {{tx:Buffer, rx:Buffer}}
 */
function wireMacKeys(handshakeHash, role) {
  const derive = (info) =>
    Buffer.from(hkdfSync('sha256', handshakeHash, Buffer.alloc(0), Buffer.from(info, 'utf8'), 32))
  const i2r = derive('p2p-wire-mac-v1-i2r')            // initiator -> responder frames
  const r2i = derive('p2p-wire-mac-v1-r2i')            // responder -> initiator frames
  return role === 'initiator' ? { tx: i2r, rx: r2i } : { tx: r2i, rx: i2r }
}

/** Opt-in trace (P2P_DEBUG=1) for first-contact diagnostics — no-op by default. */
const DBG = process.env.P2P_DEBUG ? (...a) => { try { console.error('[p2p]', ...a) } catch { /* */ } } : () => {}

const asBuf = (d) => (typeof d === 'string' ? Buffer.from(d, 'utf8') : Buffer.from(d))

/** App frame: [1B kind][4B seq][payload]. */
function encodeApp(kind, seq, data) {
  const p = data ? asBuf(data) : Buffer.alloc(0)
  const b = Buffer.allocUnsafe(5 + p.length)
  b[0] = kind; b.writeUInt32BE(seq >>> 0, 1); p.copy(b, 5)
  return b
}
function decodeApp(buf) {
  return { kind: buf[0], seq: buf.readUInt32BE(1), data: buf.subarray(5) }
}

/**
 * Length-prefixed [edPub][xPub][instance] used in HELLO / handshake payloads. `instance`
 * is a per-PROCESS nonce (stable across a same-process transport-reconnect, NEW on a fresh
 * restart) — the discriminator that lets the survivor tell "reconnect replay" (keep inbound
 * dedup) from "peer restarted" (reset it, so the restart's reset appSeqs aren't dropped).
 */
function encodeIntro(edPub, xPub, instance) {
  const e = asBuf(edPub), x = asBuf(xPub), i = asBuf(instance)
  const b = Buffer.allocUnsafe(3 + e.length + x.length + i.length)
  b[0] = e.length; e.copy(b, 1)
  b[1 + e.length] = x.length; x.copy(b, 2 + e.length)
  b[2 + e.length + x.length] = i.length; i.copy(b, 3 + e.length + x.length)
  return b
}
function decodeIntro(buf) {
  const el = buf[0]
  const edPub = buf.subarray(1, 1 + el)
  const xl = buf[1 + el]
  const xPub = buf.subarray(2 + el, 2 + el + xl)
  const il = buf[2 + el + xl]
  const instance = il ? buf.subarray(3 + el + xl, 3 + el + xl + il) : Buffer.alloc(0)
  return { edPub: Buffer.from(edPub), xPub: Buffer.from(xPub), instance: Buffer.from(instance) }
}

/**
 * Record the remote's identity on the peer: both pubkeys + its shareable 26-char contact
 * key (so EITHER side can save the other as a friend and redial later). Called before the
 * 'peer' event fires, so handlers can read peer.key immediately.
 */
function setPeerIdentity(deps, peer, edPub, xPub) {
  peer.remoteStatic = Buffer.from(xPub)
  peer.remoteEd = Buffer.from(edPub)
  if (typeof deps.encodeKey === 'function') {
    try { peer.key = deps.encodeKey(edPub, xPub, 0) } catch { /* leave whatever key we had */ }
  }
}

/** Tiny event emitter (zero-dep). */
function emitter() {
  const m = new Map()
  return {
    on(ev, fn) { if (!m.has(ev)) m.set(ev, []); m.get(ev).push(fn); return this },
    off(ev, fn) { const a = m.get(ev); if (a) { const i = a.indexOf(fn); if (i >= 0) a.splice(i, 1) } return this },
    emit(ev, ...a) { const arr = m.get(ev); if (arr) for (const fn of [...arr]) fn(...a) },
  }
}

/**
 * A logical peer. Survives socket/channel replacement (reconnect) — outbox, pending
 * promises and the delivered-dedup set live here, not on the transient channel.
 */
function makePeer(node, { S = null } = {}) {
  const outbox = new Map()        // appSeq -> plaintext Buffer (unacked; replayed on attach)
  const pending = new Map()       // appSeq -> {resolve,reject}
  let delivered = new Set()       // inbound appSeq already delivered (dedup within a peer INSTANCE)
  let appSeqNext = 0
  let peerInstance = null         // remote's per-process nonce; a change => peer restarted
  let ch = null, tx = null, rx = null, socket = null
  let connected = false, established = false

  const peer = {
    S,
    key: S,                 // the remote's shareable 26-char contact string (derived at handshake)
    remoteStatic: null,     // remote X25519 pubkey
    remoteEd: null,         // remote Ed25519 pubkey
    get connected() { return connected },
    /** Largest app payload that still fits the wire budget (mtu - wire header - wire MAC - Noise tag - app header). */
    get maxMessage() { return node._mtu - HEADER_LEN - MAC_LEN - AEAD_TAG - APP_HDR },
    /** @param {Buffer|string} data @returns {Promise<number>} resolves with appSeq on ack, REJECTS on a permanent send error */
    send(data) {
      const buf = asBuf(data)
      // FAIL LOUDLY, NEVER HANG (task #22): an oversized payload makes wire.sendReliable throw. It
      // used to be swallowed in wireSend and the caller's promise never settled — an app-level
      // deadlock. Reject synchronously here (so it also fails while DISCONNECTED, where nothing is
      // ever handed to wire), and reject from the send path below for any other throw.
      const limit = peer.maxMessage
      if (buf.length > limit) {
        return Promise.reject(Object.assign(
          new RangeError(`p2p: message too large: ${buf.length} bytes > ${limit} limit — chunk it before send()`),
          { reason: 'oversize', limit, size: buf.length },
        ))
      }
      const seq = appSeqNext++; outbox.set(seq, buf)
      const p = new Promise((resolve, reject) => pending.set(seq, { resolve, reject }))
      wireSend(APP.MSG, seq, buf)   // queued in outbox if not connected; flushed on attach
      return p
    },
    close() {
      if (ch && !ch.closed) ch.close()
      if (connected) { connected = false; node.emit('disconnect', peer) }
    },
  }

  /** Reject + drop an outbox entry whose send can never succeed (permanent error). */
  function failSend(seq, err) {
    outbox.delete(seq)                               // permanent: never replay it on reconnect
    const w = pending.get(seq)
    if (w) { pending.delete(seq); w.reject(err) }
    node.emit('divergence', peer, { reason: 'send', error: err })
  }

  function wireSend(kind, seq, data) {
    if (!connected || !ch) return false
    try { ch.sendReliable(tx.encrypt(encodeApp(kind, seq, data))); return true }
    catch (err) {
      // A MSG that wire refuses (oversize / closed channel) can never be delivered — surface it to
      // the caller instead of silently dropping the promise on the floor. ACKs stay best-effort.
      if (kind === APP.MSG) failSend(seq, err)
      return false
    }
  }

  function onAppCipher(cipher) {
    let plain
    try { plain = rx.decrypt(cipher) }
    catch (err) { node.emit('divergence', peer, { reason: 'decrypt', error: err }); return }
    const { kind, seq, data } = decodeApp(plain)
    if (kind === APP.MSG) {
      wireSend(APP.ACK, seq, null)                    // ack every MSG (idempotent)
      if (!delivered.has(seq)) { delivered.add(seq); node.emit('message', peer, Buffer.from(data)) }
    } else if (kind === APP.ACK) {
      if (outbox.delete(seq)) {
        const w = pending.get(seq)
        if (w) { pending.delete(seq); w.resolve(seq) }
        node.emit('ack', peer, seq)
      }
    }
  }

  /**
   * Bind a freshly-handshaked socket+session; replay any unacked outbox in order.
   * `mac` = the directional control-plane keys (wireMacKeys) — REQUIRED by createChannel:
   * a channel is never built without an authenticated control plane (WIRE-1/2/3).
   */
  function attach({ socket: sock, tx: txN, rx: rxN, connId, instance, mac }) {
    // Peer RESTART detection: a different per-process instance nonce means the remote is a
    // fresh process with its outbound appSeq reset to 0. Its new low seqs would collide with
    // the dead session's entries in `delivered` and be dropped as dups — so reset inbound
    // dedup. A SAME instance (transport-reconnect of the same process) keeps `delivered` so a
    // genuine outbox-replay retransmit is still deduped (exactly-once across reconnect holds).
    if (instance && instance.length && peerInstance && !instance.equals(peerInstance)) {
      delivered = new Set()
    }
    if (instance && instance.length) peerInstance = instance
    socket = sock; tx = txN; rx = rxN
    ch = createChannel({ connId, mac, mtu: node._mtu, keepaliveMs: node._keepaliveMs, now: node._now, send: (frame) => socket.send(frame) })
    ch.onReliable(onAppCipher)
    ch.onClose(() => { if (connected) { connected = false; node.emit('disconnect', peer) } })
    connected = true
    for (const seq of [...outbox.keys()].sort((a, b) => a - b)) wireSend(APP.MSG, seq, outbox.get(seq))
    if (!established) { established = true; node.emit('peer', peer) }
    else node.emit('reconnect', peer)
  }

  return { peer, attach, channel: () => ch, _outbox: outbox, _delivered: () => delivered }
}

/**
 * Merge injected seams with lazy real defaults. Full injection => no sibling import
 * (tests never touch real modules). Real path: rendezvous is a FACTORY — createRace
 * exports {publishAll,resolve}, NOT bare functions, and its channels come from the
 * createMdns/createDht/createTracker factories. Construct that here.
 * @param {object} inj  injected deps
 * @param {object} opts listen opts (passed to channel/endpoint factories)
 */
async function resolveDeps(inj = {}, opts = {}, invite = null) {
  const need = ['generateIdentity', 'decodeKey', 'verifyCommitment', 'createEndpoint', 'initiator', 'responder', 'resolve', 'publishAll']
  if (need.every((k) => typeof inj[k] === 'function')) {
    // Fully-mocked stack (tests). An invite still needs an invite-scoped rendezvous: honour the
    // makeRace seam if the test provides one, otherwise the injected resolve/publishAll stand.
    if (invite && typeof inj.makeRace === 'function') {
      const r = inj.makeRace(invite)
      return { ...inj, resolve: r.resolve, publishAll: r.publishAll, _channels: r.channels || [] }
    }
    return inj
  }
  const [key, noise, transport, race, mdns, dht, tracker] = await Promise.all([
    import('./key.js'), import('./noise.js'), import('./transport.js'),
    import('./rendezvous/race.js'), import('./rendezvous/mdns.js'),
    import('./rendezvous/dht.js'), import('./rendezvous/tracker.js'),
  ])
  /**
   * Build one rendezvous race, S-mode (inv=null) or INVITE-mode (inv = createInvite(K_inv)).
   * Invite mode changes exactly three things (research/metadata-privacy.md §9/§10, invite.js header):
   * rids come from K_inv (`createRace({invite})`), tracker blobs are AEAD-sealed (`codec`), and the
   * DHT switches from plaintext announce_peer to encrypted BEP44 (`invite`). Pass nothing and every
   * byte is the v0.1.0 reusable-S wire.
   * @param {object|null} inv
   */
  const makeRace = (inv = null) => {
    const rz = opts.rendezvous || {}
    const channels = [
      mdns.createMdns(rz),                                             // LAN broadcast: rid_inv, plaintext TXT (LAN-only; see README)
      dht.createDht(inv ? { ...rz, invite: inv } : rz),
      tracker.createTracker(inv ? { ...rz, codec: inv.codec } : rz),
    ]
    const r = race.createRace({ channels, now: opts.now, invite: inv })
    return { resolve: r.resolve, publishAll: r.publishAll, channels }
  }
  let { resolve, publishAll } = inj
  let channels = []
  if (!resolve || !publishAll) {
    const r = makeRace(invite)
    channels = r.channels
    resolve = resolve || r.resolve
    publishAll = publishAll || r.publishAll
  }
  return {
    generateIdentity: key.generateIdentity, decodeKey: key.decodeKey, verifyCommitment: key.verifyCommitment,
    encodeKey: key.encodeKey,                       // derive a peer's shareable 26-char key from its pubkeys
    createEndpoint: transport.createEndpoint, initiator: noise.initiator, responder: noise.responder,
    makeRace,                                       // per-invite rendezvous factory (dialing an invite builds its own)
    resolve, publishAll, _channels: channels, ...inj,
  }
}

/**
 * Normalise whatever the caller passed as an invite into a createInvite() context.
 * Accepts: an invite context (has .psk), the raw K_inv Buffer, a share string `S-<tail>`, or a bare
 * invite token. null/undefined => reusable-S mode.
 * @param {any} v
 */
function toInvite(v) {
  if (v == null) return null
  if (Buffer.isBuffer(v)) return createInvite(v)
  if (typeof v === 'object' && v.psk) return v                       // already a createInvite() context
  if (typeof v === 'string') {
    const { secret } = parseShare(v.includes('-') ? v : 'X'.repeat(26) + '-' + v)   // bare token => treat as the tail
    if (!secret) throw new TypoError('invite string carries no invite tail')
    return createInvite(secret)
  }
  throw new TypeError('invite must be a share string, an invite token, a K_inv Buffer, or a createInvite() context')
}

/**
 * The Noise prologue used in invite mode, on BOTH sides: invite.js's canonical
 * `handshakePrologue()` — a FIXED, invite-scoped value ("p2p-inv-v1" ‖ HKDF(K_inv,"handshake")) that
 * both sides derive from K_inv alone.
 *
 * Why not the per-rendezvous prologue metadata-privacy.md §5/§10 sketches ("p2p-inv-v1" ‖ rid ‖ epoch):
 * the RESPONDER cannot know which rid the dialer read — it announces under several (channel × epoch)
 * rids, and the prologue is mixed BEFORE msg1 is parsed, so there is nowhere to carry a hint without a
 * wire change. The security property that matters (only a K_inv holder can complete the handshake) is
 * carried by the psk regardless; what is given up is per-rendezvous replay binding, which the psk plus
 * the rid-bound AEAD AD on the sealed blob already cover. (Deviation raised with main and approved;
 * the derivation now lives in invite.js beside the others.)
 * @param {object} inv
 */
const invitePrologue = (inv) => inv.handshakePrologue()

const DEADLINE = Symbol('deadline')

/**
 * Drain a candidate source (async generator | Promise<array> | array) into a bounded
 * array — but DON'T wait for the whole stream to end. Real resolve() streams mDNS at
 * ~1ms yet only ENDS at ~13s (DHT/tracker stragglers); punching must start as soon as a
 * usable candidate lands. Strategy: block for the FIRST candidate (however long discovery
 * takes), then a short grace window for stragglers, then return. Closes the stream on the
 * way out so slow DHT/tracker lookups stop.
 * @param {any} source @param {number} [cap] @param {number} [graceMs]
 */
async function collectCandidates(source, cap = 64, graceMs = 1500) {
  let r = source
  if (r && typeof r.then === 'function') r = await r
  const out = []
  if (r && typeof r[Symbol.asyncIterator] === 'function') {
    const it = r[Symbol.asyncIterator]()
    try {
      const first = await it.next()                       // wait for the first candidate, no deadline
      if (!first.done) {
        out.push(first.value)
        let timer
        const grace = new Promise((res) => { timer = setTimeout(() => res(DEADLINE), graceMs); if (timer.unref) timer.unref() })
        try {
          while (out.length < cap) {
            const nx = await Promise.race([it.next(), grace])
            if (nx === DEADLINE || nx.done) break         // grace elapsed or stream ended -> punch now
            out.push(nx.value)
          }
        } finally { clearTimeout(timer) }
      }
    } finally {
      if (typeof it.return === 'function') { try { await it.return() } catch { /* stop the stream */ } }
    }
  } else if (r && typeof r[Symbol.iterator] === 'function') {
    for (const c of r) { out.push(c); if (out.length >= cap) break }
  } else if (r) { out.push(r) }
  return out
}

/**
 * Initiator (dialer) side: resolve -> punch -> gate HELLO -> IK -> resolve after first-ack.
 * @param {object} [ctx] {resolve, invite} — invite mode dials an invite-scoped rendezvous (rid_inv +
 *   sealed candidates) and runs Noise_IKpsk2. Absent => today's reusable-S path, byte-identical.
 */
function initiatorHandshake(node, deps, S, dec, ctx = {}) {
  const inv = ctx.invite || null
  const resolveFn = ctx.resolve || deps.resolve
  let rec = node._peers.get(S)
  if (!rec) { rec = makePeer(node, { S }); node._peers.set(S, rec) }
  const myConnId = randomBytes(8)

  return (async () => {
    const cands = await collectCandidates(resolveFn(S))   // resolve is a STREAM (async gen) in the real path
    DBG('dial: collected', cands.length, 'candidates -> punch')
    // Per-connect correlation token: collapses transport's 5×-per-dialer onConnection
    // (one per v4/v6 source tuple) to ONE accept. Correlation only, NOT auth (auth stays
    // gate+Noise) — reuse myConnId (already random 8 bytes) as the nonce.
    // META-1: in invite mode the PROBE's nonce field carries the K_inv proof over that token, so
    // the responder answers US and stays dark to everyone else. Reusable-S sends a random nonce
    // exactly as before (byte-identical wire).
    const socket = await node._ep.punch(cands, { token: myConnId, nonce: inv ? probeProof(inv, myConnId) : undefined })
    DBG('dial: punch resolved, socket ready -> awaiting HELLO')
    return new Promise((resolve, reject) => {
      let hs = null, helloSeen = false, settled = false, peerInstance = null
      const fail = (reason, err) => {
        if (settled) return; settled = true
        node.emit('divergence', rec.peer, { reason, error: err })
        try { socket.close() } catch { /* ignore */ }
        reject(Object.assign(new Error(`p2p: ${reason}`), { reason, cause: err }))
      }
      socket.onMessage = (buf) => {
        const f = decodeFrame(buf); if (!f) return
        DBG('dial: recv frame type', f.type)
        if (f.type === TYPE.HELLO && !helloSeen) {
          helloSeen = true
          const { edPub, xPub, instance } = decodeIntro(f.payload)
          if (!deps.verifyCommitment(dec.commitment, edPub, xPub)) return fail('gate')  // NOT auth — cheap prefilter (D4)
          DBG('dial: HELLO gated OK -> send HS1')
          setPeerIdentity(deps, rec.peer, edPub, xPub)   // peer.key === the remote's BARE S (invites are one-time; the durable contact is S)
          peerInstance = instance
          // Invite mode: Noise_IKpsk2 (psk = HKDF(K_inv,"psk")) + the invite-scoped prologue. No
          // invite => neither option is passed and the wire bytes are plain IK, unchanged.
          const noiseOpts = { localX: { pub: node._identity.xPub, priv: node._identity.xPriv }, remoteXPub: xPub }
          if (inv) { noiseOpts.psk = inv.psk; noiseOpts.prologue = invitePrologue(inv) }
          hs = deps.initiator(noiseOpts)
          socket.send(encodeFrame(TYPE.HS1, myConnId, 0, 0, hs.writeMessage(encodeIntro(node._identity.edPub, node._identity.xPub, node._instance))))
        } else if (f.type === TYPE.HS2 && hs) {
          let payload
          try { payload = hs.readMessage(f.payload) }               // decrypt SUCCESS == first ack == MITM proof
          catch (err) { return fail('handshake', err) }             // fail CLOSED
          void payload
          const { tx, rx, handshakeHash } = hs.split()
          // Control-plane keys ride out of the SAME handshake that proves the peer (D4) —
          // so the ARQ/ack/close plane is authenticated from the very first channel frame.
          rec.attach({ socket, tx, rx, connId: myConnId, instance: peerInstance, mac: wireMacKeys(handshakeHash, 'initiator') })
          if (!settled) { settled = true; resolve(rec.peer) }
        } else if (rec.channel()) {
          rec.channel().onDatagram(buf, socket.rinfo)
        }
      }
    })
  })()
}

/**
 * DOS-1 — admission control for the INBOUND peer table. Returns true if a new accept-side record
 * may be minted. When full, shed a record that is provably worthless first — inbound, disconnected,
 * and owing nothing (empty outbox, so no buffered message is lost) — and only refuse if none exists.
 *
 * We REFUSE rather than evict a live peer on purpose: evicting the stalest CONNECTED peer would
 * hand a flooder the power to tear down real sessions, which is a worse capability than the
 * newcomer-refusal it would avoid. Residual, stated honestly: a flooder that keeps 256 handshaked
 * channels alive (it must keepalive each one — wire kills a silent channel at livenessMs) can deny
 * NEW inbound peers. Memory stays bounded, established sessions and outbound dials keep working.
 */
function admitInbound(node) {
  let n = 0
  for (const r of node._peers.values()) if (r._inbound) n++
  if (n < node._maxInbound) return true
  for (const [k, r] of node._peers) {
    if (r._inbound && !r.peer.connected && r._outbox.size === 0) { node._peers.delete(k); return true }
  }
  return false
}

/**
 * v2 BURN — retire a one-time invite the instant its invitee connects (metadata-privacy §7 / §9-v2):
 * the owner's "single connection then the route is gone, no re-use, no trail," at the achievable
 * (operational) layer. Three effects, all in-memory — no persisted state (honest scope: a process
 * restart that re-`listen`s the SAME K_inv re-arms the invite; documented, not hidden):
 *
 *   1. STOP-REPUBLISH. Halt the epoch/netchange re-announce loop (`_publishHandle.stop()`) AND close
 *      the rendezvous channels. Both are needed: `stop()` clears the race's epoch timer + its own
 *      netchange listener, but each tracker connection re-announces on its OWN interval that the
 *      publish handle does not own (tracker.js openConn) — only channel.close() stops those. With
 *      both halted, the sealed record is never refreshed and ages off every surface via native TTL
 *      (trackers/mDNS ~120s; DHT BEP44 ~2h storing-node item TTL — the longest-lived residual, and
 *      network-set, not ours to shorten). See createNode for the third, node-level netchange path.
 *   2. K_inv RETIRE / GO DARK. `_inviteBurned` makes acceptConnection refuse every NEW inbound socket
 *      and the META-1 probe gate stay silent — so a captured/leaked SHARE (which carries K_inv) can no
 *      longer re-open the route, even against a candidate still cached on a not-yet-expired surface.
 *   3. COMPOSE WITH EPOCH ROTATION. Stopping the publish loop also stops the pre-announce/rollover
 *      timer, so a burned invite never rolls its rid to the next epoch.
 *
 * The already-established peer rides its TRANSPORT socket (bound in the accept that burned us), which
 * is untouched by any of the above — burn kills the ROUTE, not the live connection. Fires once, and
 * only in invite mode; reusable-S never burns (its `_inviteBurned` stays false forever).
 */
function burnInvite(node) {
  if (node._inviteBurned) return
  node._inviteBurned = true
  const h = node._publishHandle
  if (h && typeof h.stop === 'function') { try { h.stop() } catch { /* */ } }
  for (const c of node._channels) { if (c && typeof c.close === 'function') { try { c.close() } catch { /* */ } } }
  node._channels = []
}

/** Responder (accepter) side: send HELLO, run IK responder, key peer by remote static. */
function acceptConnection(node, deps, socket) {
  const id = node._identity
  const inv = node._invite || null
  // v2 BURN: once the invitee has connected this listener is DARK — the one-time invite is retired, so
  // a NEW inbound socket (a captured/leaked share re-dialing a still-cached candidate) gets no HELLO
  // and no handshake. The already-established peer rides the transport socket bound in the accept that
  // burned us and is untouched. Reusable-S never burns, so this is a permanent no-op there.
  if (node._inviteBurned) { try { socket.close() } catch { /* */ } return }
  // Invite mode is EXCLUSIVE while it lasts: the responder runs Noise_IKpsk2 only, so a holder of the
  // reusable S who never got K_inv cannot complete the handshake even if it somehow learns our IP
  // (metadata-privacy §10: "success == MITM ruled out AND initiator proven to be the invitee"). The
  // cost, stated: an ordinary reusable-S friend cannot connect to a node while it is listening for an
  // invite. No invite => plain IK, byte-identical to v0.1.0.
  const hs = deps.responder(inv
    ? { localX: { pub: id.xPub, priv: id.xPriv }, psk: inv.psk, prologue: invitePrologue(inv) }
    : { localX: { pub: id.xPub, priv: id.xPriv } })
  let rec = null, hs1seen = false, tries = 0

  // HELLO must RETRANSMIT: onConnection can fire (and this first HELLO go out) before the
  // dialer has finished punch() and installed its onMessage — a non-buffering real socket
  // then drops that HELLO with no recovery, and the dialer waits forever. Resend until HS1
  // arrives (capped, so a dead/duplicate accept doesn't spin). HS1 itself is retransmitted
  // by wire's ARQ once the channel exists — only the pre-handshake HELLO needs this.
  const sendHello = () => { try { socket.send(encodeFrame(TYPE.HELLO, ZERO8, 0, 0, encodeIntro(id.edPub, id.xPub, node._instance))) } catch { /* */ } }
  DBG('accept: onConnection -> sending HELLO')
  sendHello()
  const timer = setInterval(() => {
    if (hs1seen || socket.closed || ++tries >= 8) { clearInterval(timer); return }
    sendHello()
  }, 250)
  if (typeof timer.unref === 'function') timer.unref()

  socket.onMessage = (buf) => {
    const f = decodeFrame(buf); if (!f) return
    DBG('accept: recv frame type', f.type)
    if (f.type === TYPE.HS1 && !rec) {
      hs1seen = true; clearInterval(timer)
      const connId = Buffer.from(f.connId)
      let payload
      try { payload = hs.readMessage(f.payload) }                     // in invite mode a msg1 without the psk fails HERE (fail-closed)
      catch (err) { node.emit('divergence', null, { reason: 'handshake', error: err }); try { socket.close() } catch { /* */ } return }
      // DOS-1: HS1 has now authenticated as far as this handshake CAN (in invite mode that is the
      // psk — real auth; in reusable-S it is only "knows our public static"). Either way the socket
      // leaves the transport's pre-auth pending set, so a flood of never-handshaking PROBEs can
      // never crowd out real peers, and the peer record below is created no earlier than this.
      if (typeof socket.confirm === 'function') socket.confirm()
      const { edPub, xPub, instance } = decodeIntro(payload)         // Bob's pubkeys — TOFU pin + peer key; instance = restart nonce
      const pkey = 'static:' + Buffer.from(xPub).toString('hex')
      rec = node._peers.get(pkey)
      if (!rec) {
        // Bounded inbound table: a reusable-S flooder can mint a fresh static per HS1, so the
        // record count — not the handshake — is what has to be capped. Fail CLOSED for the
        // newcomer; never at the expense of an established peer (see admitInbound).
        if (!admitInbound(node)) {
          node.emit('divergence', null, { reason: 'peer-limit' })
          try { socket.close() } catch { /* */ }
          rec = null
          return
        }
        rec = makePeer(node, {}); rec._inbound = true; node._peers.set(pkey, rec)
      }
      setPeerIdentity(deps, rec.peer, edPub, xPub)                   // listener learns the DIALER's real 26-char key
      // Attach BEFORE sending HS2: sending HS2 may synchronously drive the dialer to
      // completion and make it reply (e.g. outbox replay) reentrantly — our channel must
      // already be live to receive it. (Real async transport is unaffected; this is the
      // safe order either way.)
      const hs2 = hs.writeMessage(encodeIntro(id.edPub, id.xPub, node._instance))
      const { tx, rx, handshakeHash } = hs.split()
      rec.attach({ socket, tx, rx, connId, instance, mac: wireMacKeys(handshakeHash, 'responder') })
      socket.send(encodeFrame(TYPE.HS2, connId, 0, 0, hs2))
      // v2 BURN: a valid invite-mode msg1 (the correct K_inv-derived prologue made hs.readMessage
      // succeed) just completed and we answered — the one-time invite has done its single job. Retire
      // it now: stop-republish on every surface + go dark to any further dial of this K_inv. Fires
      // exactly once; the peer attached above stays live. No invite (reusable-S) => never fires.
      if (inv && !node._inviteBurned) burnInvite(node)
    } else if (rec && rec.channel()) {
      rec.channel().onDatagram(buf, socket.rinfo)
    }
  }
}

function createNode(identity, opts, deps, ep) {
  const em = emitter()
  const node = {
    on: em.on, off: em.off, emit: em.emit,
    _identity: identity, _ep: ep, _peers: new Map(),
    _invite: opts._invite || null,                // live one-time invite (listen({invite})) -> IKpsk2 + rid_inv
    _inviteBurned: false,                         // v2 burn: set once the invitee connects -> listener dark, K_inv retired, stop-republish
    _burnedInvites: new Set(),                    // v2 burn (dialer): K_inv fingerprints already spent -> a re-dial of that share is refused
    _instance: opts.instance || randomBytes(8),   // per-process nonce -> peer-restart discriminator
    _now: opts.now || (() => Date.now()),
    _keepaliveMs: opts.keepaliveMs ?? 25000,
    _mtu: opts.mtu ?? 1200,
    _maxInbound: opts.maxInboundPeers ?? MAX_INBOUND_PEERS,   // DOS-1: bound the accept-side table
    /**
     * find + handshake (first contact or reconnect); resolves after the IK first-ack.
     * Accepts a bare 26-char S (reusable mode — unchanged) OR a one-time invite share string
     * `S-<tail>` (invite mode: rid_inv + sealed candidates + Noise_IKpsk2).
     * @param {string} share
     */
    connect(share) {
      return (async () => {
        const { S, secret } = parseShare(String(share))   // TypoError on a typo'd key or tail — no network
        const dec = deps.decodeKey(S)                     // rejects (TypoError) on checksum/alphabet — no network
        if (!secret && hasInvite(dec.version)) {
          throw new TypoError('this is a one-time invite key — you need the full share string (S-…)')
        }
        const existing = node._peers.get(S)
        if (existing && existing.peer.connected) return existing.peer
        if (!secret) return initiatorHandshake(node, deps, S, dec)   // reusable-S: identical to v0.1.0

        // Invite mode: build a rendezvous scoped to THIS invite (its own rids + sealed codec). It is
        // separate from the node's own listen-side rendezvous, so dialing an invite never disturbs it.
        const inv = createInvite(secret)
        // v2 BURN (dialer single-use): a one-time invite is spent by its first successful connect. A
        // later re-dial of the SAME share string — the captured/leaked-share case — is refused before
        // any network work, so the route cannot be re-opened from this side either. Keyed by the K_inv
        // fingerprint (never by S: two invites Alice mints share her S, so S-keying would cross-burn).
        // A still-CONNECTED peer short-circuits above (returns the live peer), so this only bites a
        // genuine re-dial after the session ended.
        const fp = inv.fp.toString('hex')
        if (node._burnedInvites.has(fp)) throw new TypoError('this one-time invite is already used (burned) — mint a fresh invite')
        if (typeof deps.makeRace !== 'function') throw new Error('p2p: invite-mode dialing needs the real rendezvous stack (no makeRace seam)')
        const r = deps.makeRace(inv)
        for (const c of r.channels || []) node._channels.push(c)     // closed with the node
        const peer = await initiatorHandshake(node, deps, S, dec, { resolve: r.resolve, invite: inv })
        node._burnedInvites.add(fp)                                  // spent — a later connect(share) is now refused
        return peer
      })()
    },
    /** @param {string[]} keys */
    group(keys) { return createGroup(node, keys) },
    /** drive channel timers (resend + keepalive) for every peer. */
    tick(now) { const t = now ?? node._now(); for (const r of node._peers.values()) { const c = r.channel(); if (c) c.tick(t) } },
    peers() { return [...node._peers.values()].map((r) => r.peer) },
    _accept(socket) { acceptConnection(node, deps, socket) },
    _channels: [], _publishHandle: null, _tickTimer: null,
    close() {
      if (node._tickTimer) { clearInterval(node._tickTimer); node._tickTimer = null }
      for (const r of node._peers.values()) r.peer.close()
      const h = node._publishHandle
      if (h && typeof h.stop === 'function') { try { h.stop() } catch { /* */ } }        // stop rendezvous timers
      for (const c of node._channels) { if (c && typeof c.close === 'function') { try { c.close() } catch { /* */ } } }
      if (ep && ep.close) ep.close()
    },
  }
  // Drive every peer channel's timers: RTO resend + keepalive PING + liveness-death.
  // Without this NOTHING fires in production (loopback hid it) — no resend on loss, no
  // keepalive (NAT mapping expires ~30s), no dead-peer detection. 250ms = RTO granularity;
  // wire only PINGs every keepaliveMs internally. unref so it never blocks process exit.
  const tk = setInterval(() => { try { node.tick() } catch { /* */ } }, opts.tickMs ?? 250)
  if (typeof tk.unref === 'function') tk.unref()
  node._tickTimer = tk
  if (ep && typeof ep.onConnection === 'function') ep.onConnection((sock) => node._accept(sock))
  // META-1: invite mode only — make the pubkey-bearing HELLO answer ONLY a prober that can prove
  // K_inv. A scanner reaching this socket now gets silence (not even a PROBE_ACK). Reusable-S
  // installs nothing: S is public, the pubkeys it commits to are not a secret worth gating.
  if (node._invite && ep && typeof ep.probeAuth === 'function') {
    const inv = node._invite
    // v2 BURN: after the invitee connects, the probe gate falls silent — a captured share can no
    // longer even elicit the pubkey-bearing HELLO (META-1) from a retired invite.
    ep.probeAuth((tok, nonce) => !node._inviteBurned && equal(Buffer.from(nonce), probeProof(inv, tok)))
  }
  // Node-level netchange republish. Gated on the burn flag (else a post-burn netchange would
  // re-announce the retired invite and re-open the route — reusable-S never burns, so it re-announces
  // as before). It REPLACES _publishHandle (stops the previous, stores the new) rather than spawning
  // an orphan each time: every race publish handle registers its OWN netchange listener, so discarding
  // handles would leak listeners that keep re-announcing forever — and would survive burn's stop(),
  // defeating stop-republish. One tracked handle means burn's stop() always reaches the live one.
  if (ep && typeof ep.on === 'function') ep.on('netchange', () => {
    if (node._inviteBurned) return
    Promise.resolve().then(() => {
      const prev = node._publishHandle
      if (prev && typeof prev.stop === 'function') { try { prev.stop() } catch { /* */ } }
      node._publishHandle = deps.publishAll(identity.S ?? identity.key, ep)
    }).catch(() => {})
  })
  return node
}

/**
 * Create (or load) this host's identity.
 * @param {{deps?:object}} [opts]
 * @returns {Promise<{S:string,edPub:Buffer,edPriv:Buffer,xPub:Buffer,xPriv:Buffer}>}
 */
export async function identity(opts = {}) {
  const inj = opts.deps || {}
  const gen = inj.generateIdentity || (await import('./key.js')).generateIdentity  // no rendezvous just to keygen
  return gen()
}

/**
 * Go online: bind transport, publish presence in the background (instant-on), accept
 * inbound connections. Returns fast — rendezvous publishing continues async.
 *
 * `opts.invite` (a share string / invite token / K_inv Buffer) switches this node's PRESENCE into
 * one-time-invite mode: candidates are published only under rid_inv = HKDF(K_inv,…) and AEAD-sealed,
 * so nobody but the invitee can even locate — let alone read — the record, and the handshake gains
 * the psk. Omit it and every published byte is the reusable-S v0.1.0 wire.
 * @param {object} id  identity from identity()
 * @param {object} [opts]  {port?, endpoint?, now?, keepaliveMs?, mtu?, invite?, deps?}
 * @returns {Promise<object>} node
 */
export async function listen(id, opts = {}) {
  const invite = toInvite(opts.invite)
  const deps = await resolveDeps(opts.deps || {}, opts, invite)
  const ep = opts.endpoint || await deps.createEndpoint({ port: opts.port })
  const node = createNode(id, { ...opts, _invite: invite }, deps, ep)
  node._channels = deps._channels || []
  try {                                          // instant-on: publishAll returns fast (schedules in bg)
    const h = deps.publishAll(id.S ?? id.key, ep)
    node._publishHandle = h
    if (h && typeof h.then === 'function') h.catch((err) => node.emit('divergence', null, { reason: 'publish', error: err }))
  } catch (err) { node.emit('divergence', null, { reason: 'publish', error: err }) }
  return node
}

export default { identity, listen }
