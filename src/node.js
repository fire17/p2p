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

import { randomBytes } from 'node:crypto'
import { createChannel, encodeFrame, decodeFrame, TYPE, HEADER_LEN } from './wire.js'
import { createGroup } from './group.js'
import { parseShare, createInvite, hasInvite, TypoError } from './invite.js'

/** App-layer message kinds (inside the encrypted DATA payload). */
const APP = Object.freeze({ MSG: 1, ACK: 2 })
const ZERO8 = Buffer.alloc(8)
/** Bytes an app payload loses on the way to the wire: app header [1B kind][4B seq] + Noise AEAD tag. */
const APP_HDR = 5
const AEAD_TAG = 16

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
    /** Largest app payload that still fits the wire budget (mtu - wire header - Noise tag - app header). */
    get maxMessage() { return node._mtu - HEADER_LEN - AEAD_TAG - APP_HDR },
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

  /** Bind a freshly-handshaked socket+session; replay any unacked outbox in order. */
  function attach({ socket: sock, tx: txN, rx: rxN, connId, instance }) {
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
    ch = createChannel({ connId, mtu: node._mtu, keepaliveMs: node._keepaliveMs, now: node._now, send: (frame) => socket.send(frame) })
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
    const socket = await node._ep.punch(cands, { token: myConnId })
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
          const { tx, rx } = hs.split()
          rec.attach({ socket, tx, rx, connId: myConnId, instance: peerInstance })
          if (!settled) { settled = true; resolve(rec.peer) }
        } else if (rec.channel()) {
          rec.channel().onDatagram(buf, socket.rinfo)
        }
      }
    })
  })()
}

/** Responder (accepter) side: send HELLO, run IK responder, key peer by remote static. */
function acceptConnection(node, deps, socket) {
  const id = node._identity
  const inv = node._invite || null
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
      const { edPub, xPub, instance } = decodeIntro(payload)         // Bob's pubkeys — TOFU pin + peer key; instance = restart nonce
      const pkey = 'static:' + Buffer.from(xPub).toString('hex')
      rec = node._peers.get(pkey)
      if (!rec) { rec = makePeer(node, {}); node._peers.set(pkey, rec) }
      setPeerIdentity(deps, rec.peer, edPub, xPub)                   // listener learns the DIALER's real 26-char key
      // Attach BEFORE sending HS2: sending HS2 may synchronously drive the dialer to
      // completion and make it reply (e.g. outbox replay) reentrantly — our channel must
      // already be live to receive it. (Real async transport is unaffected; this is the
      // safe order either way.)
      const hs2 = hs.writeMessage(encodeIntro(id.edPub, id.xPub, node._instance))
      const { tx, rx } = hs.split()
      rec.attach({ socket, tx, rx, connId, instance })
      socket.send(encodeFrame(TYPE.HS2, connId, 0, 0, hs2))
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
    _instance: opts.instance || randomBytes(8),   // per-process nonce -> peer-restart discriminator
    _now: opts.now || (() => Date.now()),
    _keepaliveMs: opts.keepaliveMs ?? 25000,
    _mtu: opts.mtu ?? 1200,
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
        if (typeof deps.makeRace !== 'function') throw new Error('p2p: invite-mode dialing needs the real rendezvous stack (no makeRace seam)')
        const r = deps.makeRace(inv)
        for (const c of r.channels || []) node._channels.push(c)     // closed with the node
        return initiatorHandshake(node, deps, S, dec, { resolve: r.resolve, invite: inv })
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
  if (ep && typeof ep.on === 'function') ep.on('netchange', () => { Promise.resolve().then(() => deps.publishAll(identity.S ?? identity.key, ep)).catch(() => {}) })
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
