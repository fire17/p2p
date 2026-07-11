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
import { createChannel, encodeFrame, decodeFrame, TYPE } from './wire.js'
import { createGroup } from './group.js'

/** App-layer message kinds (inside the encrypted DATA payload). */
const APP = Object.freeze({ MSG: 1, ACK: 2 })
const ZERO8 = Buffer.alloc(8)

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

/** Length-prefixed pubkey pair, used in HELLO / handshake payloads. */
function encodeIdent(edPub, xPub) {
  const e = asBuf(edPub), x = asBuf(xPub)
  const b = Buffer.allocUnsafe(2 + e.length + x.length)
  b[0] = e.length; e.copy(b, 1); b[1 + e.length] = x.length; x.copy(b, 2 + e.length)
  return b
}
function decodeIdent(buf) {
  const el = buf[0]
  const edPub = buf.subarray(1, 1 + el)
  const xl = buf[1 + el]
  const xPub = buf.subarray(2 + el, 2 + el + xl)
  return { edPub: Buffer.from(edPub), xPub: Buffer.from(xPub) }
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
  const delivered = new Set()     // inbound appSeq already delivered (dedup across reconnect)
  let appSeqNext = 0
  let ch = null, tx = null, rx = null, socket = null
  let connected = false, established = false

  const peer = {
    S,
    remoteStatic: null,
    get connected() { return connected },
    /** @param {Buffer|string} data @returns {Promise<number>} resolves with appSeq on ack */
    send(data) {
      const buf = asBuf(data)
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

  function wireSend(kind, seq, data) {
    if (!connected || !ch) return false
    try { ch.sendReliable(tx.encrypt(encodeApp(kind, seq, data))); return true }
    catch { return false }
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
  function attach({ socket: sock, tx: txN, rx: rxN, connId }) {
    socket = sock; tx = txN; rx = rxN
    ch = createChannel({ connId, mtu: node._mtu, keepaliveMs: node._keepaliveMs, now: node._now, send: (frame) => socket.send(frame) })
    ch.onReliable(onAppCipher)
    ch.onClose(() => { if (connected) { connected = false; node.emit('disconnect', peer) } })
    connected = true
    for (const seq of [...outbox.keys()].sort((a, b) => a - b)) wireSend(APP.MSG, seq, outbox.get(seq))
    if (!established) { established = true; node.emit('peer', peer) }
    else node.emit('reconnect', peer)
  }

  return { peer, attach, channel: () => ch, _outbox: outbox, _delivered: delivered }
}

/**
 * Merge injected seams with lazy real defaults. Full injection => no sibling import
 * (tests never touch real modules). Real path: rendezvous is a FACTORY — createRace
 * exports {publishAll,resolve}, NOT bare functions, and its channels come from the
 * createMdns/createDht/createTracker factories. Construct that here.
 * @param {object} inj  injected deps
 * @param {object} opts listen opts (passed to channel/endpoint factories)
 */
async function resolveDeps(inj = {}, opts = {}) {
  const need = ['generateIdentity', 'decodeKey', 'verifyCommitment', 'createEndpoint', 'initiator', 'responder', 'resolve', 'publishAll']
  if (need.every((k) => typeof inj[k] === 'function')) return inj
  const [key, noise, transport, race, mdns, dht, tracker] = await Promise.all([
    import('./key.js'), import('./noise.js'), import('./transport.js'),
    import('./rendezvous/race.js'), import('./rendezvous/mdns.js'),
    import('./rendezvous/dht.js'), import('./rendezvous/tracker.js'),
  ])
  let { resolve, publishAll } = inj
  let channels = []
  if (!resolve || !publishAll) {
    channels = [mdns.createMdns(opts.rendezvous), dht.createDht(opts.rendezvous), tracker.createTracker(opts.rendezvous)]
    const r = race.createRace({ channels, now: opts.now })
    resolve = resolve || r.resolve
    publishAll = publishAll || r.publishAll
  }
  return {
    generateIdentity: key.generateIdentity, decodeKey: key.decodeKey, verifyCommitment: key.verifyCommitment,
    createEndpoint: transport.createEndpoint, initiator: noise.initiator, responder: noise.responder,
    resolve, publishAll, _channels: channels, ...inj,
  }
}

/** Drain a candidate source (async generator | Promise<array> | array) into a bounded array. */
async function collectCandidates(source, cap = 64) {
  let r = source
  if (r && typeof r.then === 'function') r = await r
  const out = []
  if (r && typeof r[Symbol.asyncIterator] === 'function') {
    for await (const c of r) { out.push(c); if (out.length >= cap) break }
  } else if (r && typeof r[Symbol.iterator] === 'function') {
    for (const c of r) { out.push(c); if (out.length >= cap) break }
  } else if (r) { out.push(r) }
  return out
}

/** Initiator (dialer) side: resolve -> punch -> gate HELLO -> IK -> resolve after first-ack. */
function initiatorHandshake(node, deps, S, dec) {
  let rec = node._peers.get(S)
  if (!rec) { rec = makePeer(node, { S }); node._peers.set(S, rec) }
  const myConnId = randomBytes(8)

  return (async () => {
    const cands = await collectCandidates(deps.resolve(S))   // resolve is a STREAM (async gen) in the real path
    const socket = await node._ep.punch(cands, {})
    return new Promise((resolve, reject) => {
      let hs = null, helloSeen = false, settled = false
      const fail = (reason, err) => {
        if (settled) return; settled = true
        node.emit('divergence', rec.peer, { reason, error: err })
        try { socket.close() } catch { /* ignore */ }
        reject(Object.assign(new Error(`p2p: ${reason}`), { reason, cause: err }))
      }
      socket.onMessage = (buf) => {
        const f = decodeFrame(buf); if (!f) return
        if (f.type === TYPE.HELLO && !helloSeen) {
          helloSeen = true
          const { edPub, xPub } = decodeIdent(f.payload)
          if (!deps.verifyCommitment(dec.commitment, edPub, xPub)) return fail('gate')  // NOT auth — cheap prefilter (D4)
          rec.peer.remoteStatic = Buffer.from(xPub)
          hs = deps.initiator({ localX: { pub: node._identity.xPub, priv: node._identity.xPriv }, remoteXPub: xPub })
          socket.send(encodeFrame(TYPE.HS1, myConnId, 0, 0, hs.writeMessage(encodeIdent(node._identity.edPub, node._identity.xPub))))
        } else if (f.type === TYPE.HS2 && hs) {
          let payload
          try { payload = hs.readMessage(f.payload) }               // decrypt SUCCESS == first ack == MITM proof
          catch (err) { return fail('handshake', err) }             // fail CLOSED
          void payload
          const { tx, rx } = hs.split()
          rec.attach({ socket, tx, rx, connId: myConnId })
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
  socket.send(encodeFrame(TYPE.HELLO, ZERO8, 0, 0, encodeIdent(id.edPub, id.xPub)))
  const hs = deps.responder({ localX: { pub: id.xPub, priv: id.xPriv } })
  let rec = null
  socket.onMessage = (buf) => {
    const f = decodeFrame(buf); if (!f) return
    if (f.type === TYPE.HS1 && !rec) {
      const connId = Buffer.from(f.connId)
      let payload
      try { payload = hs.readMessage(f.payload) }
      catch (err) { node.emit('divergence', null, { reason: 'handshake', error: err }); try { socket.close() } catch { /* */ } return }
      const { xPub } = decodeIdent(payload)                          // Bob's static — TOFU pin + peer key
      const pkey = 'static:' + Buffer.from(xPub).toString('hex')
      rec = node._peers.get(pkey)
      if (!rec) { rec = makePeer(node, {}); rec.peer.remoteStatic = Buffer.from(xPub); node._peers.set(pkey, rec) }
      // Attach BEFORE sending HS2: sending HS2 may synchronously drive the dialer to
      // completion and make it reply (e.g. outbox replay) reentrantly — our channel must
      // already be live to receive it. (Real async transport is unaffected; this is the
      // safe order either way.)
      const hs2 = hs.writeMessage(encodeIdent(id.edPub, id.xPub))
      const { tx, rx } = hs.split()
      rec.attach({ socket, tx, rx, connId })
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
    _now: opts.now || (() => Date.now()),
    _keepaliveMs: opts.keepaliveMs ?? 25000,
    _mtu: opts.mtu ?? 1200,
    /** find + handshake (first contact or reconnect); resolves after the IK first-ack. */
    connect(S) {
      return (async () => {
        S = String(S).toUpperCase()
        const dec = deps.decodeKey(S)               // rejects (TypoError) on checksum/alphabet — no network
        const existing = node._peers.get(S)
        if (existing && existing.peer.connected) return existing.peer
        return initiatorHandshake(node, deps, S, dec)
      })()
    },
    /** @param {string[]} keys */
    group(keys) { return createGroup(node, keys) },
    /** drive channel timers (resend + keepalive) for every peer. */
    tick(now) { const t = now ?? node._now(); for (const r of node._peers.values()) { const c = r.channel(); if (c) c.tick(t) } },
    peers() { return [...node._peers.values()].map((r) => r.peer) },
    _accept(socket) { acceptConnection(node, deps, socket) },
    _channels: [], _publishHandle: null,
    close() {
      for (const r of node._peers.values()) r.peer.close()
      const h = node._publishHandle
      if (h && typeof h.stop === 'function') { try { h.stop() } catch { /* */ } }        // stop rendezvous timers
      for (const c of node._channels) { if (c && typeof c.close === 'function') { try { c.close() } catch { /* */ } } }
      if (ep && ep.close) ep.close()
    },
  }
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
 * @param {object} id  identity from identity()
 * @param {object} [opts]  {port?, endpoint?, now?, keepaliveMs?, mtu?, deps?}
 * @returns {Promise<object>} node
 */
export async function listen(id, opts = {}) {
  const deps = await resolveDeps(opts.deps || {}, opts)
  const ep = opts.endpoint || await deps.createEndpoint({ port: opts.port })
  const node = createNode(id, opts, deps, ep)
  node._channels = deps._channels || []
  try {                                          // instant-on: publishAll returns fast (schedules in bg)
    const h = deps.publishAll(id.S ?? id.key, ep)
    node._publishHandle = h
    if (h && typeof h.then === 'function') h.catch((err) => node.emit('divergence', null, { reason: 'publish', error: err }))
  } catch (err) { node.emit('divergence', null, { reason: 'publish', error: err }) }
  return node
}

export default { identity, listen }
