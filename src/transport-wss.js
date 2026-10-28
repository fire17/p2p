// src/transport-wss.js — the ZERO-DEP universal transport floor: our Noise ciphertext over a
// public MQTT-over-WSS relay. Implements the SAME endpoint seam as src/transport.js
// (createEndpoint → ep.punch(cands,{token}) / ep.onConnection(cb) → socketLike), so src/node.js
// consumes it UNCHANGED. research/browser-client.md §6.3 (BC-6b) — DESIGN D8's ladder floor.
//
// WHY IT EXISTS: a browser can never speak UDP, and a symmetric↔symmetric NAT pair can never
// hole-punch. Both Node ≥22 and every browser DO have a native global WebSocket. A public relay
// that both sides dial OUT to therefore traverses every NAT with no WebRTC, no STUN, no TURN, no
// dependency and NO SERVER OF OURS. It is what makes browser↔TUI interop unconditional.
//
// SECURITY — the relay is a BLIND, HOSTILE PIPE, exactly like a tracker (research §8/§9 step 5):
//   • it sees an opaque topic = HKDF(S,"p2p-rv-wss-v1",epoch,20) — a non-holder of the 130-bit S
//     can neither compute nor invert it;
//   • it sees our Noise AEAD frames — it cannot read (ChaCha20-Poly1305), forge (Poly1305 tag),
//     replay (strictly-increasing Noise nonce) or MITM (no committed static X25519 scalar ⇒ it
//     cannot produce a msg2 the initiator decrypts; node.js fails CLOSED on tag failure).
// node.js runs the identical HELLO → commitment-gate → Noise IK over this transport as over UDP,
// so confidentiality/authenticity are IDENTICAL to the TUI's. What differs: latency, and the
// relay operator sees the contact graph within an epoch — the same exposure a tracker already has
// (DESIGN §3). ⇒ ANY public relay works; we ship a list and trust none of them.
//
// PROTOCOL: MQTT 3.1.1, QoS 0 (~110 LOC below) — public brokers speak it over WSS for free.
// Live-probed 2026-07-12 from Node's native WebSocket: broker.emqx.io ✅, test.mosquitto.org ✅,
// broker.hivemq.com ✗ (timeout). Their ToS says "do not rely on it for anything of importance" —
// hence: fan out across relays, expect failure, and keep this as the FLOOR under WebRTC.
//
// Zero deps. Node ≥22 (global WebSocket) and browsers (native WebSocket + the Buffer shim).

import { deriveRid } from './key.js'

/** Public MQTT-over-WSS relays (live-probed 2026-07-12). Untrusted by construction — see header. */
export const RELAYS = [
  'wss://broker.emqx.io:8084/mqtt',
  'wss://test.mosquitto.org:8081/mqtt',
]

const VER = 1
const ENV_HDR = 1 + 16 + 8 // [1B ver][16B senderId][8B msgId]
const NS = 'p2p1/'
const DAY_MS = 86400000
const EPOCH_ROLL_MS = 3_600_000 // re-derive the listener inbox topics hourly (see the EPOCH ROLL note below)

// DOS-1-WSS: the relay is a GUARANTEED on-path attacker — it can inject unlimited PUBLISHes with
// fresh attacker-chosen 16-byte senderIds, each spawning a socketLike + (via onConnCb) a node
// peer-record pre-auth. Bound the accepted set (cap + idle-evict) and rate-limit new accepts so a
// flood cannot grow `accepted` — or the node records it triggers — without bound (wargame §10.3).
const MAX_ACCEPTED = 1024     // cap concurrently-tracked inbound peers
const ACCEPT_IDLE_MS = 60_000 // idle-evict an accepted socket silent this long
const ACCEPT_RATE = 20        // sustained new-accept rate (per second, token-bucket refill)
const ACCEPT_BURST = 40       // burst cap on new accepts
const IDLE_SWEEP_MS = 30_000  // idle-sweep cadence

const rnd = (n) => { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return b }
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('')

/** UTC-day epoch string — identical to rendezvous/race.js epochStr. */
export const epochStr = (ms) => new Date(ms).toISOString().slice(0, 10)

/** The relay topic a peer holding contact string S listens on for a given UTC-day epoch. */
export const topicFor = (S, epoch) => NS + deriveRid(S, 'wss', epoch, 20).toString('hex')

// ── minimal MQTT 3.1.1 client (QoS 0: no acks, no retain, no will) ───────────────────────────

const enc = new TextEncoder()
const dec = new TextDecoder()

function remlen(n) {
  const o = []
  do { let b = n % 128; n = Math.floor(n / 128); if (n > 0) b |= 0x80; o.push(b) } while (n > 0)
  return o
}
const packet = (type, flags, body) => Uint8Array.from([(type << 4) | flags, ...remlen(body.length), ...body])
const mstr = (s) => { const b = enc.encode(s); return [b.length >> 8, b.length & 255, ...b] }

/** Split a WS chunk into MQTT packets; QoS-0 PUBLISH bodies are [2B topiclen][topic][payload]. */
function parse(buf) {
  const out = []
  let i = 0
  while (i < buf.length) {
    const type = buf[i] >> 4
    let mult = 1, len = 0, j = i + 1, b
    do { b = buf[j++]; len += (b & 127) * mult; mult *= 128 } while (b & 0x80)
    const body = buf.subarray(j, j + len)
    if (type === 3) {
      const tl = (body[0] << 8) | body[1]
      out.push({ type, topic: dec.decode(body.subarray(2, 2 + tl)), payload: body.subarray(2 + tl) })
    } else out.push({ type })
    i = j + len
  }
  return out
}

// ── relay redial policy + process-wide socket accounting ─────────────────────────────────────
// THE WINDOWS JOINER LEAK (2026-10-28, bun 1.4.2 win32: one joiner held 15,948 TCP sockets — 13,371
// Bound + 2,596 CloseWait — and exhausted the PC's ephemeral ports, WSAENOBUFS). Root cause was HERE:
// `down` was wired to BOTH ws.onerror and ws.onclose, and every failed or reset connection fires BOTH.
// So each failure armed TWO reconnect timers, each of which replaced `ws` with a fresh socket while the
// one it overwrote was never closed (its handlers still armed it to redial). Every network hiccup
// therefore DOUBLED the relay sockets — 1, 3, 7, 15, 31, 63 … every 2s while a relay was unreachable,
// on node AND bun — and every orphan the broker later hung up on sat in CloseWait because nothing
// ever closed it. A flaky network fed the loop, the loop broke the network: a positive feedback.
//
// The fix: ONE socket per relay at a time, owned by a generation check (a stale socket's events are
// ignored except for accounting), the old socket is always closed with its handlers detached before
// a redial, ONE retry timer (cleared before re-arming), exponential backoff with jitter and a 60s
// ceiling (reset only after a link stayed up), a connect deadline (a socket stuck CONNECTING is torn
// down, not abandoned), and a dead-link check on the keepalive (a broker that vanished without a FIN
// is noticed instead of held forever).
const BACKOFF_MIN_MS = 2000
const BACKOFF_MAX_MS = 60000
const STABLE_MS = 30000           // a link that lived this long resets the backoff
const CONNECT_TIMEOUT_MS = 15000  // CONNECT → CONNACK deadline
const PING_MS = 30000             // MQTT PINGREQ cadence (keepalive 60s in CONNECT)
const DEAD_MS = 95000             // nothing heard for ~3 pings → the link is dead; redial

// Process-wide: every relay WebSocket this module constructs, and how many have not yet reported
// close. The joiner's socket guard (bin/lib.js createSocketGuard) reads this — it is the in-process
// truth on runtimes where process.getActiveResourcesInfo() is empty (bun).
const stats = { made: 0, open: 0 }
/** @returns {{made:number, open:number}} relay sockets ever constructed / not yet closed */
export const relayStats = () => ({ made: stats.made, open: stats.open })

/**
 * One relay connection: auto-reconnects, replays its subscriptions, never throws outward.
 * sub() returns a promise that settles on the broker's SUBACK — the dialer MUST await that before
 * it knocks, or the listener's HELLO (retransmitted for only ~2s by node.js) can land on a topic
 * nobody is subscribed to yet, and the dial hangs until a retry happens to line up. Observed live:
 * without this, first-contact took ~13s; with it, ~1s.
 */
function relayConn(url, WS, onPublish, {
  backoffMinMs = BACKOFF_MIN_MS, backoffMaxMs = BACKOFF_MAX_MS, connectTimeoutMs = CONNECT_TIMEOUT_MS,
} = {}) {
  const subs = new Set()
  const queue = []
  const subWaiters = []                                       // FIFO — one SUBACK per SUBSCRIBE
  let ws = null, ready = false, ping = null, closed = false
  let retry = null, connTimer = null, backoff = backoffMinMs, upAt = 0, lastRx = 0

  const raw = (u8) => { try { ws?.send(u8) } catch { /* relay hiccup */ } }
  const doSub = (t) => raw(packet(8, 2, [0, 1, ...mstr(t), 0]))

  /** Drop the CURRENT socket completely: timers, handlers (bar close accounting), the OS handle. */
  const teardown = () => {
    clearInterval(ping); ping = null
    clearTimeout(connTimer); connTimer = null
    ready = false; upAt = 0
    const old = ws
    ws = null
    if (!old) return
    old.onopen = null; old.onmessage = null; old.onerror = null   // onclose stays: it only accounts
    try { old.close() } catch { /* already closing */ }
  }
  /** Exactly one redial, after backoff. Idempotent: a second call while one is armed re-arms it. */
  const down = () => {
    const lived = upAt ? Date.now() - upAt : 0
    teardown()
    if (closed) return
    if (lived >= STABLE_MS) backoff = backoffMinMs
    const delay = Math.round(backoff * (0.75 + Math.random() * 0.5))   // jitter: relays must not see a herd
    backoff = Math.min(backoffMaxMs, backoff * 2)
    clearTimeout(retry)
    retry = setTimeout(open, delay)
    retry.unref?.()
  }

  function open() {
    retry = null
    if (closed || ws) return
    let me
    try { me = new WS(url, 'mqtt') } catch { down(); return }
    stats.made++; stats.open++
    let counted = true
    ws = me
    me.binaryType = 'arraybuffer'
    me.onopen = () => {
      if (me !== ws) return
      raw(packet(1, 0, [...mstr('MQTT'), 4, 2, 0, 60, ...mstr('p2p' + hex(rnd(6)))]))
    }
    me.onmessage = (ev) => {
      if (me !== ws) return
      lastRx = Date.now()
      let pkts
      try { pkts = parse(new Uint8Array(ev.data)) } catch { return }
      for (const p of pkts) {
        if (p.type === 2) {                                   // CONNACK
          if (ready) continue
          ready = true; upAt = Date.now()
          clearTimeout(connTimer); connTimer = null
          for (const t of subs) doSub(t)
          while (queue.length) { const [t, b] = queue.shift(); raw(packet(3, 0, [...mstr(t), ...b])) }
          clearInterval(ping)
          ping = setInterval(() => {
            if (me !== ws) return
            if (Date.now() - lastRx > DEAD_MS) { down(); return }   // half-open: the broker is gone
            raw(packet(12, 0, []))
          }, PING_MS)
          ping.unref?.()
        } else if (p.type === 9) {                            // SUBACK
          subWaiters.shift()?.()
        } else if (p.type === 3) onPublish(p.topic, p.payload)
      }
    }
    me.onerror = () => { if (me === ws) down() }
    me.onclose = () => {
      if (counted) { counted = false; stats.open-- }
      if (me === ws) down()                                   // a stale socket's close only accounts
    }
    connTimer = setTimeout(() => { if (me === ws && !ready) down() }, connectTimeoutMs)
    connTimer.unref?.()
  }
  open()

  return {
    get ready() { return ready },
    /** @returns {Promise<boolean>} resolves true on SUBACK, false if this relay never came up */
    sub(t) {
      subs.add(t)
      return new Promise((resolve) => {
        const waiter = () => { clearTimeout(timer); resolve(true) }
        const timer = setTimeout(() => {
          const i = subWaiters.indexOf(waiter)
          if (i >= 0) subWaiters.splice(i, 1)                  // a timed-out waiter must not pile up
          resolve(false)
        }, 6000)
        timer.unref?.()
        subWaiters.push(waiter)
        if (ready) doSub(t)                                    // else: replayed on CONNACK
      })
    },
    /** Stop replaying `t` on reconnect (no UNSUBSCRIBE packet — see the EPOCH ROLL note). */
    forget(t) { subs.delete(t) },
    pub(t, bytes) {
      if (!ready) { if (queue.length < 64) queue.push([t, bytes]); return }
      raw(packet(3, 0, [...mstr(t), ...bytes]))
    },
    close() { closed = true; clearTimeout(retry); retry = null; teardown() },
  }
}

// ── endpoint (the src/transport.js seam, over a relay) ────────────────────────────────────────

/**
 * A WSS-relay endpoint — a drop-in for transport.js's endpoint; src/node.js needs ZERO changes.
 *
 * Addressing: there are no IPs here. A peer is reached at its rid TOPIC (derived from its S), and
 * every dial carries a fresh 16-byte session id whose own topic is the reply address. Inbound is
 * routed BY TOPIC — a dial's replies land on that dial's private topic, so a dial is never
 * mistaken for an inbound accept.
 *
 * @param {object} opts
 * @param {string} [opts.S]        MY contact string — subscribes my inbox topic so peers can dial
 *                                 me. Omit for a dial-only endpoint.
 * @param {string[]} [opts.relays] relay URLs (default RELAYS); all are used, inbound is deduped.
 * @param {*} [opts.WebSocket]     WebSocket ctor (default: global). Injectable for tests.
 * @param {()=>number} [opts.now]  clock
 * @param {number} [opts.epochRollMs] how often the listener re-derives its inbox topics (see EPOCH ROLL)
 */
export function createEndpoint({
  S = null, relays = RELAYS, WebSocket: WS = globalThis.WebSocket, now = () => Date.now(),
  maxAccepted = MAX_ACCEPTED, acceptIdleMs = ACCEPT_IDLE_MS, acceptRate = ACCEPT_RATE,
  acceptBurst = ACCEPT_BURST, idleSweepMs = IDLE_SWEEP_MS, epochRollMs = EPOCH_ROLL_MS,
  backoffMinMs, backoffMaxMs, connectTimeoutMs,
} = {}) {
  if (!WS) throw new Error('transport-wss: no WebSocket (need Node >= 22 or a browser)')

  const myId = rnd(16)                  // sender id for sockets we ACCEPT
  const accepted = new Map()            // senderHex -> socketLike   (inbound)
  const dials = new Map()               // my dial topic -> socketLike (outbound)
  const seen = new Set(); const seenQ = []   // msgId dedup (we fan out across relays => dupes)
  let onConnCb = null

  const dup = (mid) => {
    if (seen.has(mid)) return true
    seen.add(mid); seenQ.push(mid)
    if (seenQ.length > 4096) seen.delete(seenQ.shift())
    return false
  }

  // ── DOS-1-WSS accept guards ───────────────────────────────────────────────────────────────
  let tokens = acceptBurst, lastRefill = now()
  const allowNewAccept = () => {                              // token bucket over new-sender accepts
    const t = now()
    tokens = Math.min(acceptBurst, tokens + ((t - lastRefill) / 1000) * acceptRate)
    lastRefill = t
    if (tokens < 1) return false
    tokens -= 1
    return true
  }
  const evictAccept = (sender) => {
    const s = accepted.get(sender)
    if (!s) return
    accepted.delete(sender)
    try { s.close() } catch { /* */ }
  }
  const evictMostIdle = () => {                               // shed the stalest inbound to admit a newcomer
    let oldK = null, oldT = Infinity
    for (const [k, s] of accepted) if (s.lastSeen < oldT) { oldT = s.lastSeen; oldK = k }
    if (oldK == null) return false
    evictAccept(oldK)
    return true
  }
  const sweep = setInterval(() => {
    const t = now(), stale = []
    for (const [k, s] of accepted) if (t - s.lastSeen > acceptIdleMs) stale.push(k)
    for (const k of stale) evictAccept(k)
  }, idleSweepMs)
  sweep.unref?.()

  const inbound = (topic, payload) => {
    if (payload.length < ENV_HDR || payload[0] !== VER) return
    const sender = hex(payload.subarray(1, 17))
    if (dup(hex(payload.subarray(17, 25)))) return              // same frame, second relay
    const frame = Buffer.from(payload.subarray(ENV_HDR))

    const dial = dials.get(topic)                              // a reply to one of MY dials
    if (dial) { dial.lastSeen = now(); dial._emit(frame, dial.rinfo); return }

    let sock = accepted.get(sender)                            // inbound first contact
    if (!sock) {
      if (!onConnCb) return                                    // not listening — drop
      if (!allowNewAccept()) return                            // rate-limit fresh senderIds
      if (accepted.size >= maxAccepted && !evictMostIdle()) return   // full & all active — shed newcomer
      sock = socketLike(myId, NS + sender, sender, () => accepted.delete(sender))
      accepted.set(sender, sock)
      onConnCb(sock)                                           // node.js installs .onMessage here
    }
    sock.lastSeen = now()
    sock._emit(frame, sock.rinfo)
  }

  const conns = relays.map((u) => relayConn(u, WS, inbound, { backoffMinMs, backoffMaxMs, connectTimeoutMs }))
  const subAll = (t) => conns.forEach((c) => c.sub(t))
  const pubAll = (t, b) => conns.forEach((c) => c.pub(t, b))

  const topics = []
  const subEpochs = () => {                                    // listener inbox: prev/cur/next UTC day
    const t = now()
    for (const e of [epochStr(t - DAY_MS), epochStr(t), epochStr(t + DAY_MS)]) {
      const top = topicFor(S, e)
      if (!topics.includes(top)) { subAll(top); topics.push(top) }
    }
  }

  // EPOCH ROLL (fixed 2026-09-13): these topics used to be derived ONCE, at endpoint creation. A
  // dialer always knocks topicFor(S, epochStr(now)) — so a `tunnel listen` daemon still alive two
  // UTC midnights later held NO subscription for the day being knocked on, and was unreachable over
  // the relay by any NEW dial (the MIND's listeners run for days). Re-derive prev/cur/next on a
  // timer and SUBSCRIBE whatever is new. Old topics stay subscribed on purpose: this MQTT client
  // implements no UNSUBSCRIBE packet, and the growth is one 20-byte topic per UTC day per listener.
  // Wire format is untouched — SUBSCRIBE packets only, so a v0.3.6 dialer is unaffected.
  let roll = null
  if (S) {
    subEpochs()
    roll = setInterval(() => { try { subEpochs() } catch { /* never throw from a timer */ } }, epochRollMs)
    roll.unref?.()
  }

  /**
   * @param {Uint8Array} senderId  the id we stamp on outbound envelopes (our reply address)
   * @param {string} replyTopic    where our frames are published
   * @param {string} label         for rinfo/debug
   */
  function socketLike(senderId, replyTopic, label, onClose) {
    let handler = () => {}
    let closed = false
    const rinfo = { address: 'wss:' + label.slice(0, 12), port: 0, family: 4 }
    return {
      proto: 'wss',
      remote: { ...rinfo },
      rinfo,
      lastSeen: now(),                                         // DOS-1-WSS: idle-evict clock
      get closed() { return closed },
      set onMessage(fn) { handler = typeof fn === 'function' ? fn : (() => {}) },
      get onMessage() { return (cb) => { handler = typeof cb === 'function' ? cb : (() => {}) } },
      send(buf) {
        if (closed) return
        const b = new Uint8Array(buf)
        const env = new Uint8Array(ENV_HDR + b.length)
        env[0] = VER
        env.set(senderId, 1)
        env.set(rnd(8), 17)                                    // msgId — cross-relay dedup key
        env.set(b, ENV_HDR)
        pubAll(replyTopic, env)
      },
      close() { if (closed) return; closed = true; try { onClose?.() } catch { /* */ } }, // deferred map-cleanup
      _emit(frame, ri) { try { handler(frame, ri) } catch { /* consumer threw */ } },
    }
  }

  return {
    topics,
    _debug: { acceptedCount: () => accepted.size, dialsCount: () => dials.size, rollActive: () => roll !== null, relayStats }, // DOS-1-WSS leak-monitor hook + epoch-roll probe
    candidates() { return S ? [{ proto: 'wss', topic: topicFor(S, epochStr(now())), relays }] : [] },
    async stun() { return { ip: 'wss', port: 0 } },             // the relay IS the reflexive address
    onConnection(cb) { onConnCb = cb },
    on() { /* no netchange: both sides dial OUT and reconnect themselves */ },

    /**
     * "Punch" a relay path — nothing to punch: both sides dial out. Register a private reply
     * topic, hand back a live socketLike, and let node.js drive HELLO → gate → IK over it exactly
     * as it does over UDP.
     * @param {Array<{proto:string, topic?:string}>} cands
     */
    async punch(cands) {
      const c = (cands || []).find((x) => x && x.proto === 'wss' && x.topic)
      if (!c) throw new Error('transport-wss: no wss candidate ({proto:"wss", topic} required)')
      const dialId = rnd(16)                                   // this dial's private reply address
      const myDialTopic = NS + hex(dialId)
      const sock = socketLike(dialId, c.topic, hex(dialId), () => {         // no dial-map leak
        dials.delete(myDialTopic)
        for (const cn of conns) cn.forget(myDialTopic)                     // nor a replayed dead topic
      })
      dials.set(myDialTopic, sock)
      // Await the FIRST broker's SUBACK before making any noise: the listener answers a knock with
      // a HELLO that node.js retransmits for only ~2s, so our reply topic must already be live.
      // Race, don't wait-all — one slow/dead broker in the pool must not stall first contact
      // (waiting on all of them cost ~6s of dead time; racing makes a dial ~1s).
      await new Promise((resolve) => {
        let done = false
        const finish = () => { if (!done) { done = true; resolve() } }
        for (const cn of conns) cn.sub(myDialTopic).then((ok) => ok && finish())
        setTimeout(finish, 6000).unref?.()                     // no relay came up — knock anyway
      })

      // THE KNOCK — the relay analogue of transport.js's PROBE burst. node.js's dialer waits for
      // the listener's HELLO, and the listener only speaks once ep.onConnection fires — which only
      // happens when a frame from us reaches its topic. So the dial must make the first noise.
      // KNOCK is a 1-byte runt: wire.decodeFrame() returns null below HEADER_LEN (17B), so
      // node.js ignores it — it exists purely to materialise the inbound socket on the far side.
      // Repeat it (relay SUBSCRIBEs are not instant, brokers are best-effort) until the listener
      // answers; stop on the first inbound frame.
      const KNOCK = new Uint8Array([0])
      let knocks = 0
      const iv = setInterval(() => { if (sock.closed || ++knocks > 12) clearInterval(iv); else sock.send(KNOCK) }, 500)
      iv.unref?.()
      const emit = sock._emit
      sock._emit = (frame, ri) => { clearInterval(iv); emit(frame, ri) }   // answered — stop knocking
      sock.send(KNOCK)
      return sock
    },

    close() {
      clearInterval(sweep)
      if (roll) { clearInterval(roll); roll = null }            // EPOCH ROLL: stop re-subscribing
      for (const c of conns) c.close()
      for (const s of [...accepted.values(), ...dials.values()]) s.close()
    },
  }
}

/**
 * Rendezvous seam for node.js's deps: over a relay there is nothing to "publish" — presence IS the
 * subscription the endpoint already holds. resolve(S) simply derives the peer's topic.
 * @param {{relays?:string[], now?:()=>number}} [opts]
 */
export function createWssRendezvous({ relays = RELAYS, now = () => Date.now() } = {}) {
  return {
    publishAll() { return { stop() {} } },
    resolve(S) {
      const t = now()
      return [epochStr(t), epochStr(t + DAY_MS)]
        .filter((e, i, a) => a.indexOf(e) === i)
        .map((e) => ({ proto: 'wss', topic: topicFor(S, e), relays }))
    },
  }
}

export default { createEndpoint, createWssRendezvous, RELAYS, topicFor, epochStr, relayStats }
