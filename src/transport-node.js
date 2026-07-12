// src/transport-node.js — the TUI/CLI's RACED transport: UDP/ICE + WSS-relay, behind the one
// endpoint seam src/node.js already injects (createEndpoint → punch/onConnection → socketLike).
// The node-side mirror of src/browser/transport.js, sharing its composite (src/compose.js).
//
// WHY IT EXISTS — tui↔web could not connect AT ALL. The TUI's node stood up ONLY the UDP endpoint
// (src/transport.js); the browser can only speak WebRTC or the WSS relay (src/browser/transport.js).
// A browser has no UDP socket and the TUI never opened the relay, so the two had NO transport in
// common and could never meet, however well rendezvous worked. Composing the relay in on the node
// side is what closes that — it is the same universal floor the browser already stands on:
//
//   • UDP/ICE (src/transport.js)    — direct, low latency, the path a TUI pair should always take.
//   • WSS-relay (src/transport-wss.js) — the zero-dep floor that traverses every NAT AND is the only
//     pipe a browser peer can meet a TUI peer on. Presence IS the subscription; the topic is derived
//     from the contact string alone (HKDF(S,…)), so NOTHING new has to be published to reach it.
//
// UDP KEEPS ITS PRIORITY. The relay is a floor, not a preference: a TUI pair must not silently end up
// bouncing its chat off a public MQTT broker because the relay answered a beat sooner. Two things
// guarantee that: the composite locks to whoever delivers the first real frame (on a punchable path
// the UDP HELLO arrives in ~ms, the relay's needs a SUBACK + two broker hops), and the WSS leg is
// held back by `wssDelayMs` so UDP always gets a clean head start. If UDP is impossible (symmetric
// NAT, blocked, or the peer is a browser), the relay leg lands ~a second later and the dial succeeds
// anyway — which is exactly the ladder DESIGN D8 asks for.
//
// INVITE MODE gets no WSS leg (src/node.js passes {wss:false}): the relay topic is derived from the
// reusable S, and subscribing it would make an invite-mode listener answerable to any S holder —
// re-opening the META-1 pubkey-harvest oracle the invite path exists to close, outside the reach of
// the probe gate and of burn's go-dark. An invite-scoped relay topic is a rendezvous-lane change; it
// is NOT smuggled in here. (Documented gap, not a hidden one.)
//
// Zero deps. Node ≥22 (global WebSocket). Falls back to a PLAIN UDP endpoint — byte-identical to
// v0.1.0 — whenever the relay is disabled or unavailable.

import { createEndpoint as createUdpEndpoint } from './transport.js'
import { createEndpoint as createWssEndpoint, topicFor, epochStr, RELAYS } from './transport-wss.js'
import { composePunch } from './compose.js'

/** Give a punchable UDP path this long to win before the relay leg even starts knocking. */
const WSS_DELAY_MS = 700

const sleep = (ms) => new Promise((r) => { const t = setTimeout(r, ms); t.unref?.() })

/**
 * A UDP endpoint with the WSS relay composed in. Drop-in for src/transport.js's createEndpoint:
 * every seam src/node.js and src/rendezvous/race.js use (candidates/port/stun/probeAuth/on/off/
 * onConnection/punch/close) is delegated to the UDP endpoint; only onConnection (fan to both) and
 * punch (race both) are composite.
 *
 * @param {object} [opts]
 * @param {number} [opts.port]      UDP bind port (0 = ephemeral)
 * @param {string} [opts.S]         OUR contact string — the relay subscribes its inbox topic from it.
 *                                  Absent ⇒ no relay leg (we would be unreachable on it anyway).
 * @param {boolean} [opts.wss]      false ⇒ plain UDP endpoint (tests, tui↔tui-only, invite mode)
 * @param {string[]} [opts.relays]  relay URLs (default transport-wss RELAYS)
 * @param {*} [opts.WebSocket]      WebSocket ctor (default: global) — injectable for tests
 * @param {number} [opts.wssDelayMs] UDP head start before the relay leg dials (default 700ms)
 * @returns {Promise<object>} endpoint
 */
export async function createEndpoint({
  port = 0, S = null, wss = true, relays = RELAYS, WebSocket, now = () => Date.now(),
  wssDelayMs = WSS_DELAY_MS, ...opts
} = {}) {
  const udp = await createUdpEndpoint({ port, now, ...opts })
  if (!wss || !S) return udp                       // plain UDP — unchanged from v0.1.0

  let wssEp = null
  try {
    wssEp = createWssEndpoint({ S, relays, WebSocket, now })
  } catch {
    return udp                                     // no WebSocket (Node < 22) ⇒ degrade to UDP, never throw
  }

  const ep = {
    udp,
    wss: wssEp,
    get port() { return udp.port },
    get port4() { return udp.port4 },
    get port6() { return udp.port6 },
    /** Only UDP has addressable candidates. The relay's address IS the topic, derived from S. */
    candidates() { return udp.candidates() },
    stun(o) { return udp.stun(o) },
    probeAuth(fn) { return udp.probeAuth(fn) },    // META-1 — UDP-only (invite mode never gets a relay leg)
    on(...a) { return udp.on(...a) },              // 'netchange' — the relay redials itself, nothing to re-announce
    off(...a) { return udp.off(...a) },
    removeListener(...a) { return udp.removeListener(...a) },

    /** Fan the accept callback to BOTH sub-transports: a peer may reach us on either. */
    onConnection(cb) {
      udp.onConnection(cb)
      wssEp.onConnection(cb)
    },

    /**
     * Race a dial over both transports. node.js hands us the rendezvous candidates; the relay's
     * candidate needs no rendezvous at all — its topic is HKDF(peer S,…), and node.js passes that S
     * in `popts`. So a peer with ZERO published UDP candidates (a browser) is still dialable.
     * @param {Array} cands @param {{token?:Buffer, nonce?:Buffer, S?:string}} [popts]
     */
    punch(cands, popts = {}) {
      const all = cands || []
      const udpCands = all.filter((c) => c && (c.proto === 'udp4' || c.proto === 'udp6' || c.proto === 'tcp'))
      let wssCands = all.filter((c) => c && c.proto === 'wss')
      if (!wssCands.length && popts.S) {
        wssCands = [{ proto: 'wss', topic: topicFor(popts.S, epochStr(now())), relays }]
      }
      const attempts = []
      let composite = null
      if (udpCands.length) attempts.push(udp.punch(udpCands, popts))
      if (wssCands.length) {
        // Head start for UDP — but only when there IS a UDP path to give one to (dialing a browser
        // must not pay the delay). And if the peer already answered on UDP within the head start, the
        // relay is never dialed at all: no knock, no subscription, no public broker sees this pair.
        attempts.push(udpCands.length
          ? sleep(wssDelayMs).then(() => {
            if (composite && composite.winner) throw new Error('relay leg not needed: UDP won')
            return wssEp.punch(wssCands, popts)
          })
          : wssEp.punch(wssCands, popts))
      }
      if (!attempts.length) attempts.push(udp.punch(all, popts))   // no usable candidate: keep UDP's own error
      const p = composePunch(attempts)
      p.then((c) => { composite = c }, () => { /* all legs failed — nothing to skip */ })
      return p
    },

    close() {
      try { udp.close() } catch { /* */ }
      try { wssEp.close() } catch { /* */ }
    },
  }
  return ep
}

export default { createEndpoint }
