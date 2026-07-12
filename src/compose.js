// src/compose.js — race SEVERAL transports into ONE logical socket, then COMMIT to the winner.
//
// Both composites need the identical semantics, so there is exactly ONE implementation of them:
//   • src/browser/transport.js — WebRTC + WSS-relay (the browser)
//   • src/transport-node.js    — UDP/ICE + WSS-relay (the TUI/CLI)
// src/node.js consumes either UNCHANGED: it sees one endpoint, one socketLike, and drives
// HELLO → commitment gate → Noise IK over whichever transport the peer actually answers on.
//
// WHY RACE TO FIRST *CONTACT*, NOT FIRST SOCKET: a WSS punch resolves OPTIMISTICALLY (on the
// broker's SUBACK, before any peer answers), so "first socket wins" always picks the relay and
// starves a peer only reachable on the other pipe — the dial then hangs on a pipe nobody answers.
// So the composite fronts EVERY leg, forwards inbound from all of them, and locks its outbound to
// whichever leg delivered the first WELL-FORMED wire frame (the peer's HELLO). The peer can only
// answer on a transport it is genuinely reachable on, so the handshake lands on that one.
//
// GLARE — and why the loser must be CLOSED, not merely ignored (the reason this file exists):
// a raced dial opens N transports, and the listener's endpoint fans onConnection to ALL of its
// sub-transports — so ONE dial can mint N inbound sockets on the listener, each running its OWN
// Noise responder and its own HELLO. Only one of them ever receives our HS1 (outbound is locked),
// so the others are pure waste: N-1 half-open responders, N-1 sockets held on the accept table,
// N-1 HELLO retransmit loops, and their stray HELLOs keep arriving on our dead legs. Committing to
// the winner and CLOSING every loser (here, on the dialer) collapses that back to exactly ONE
// logical session per peer on BOTH ends — at the transport layer, where it costs nothing.
//
// What we deliberately do NOT do: merge two Noise cipher states, or let the listener "adopt" a
// second handshake for a static it already has. Two handshakes are two independent key schedules;
// stitching them together is a footgun. One winner, one session, losers closed.

import { decodeFrame } from './wire.js'

/**
 * @param {Array<Promise<object>>} attempts punch promises (each resolves to a socketLike, or rejects)
 * @returns {Promise<object>} the composite socket (resolves once ≥1 leg is up; rejects if all fail)
 */
export function composePunch(attempts) {
  if (!attempts.length) return Promise.reject(new Error('raced transport: no usable candidate'))
  const wrapped = attempts.map((a) => a.then((s) => ({ s })).catch((e) => ({ e })))
  const subs = []
  let nodeHandler = null
  let outbound = null
  const composite = {
    closed: false,
    rinfo: { address: 'raced', port: 0 },
    /** The leg that won the race — for tests/diagnostics; null until first peer contact. */
    get winner() { return outbound },
    set onMessage(fn) { nodeHandler = typeof fn === 'function' ? fn : null },
    get onMessage() { return nodeHandler },
    send(frame) {
      const targets = outbound ? [outbound] : subs
      for (const s of targets) { try { s.send(frame) } catch { /* dead leg */ } }
    },
    close() {
      composite.closed = true
      for (const s of subs) { try { s.close() } catch { /* */ } }
    },
  }
  /** Commit: this leg carries the session. Every other leg is dead weight — tear it down. */
  const commit = (winner) => {
    outbound = winner
    for (const s of subs) if (s !== winner) { try { s.close() } catch { /* already gone */ } }
  }
  const wire = (s) => {
    if (subs.includes(s)) return
    // A leg that comes up AFTER the race is already won is never spoken on and would only mint a
    // duplicate accept on the listener. Close it on arrival instead of wiring it in.
    if (outbound) { try { s.close() } catch { /* */ } return }
    subs.push(s)
    s.onMessage = (buf, ri) => {
      // BRW-1: lock outbound only on a WELL-FORMED wire frame. The peer's real first contact is a full
      // HELLO frame (≥ HEADER_LEN); a hostile relay injecting a runt/garbage byte no longer wins the
      // lock and misroutes the handshake outbound. Inbound is ALWAYS forwarded up — node.js's own
      // decodeFrame drops the junk, and only a validated frame flips the lock.
      if (!outbound && decodeFrame(buf)) commit(s)   // first REAL peer contact wins; losers are closed
      if (nodeHandler) nodeHandler(buf, ri)
    }
  }
  return new Promise((resolve, reject) => {
    let pending = wrapped.length
    let resolved = false
    const errs = []
    for (const a of wrapped) {
      a.then(({ s, e }) => {
        if (s) {
          wire(s)
          if (!resolved) { resolved = true; resolve(composite) }
        } else if (e) {
          errs.push(e)
        }
        if (--pending === 0 && !resolved) {
          reject(new Error('raced transport: all paths failed (' + errs.map((x) => x && x.message).join('; ') + ')'))
        }
      })
    }
  })
}

export default { composePunch }
