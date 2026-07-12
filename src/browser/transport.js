// src/browser/transport.js — the browser's RACED transport: WebRTC + WSS-relay, both behind the
// one endpoint seam src/node.js injects (createEndpoint → punch/onConnection → socketLike). This is
// the browser side of the owner's "BOTH paths" decision (research/browser-client.md §6, BC-6):
//
//   • WebRTC DataChannel (src/browser/webrtc.js) — direct P2P, ~85% of pairs, low latency.
//   • WSS-relay (src/transport-wss.js, browser-build's lane) — the zero-dep universal FLOOR that
//     traverses every NAT incl. symmetric↔symmetric AND reaches a TUI peer on the same relay.
//
// We race them exactly like the rendezvous channels race: publish/announce on both, and on a dial
// try both, first verified handshake wins. node.js consumes this composite UNCHANGED — it just sees
// one endpoint + one resolve() stream carrying candidates of both kinds, and its own connect() drives
// HELLO → commitment gate → Noise IK over whichever transport answers first. The security layer is
// identical on both pipes, so racing them costs nothing but adds a whole extra reachability path.
//
// DEFENSIVE by design: transport-wss.js is another lane's module. We DYNAMIC-import it and degrade to
// WebRTC-only if it is absent or its shape changed — so this committed browser client never
// hard-breaks on a churn in that file. If WSS loads, both race; if not, WebRTC alone still works.

import { createBrowserTransport } from './webrtc.js'
// The composite lives in src/compose.js — ONE implementation, shared with the node-side composite
// (src/transport-node.js), so the glare rule ("commit to the winner, close every loser") is the same
// on both runtimes. Re-exported here because this is the path the browser tests import it from.
export { composePunch } from '../compose.js'
import { composePunch } from '../compose.js'

/**
 * @param {object} [opts] {trackers, iceServers, relays, RTCPeerConnection, WebSocket, now,
 *                          wss?:boolean(default true), webrtc?:boolean(default true)}
 * @returns {Promise<{createEndpoint:Function, publishAll:Function, resolve:Function, close:Function}>}
 */
export async function createRacedTransport(opts = {}) {
  const useWebrtc = opts.webrtc !== false
  const useWss = opts.wss !== false

  const webrtc = useWebrtc ? createBrowserTransport(opts) : null

  // WSS is another lane's file — load it defensively. Absent/incompatible ⇒ WebRTC-only, logged.
  let wssEp = null
  let wssRv = null
  if (useWss) {
    try {
      const wss = await import('../transport-wss.js')
      if (typeof wss.createEndpoint === 'function' && typeof wss.createWssRendezvous === 'function') {
        // wssEp is created per-listen with S (it subscribes its own inbox); defer to createEndpoint.
        wssRv = wss.createWssRendezvous({ relays: opts.relays, now: opts.now })
        wssEp = { create: (S) => wss.createEndpoint({ S, relays: opts.relays, WebSocket: opts.WebSocket, now: opts.now }) }
      } else {
        console.warn('[p2p] transport-wss present but shape unexpected — WebRTC only')
      }
    } catch {
      console.warn('[p2p] transport-wss unavailable — WebRTC only (browser↔browser still works)')
    }
  }

  let webrtcEndpoint = null
  let wssEndpoint = null

  const endpoint = {
    /** Fan an inbound-accept callback to every live sub-transport. */
    onConnection(cb) {
      if (webrtcEndpoint) webrtcEndpoint.onConnection(cb)
      if (wssEndpoint) wssEndpoint.onConnection(cb)
    },
    candidates() {
      return []
    },

    /**
     * Race a dial across whichever transports have a matching candidate — correctly. node.js hands
     * us the merged candidate list; we punch each kind in parallel. The naive "first socket to
     * resolve wins" is WRONG: the WSS punch resolves OPTIMISTICALLY (on a tracker SUBACK, before any
     * peer answers), so it would always beat WebRTC and starve a peer that is only reachable over
     * WebRTC (e.g. a Node/werift peer not on the relay) — the dial then hangs waiting for a HELLO
     * that never comes on the wrong pipe.
     *
     * So we return a COMPOSITE socket that fronts every sub-socket: it forwards inbound frames from
     * ALL of them to node.js, and LOCKS its outbound to whichever transport delivered the first
     * inbound frame (the peer's HELLO). Since the peer only ever answers on the transport it is
     * actually reachable on, the handshake naturally proceeds over that one; the other leg stays
     * silent and is closed. This races to first real PEER CONTACT, not first socket.
     */
    punch(cands, popts = {}) {
      const webrtcCands = cands.filter((c) => c && (c.channel === 'webrtc' || c.s))
      const wssCands = cands.filter((c) => c && c.proto === 'wss')
      const attempts = []
      if (webrtcEndpoint && webrtcCands.length) attempts.push(webrtcEndpoint.punch(webrtcCands, popts))
      if (wssEndpoint && wssCands.length) attempts.push(wssEndpoint.punch(wssCands, popts))
      return composePunch(attempts)
    },

    close() {
      if (webrtc) webrtc.close()
      if (wssEndpoint && typeof wssEndpoint.close === 'function') wssEndpoint.close()
    },
  }

  return {
    /**
     * Build both sub-endpoints. Takes OUR contact string S because the WSS endpoint subscribes its
     * own inbox topic at creation. p2p.js pre-builds this (it knows id.S) and passes the result as
     * node.js's opts.endpoint, so onConnection fans to a fully-built endpoint before listen wires it.
     * @param {string} S our own 26-char contact string
     */
    async createEndpoint(S) {
      if (webrtc) webrtcEndpoint = await webrtc.createEndpoint()
      if (wssEp) wssEndpoint = wssEp.create(S)
      return endpoint
    },

    /** Reachable on BOTH: WebRTC parks offers on trackers; WSS presence IS its inbox subscription. */
    publishAll(S) {
      const handles = []
      if (webrtc) handles.push(webrtc.publishAll(S))
      if (wssRv) handles.push(wssRv.publishAll(S))
      return { stop() { for (const h of handles) h && h.stop && h.stop() } }
    },

    /** Merge both resolvers' candidates into one stream so punch() can race them. */
    async *resolve(S) {
      if (webrtc) {
        for await (const c of webrtc.resolve(S)) yield c
      }
      if (wssRv) {
        for (const c of wssRv.resolve(S)) yield c
      }
    },

    close: endpoint.close,
  }
}

export default { createRacedTransport }
