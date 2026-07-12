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
     * Race a dial across whichever transports have a matching candidate. node.js hands us the
     * merged candidate list from resolve(); we split by kind, punch each in parallel, first
     * settled socket wins and the losers are dropped. (node.js runs the Noise handshake over the
     * winner; a lost punch just leaves an idle socket that gets GC'd / closed on node.close.)
     */
    punch(cands, popts = {}) {
      const attempts = []
      const webrtcCands = cands.filter((c) => c && (c.channel === 'webrtc' || c.s))
      const wssCands = cands.filter((c) => c && c.proto === 'wss')
      if (webrtcEndpoint && webrtcCands.length) attempts.push(webrtcEndpoint.punch(webrtcCands, popts))
      if (wssEndpoint && wssCands.length) attempts.push(wssEndpoint.punch(wssCands, popts))
      if (!attempts.length) return Promise.reject(new Error('raced transport: no usable candidate'))
      // Promise.any → first transport to produce a live socket wins; reject only if ALL fail.
      return Promise.any(attempts).catch((e) => {
        throw new Error('raced transport: all paths failed (' + (e.errors || []).map((x) => x.message).join('; ') + ')')
      })
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
