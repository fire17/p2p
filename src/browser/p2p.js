// src/browser/p2p.js — the browser client's public API. Mirrors src/node.js's shape:
//
//     const id   = await identity()          // loads from IndexedDB, or generates + saves
//     const node = await listen(id)          // reachable under rid(id.S) via the WSS trackers
//     const peer = await node.connect(S)     // resolves ONLY after the Noise IK first-ack
//     peer.send('hi');  node.on('message', (peer, buf) => …)
//     node.group([S1, S2]).send('hi all')
//
// It is the SAME node.js the TUI runs — we only inject the browser's transport/rendezvous.
// No backend of ours, anywhere: rendezvous is the public WSS trackers, NAT traversal is ICE +
// free public STUN, and the security is our own Noise IK + commitment gate on top (so the
// trackers, STUN, and WebRTC's own DTLS are all untrusted plumbing).
//
// IMPORTANT — load order: the shared protocol source uses the globals `Buffer` and `process`,
// and src/noise.js touches Buffer at MODULE TOP LEVEL (its DER prefixes). So the shims must be
// installed before anything else is imported. Static imports run in declaration order, so
// `./shim/globals.js` FIRST is load-bearing — do not reorder these.
import './shim/globals.js'

import { identity as makeIdentity, listen as nodeListen } from '../node.js'
import { createRacedTransport } from './transport.js'
import * as key from '../key.js'
import * as noise from '../noise.js'

const DB_NAME = 'p2p'
const STORE = 'identity'
const ID_KEY = 'default'

// ── identity storage (IndexedDB — NOT localStorage, which any XSS can read as plain text) ──
// ponytail: raw IndexedDB, no wrapper lib. It's ~20 lines and this is the only thing we store.

function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function idbGet(k) {
  const db = await idb()
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readonly').objectStore(STORE).get(k)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function idbPut(k, v) {
  const db = await idb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite')
    tx.objectStore(STORE).put(v, k)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

/**
 * This browser's identity — loaded from IndexedDB, or generated once and saved.
 * Same 26-char contact string as the TUI (`p2p key`): it IS the commitment to (edPub, xPub).
 * @param {{fresh?:boolean}} [opts] fresh: ignore any stored identity and mint a new one
 * @returns {Promise<{S:string, edPub:Buffer, edPriv:Buffer, xPub:Buffer, xPriv:Buffer}>}
 */
export async function identity(opts = {}) {
  if (!opts.fresh) {
    const saved = await idbGet(ID_KEY).catch(() => null)
    if (saved) {
      const id = {
        S: saved.S,
        edPub: Buffer.from(saved.edPub, 'hex'),
        edPriv: Buffer.from(saved.edPriv, 'hex'),
        xPub: Buffer.from(saved.xPub, 'hex'),
        xPriv: Buffer.from(saved.xPriv, 'hex'),
      }
      // Never trust storage blindly: the string must still be the commitment to these keys.
      const dec = key.decodeKey(id.S)
      if (!key.verifyCommitment(dec.commitment, id.edPub, id.xPub)) {
        throw new Error('stored identity is corrupt (key does not match its commitment)')
      }
      return id
    }
  }
  const id = await makeIdentity()
  await idbPut(ID_KEY, {
    S: id.S,
    edPub: Buffer.from(id.edPub).toString('hex'),
    edPriv: Buffer.from(id.edPriv).toString('hex'),
    xPub: Buffer.from(id.xPub).toString('hex'),
    xPriv: Buffer.from(id.xPriv).toString('hex'),
  })
  return id
}

/**
 * Go online: reachable under rid(S), accepting inbound connections on BOTH transports and running
 * HELLO -> commitment gate -> Noise IK on each. The transports RACE (research/browser-client.md §6):
 *   • WebRTC DataChannel over the WSS trackers — direct P2P, browser↔browser.
 *   • WSS-relay (src/transport-wss.js) — the zero-dep floor that also reaches a TUI peer.
 * Whichever completes the verified handshake first wins; node.js is unchanged.
 * @param {object} id from identity()
 * @param {object} [opts] {trackers, iceServers, relays, wss?:bool, webrtc?:bool} — all default on
 * @returns {Promise<object>} the same node object src/node.js returns (on/connect/group/peers/close)
 */
export async function listen(id, opts = {}) {
  if (!globalThis.isSecureContext) {
    // WebCrypto's getRandomValues and IndexedDB need a secure context; so does honest security.
    throw new Error('p2p requires a secure context (https:// or localhost)')
  }
  const t = await createRacedTransport(opts)
  // Pre-build the endpoint WITH our S (the WSS leg subscribes its own inbox at creation). Provide
  // it via BOTH opts.endpoint and a createEndpoint in deps: node.js's resolveDeps only skips the
  // Node-only (dgram) sibling imports when EVERY dep function is present, so createEndpoint must be
  // in deps — it just returns the endpoint we already built (node.js uses opts.endpoint anyway).
  const endpoint = await t.createEndpoint(id.S)

  // Inject the browser's seams. Everything else — the gate, Noise IK, framing, the outbox, the
  // peer lifecycle — is src/node.js's own code, byte-identical to what the TUI runs.
  const node = await nodeListen(id, {
    ...opts,
    endpoint,
    deps: {
      generateIdentity: key.generateIdentity,
      decodeKey: key.decodeKey,
      verifyCommitment: key.verifyCommitment,
      encodeKey: key.encodeKey,
      initiator: noise.initiator,
      responder: noise.responder,
      createEndpoint: async () => endpoint,
      resolve: t.resolve,
      publishAll: (S) => t.publishAll(S),
    },
  })

  const close = node.close
  node.close = () => {
    try { close() } catch { /* */ }
    t.close()
  }
  return node
}

export { key, noise }
export default { identity, listen }
