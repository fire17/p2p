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
import { createGroup, createSecureGroup } from '../group.js'
import * as key from '../key.js'
import * as noise from '../noise.js'

const DB_NAME = 'p2p'
const STORE = 'identity'
const ID_KEY = 'default' // legacy record key for the default slot — kept so existing users don't lose their identity

// ── identity storage (IndexedDB — NOT localStorage, which any XSS can read as plain text) ──
// ponytail: raw IndexedDB, no wrapper lib. It's ~20 lines and this is the only thing we store.
//
// MULTIPLE IDENTITIES: one browser origin can hold MANY identities, one per SLOT. A slot is just a
// short name; each slot is a SEPARATE IndexedDB record, so two normal tabs/windows that pick
// different slots are genuinely different peers (the failing case was: one record → both tabs = one
// peer → a message went to yourself). Which slot a tab uses is decided by the URL (#id=<name>) so it
// is PER-TAB and survives reload; the records themselves persist named identities across sessions.
// The default slot maps to the legacy 'default' key for backward compatibility.

// A slot name → its IndexedDB record key. Default slot keeps the old flat key; named slots namespace.
function slotKey(slot) {
  return !slot || slot === 'default' ? ID_KEY : 'id:' + slot
}

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

async function idbEntries() {
  const db = await idb()
  return new Promise((resolve, reject) => {
    const store = db.transaction(STORE, 'readonly').objectStore(STORE)
    const kReq = store.getAllKeys()
    const vReq = store.getAll()
    const tx = kReq.transaction
    tx.oncomplete = () => resolve(kReq.result.map((k, i) => [k, vReq.result[i]]))
    tx.onerror = () => reject(tx.error)
  })
}

// Turn a stored record into a live identity, verifying it still commits to its own keys.
function hydrate(saved) {
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

function serialize(id, slot, name) {
  return {
    S: id.S,
    edPub: Buffer.from(id.edPub).toString('hex'),
    edPriv: Buffer.from(id.edPriv).toString('hex'),
    xPub: Buffer.from(id.xPub).toString('hex'),
    xPriv: Buffer.from(id.xPriv).toString('hex'),
    slot,
    name: name || slot,
  }
}

/**
 * The identity for a SLOT — loaded from IndexedDB, or generated once and saved under that slot.
 * Same 26-char contact string as the TUI (`p2p key`): it IS the commitment to (edPub, xPub).
 *
 * BRW-2 fix: two tabs opened first-run CONCURRENTLY on the same slot used to both see null, both
 * mint DIFFERENT keypairs, and both write the same record → last-write-wins → the losing tab ran an
 * unpersisted identity and lost reachability under the S it had already shared. We now serialize the
 * create with `navigator.locks` (a per-slot lock) AND re-check storage inside the critical section,
 * so the second tab adopts the first tab's persisted identity instead of clobbering it. The lock is a
 * best-effort accelerant; the in-lock re-check is the actual correctness guarantee (works even where
 * the Web Locks API is unavailable).
 *
 * @param {{slot?:string, name?:string, fresh?:boolean}} [opts]
 *   slot: which identity this tab uses (default 'default'); fresh: mint a new keypair for this slot
 * @returns {Promise<{S:string, edPub:Buffer, edPriv:Buffer, xPub:Buffer, xPriv:Buffer}>}
 */
export async function identity(opts = {}) {
  const slot = opts.slot || 'default'
  const k = slotKey(slot)
  if (!opts.fresh) {
    const saved = await idbGet(k).catch(() => null)
    if (saved) return hydrate(saved)
  }
  const create = async () => {
    if (!opts.fresh) {
      // Re-check inside the critical section: a concurrent tab may have just minted this slot.
      const again = await idbGet(k).catch(() => null)
      if (again) return hydrate(again)
    }
    const id = await makeIdentity()
    await idbPut(k, serialize(id, slot, opts.name))
    return id
  }
  if (globalThis.navigator?.locks?.request) {
    return navigator.locks.request('p2p-identity-' + slot, create)
  }
  return create()
}

/**
 * ONE identity, ONE live tab — the "connected but no messages" bug, at its root.
 *
 * A tab with no `#id=` in its URL boots the DEFAULT slot (app.js), and the default slot is ONE
 * IndexedDB record. So two ordinary tabs (a bookmark, a plain second tab, a reload of an old link)
 * are not two peers — they are the SAME peer, holding the SAME static keypair. Both then subscribe
 * the same rendezvous topic (it is HKDF(S,…)), both ACCEPT the same incoming dial, and both complete
 * a genuine Noise IK — each really does hold the private key, so nothing in the protocol can tell
 * them apart or refuse them. The dialer binds to whichever answered first; every other tab is left
 * showing "✅ secure channel established" while receiving NOTHING, forever. Messages appear to be
 * ~50% lost because they are landing in the other tab.
 *
 * The protocol cannot fix this (both peers are cryptographically legitimate), so the browser must:
 * an identity may be ONLINE in exactly one tab. We hold a Web Lock named for S for the whole life of
 * the node; a second tab finds it taken and refuses to go online with an actionable message instead
 * of silently becoming a zombie. The lock is released automatically when a tab is closed or
 * discarded, so nothing can wedge a user out of their own identity.
 *
 * Fails OPEN on purpose: where the Web Locks API is missing or errors, we go online as before. The
 * guard exists to catch an honest footgun, and must never be the reason someone cannot get online.
 *
 * @param {string} S the contact string to claim
 * @param {*} [locks] LockManager (default navigator.locks) — injectable for tests
 * @returns {Promise<{held:boolean, release:() => void}>} held=false ⇒ already live in another tab
 */
export function claimIdentity(S, locks = globalThis.navigator?.locks) {
  const free = { held: true, release: () => {} }
  if (!locks || typeof locks.request !== 'function') return Promise.resolve(free)  // no Web Locks ⇒ fail open
  let release = () => {}
  const parked = new Promise((r) => { release = r })                               // resolves ⇒ lock let go
  return new Promise((resolve) => {
    try {
      locks.request('p2p-live-' + S, { ifAvailable: true }, (lock) => {
        if (!lock) { resolve({ held: false, release: () => {} }); return }          // someone else is online as S
        resolve({ held: true, release })
        return parked                                                               // hold it for the node's lifetime
      }).catch(() => resolve(free))                                                 // rejected ⇒ fail open
    } catch { resolve(free) }                                                       // threw synchronously ⇒ fail open
  })
}

/**
 * Every identity this browser holds, for the UI's switcher. ponytail: read straight from the store.
 * @returns {Promise<Array<{slot:string, name:string, S:string}>>}
 */
export async function listIdentities() {
  const entries = await idbEntries().catch(() => [])
  return entries
    .filter(([, v]) => v && v.S)
    .map(([recKey, v]) => ({
      slot: v.slot || (recKey === ID_KEY ? 'default' : String(recKey).replace(/^id:/, '')),
      name: v.name || v.slot || 'default',
      S: v.S,
    }))
    .sort((a, b) => (a.slot === 'default' ? -1 : b.slot === 'default' ? 1 : a.name.localeCompare(b.name)))
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
  // ONE identity, ONE live tab — claimed BEFORE any socket is opened, so a refused tab leaves no
  // trace on the network. Without this, a second tab on the same identity comes online, accepts the
  // same dials, and silently swallows the messages meant for the first (see claimIdentity).
  const lease = await claimIdentity(id.S)
  if (!lease.held) {
    // `reason` (not the prose) is the contract: app.js adopts a free slot when the tab landed on the
    // DEFAULT identity implicitly, and shows this message when the user asked for that slot by name.
    throw Object.assign(
      new Error(
        `this identity (${id.S}) is already online in another tab or window — two tabs sharing one `
        + 'identity steal each other\'s messages, so this tab is staying offline. Close the other tab, '
        + 'or click “＋ New identity” to chat as a second, separate peer.',
      ),
      { reason: 'identity-live', S: id.S },
    )
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
    lease.release()          // this identity is free to come online in another tab again
  }

  // Sender-keys secure group (src/group.js, browser-build's lane) — the browser runs it UNCHANGED
  // because the shim provides its every primitive (incl. Ed25519 sign/verify). One src/group.js,
  // both runtimes. node.group() stays the pairwise fan-out; secureGroup() is the >2 E2E group.
  node.secureGroup = (opts) => createSecureGroup(node, id, opts)
  return node
}

export { key, noise, createGroup, createSecureGroup }
export default { identity, listIdentities, listen }
