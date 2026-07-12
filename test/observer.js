// test/observer.js — the reusable leak OBSERVER for the standing leak-monitor.
//
// research/surface-hardening.md §7 asked for exactly this: generalize privacy.test.js's one-off
// SpyRelay + spyDhtBackend (which already RECORD every byte a surface sees) into ONE reusable
// Observer any rendezvous surface can be wired to, so a fixed no-leak battery can run continuously.
//
// An `Observer` records EXACTLY what a surface OPERATOR would see — the union of every observer's
// capture IS the adversary's view (§7). Surface adapters below wire the REAL modules to an Observer
// over injected/loopback backends (no live network): tracker (SDP relay), DHT (BEP44 storing node),
// mDNS (multicast bus). Read-only + test-only: it never imports non-public src internals and never
// mutates the modules it observes.
//
// Used by:  test/leak-monitor.test.js (the always-on CI monitor) and scratch/leak-canary.mjs (the
//           opt-in live-wire canary), which run the SAME assertNoLeak() battery.

import assert from 'node:assert/strict'
import { SEALED_LEN } from '../src/invite.js'

// ── the Observer: what one surface operator can read ──────────────────────────────────────────────
export class Observer {
  constructor(label = 'surface') {
    this.label = label
    this.texts = []   // string observations (relayed SDP / TXT / any wire JSON)
    this.blobs = []   // sealed-value byte buffers (a DHT put value / an extracted SDP blob)
  }
  /** record a text observation an operator relayed/stored. */
  text(s) { if (s != null) this.texts.push(typeof s === 'string' ? s : String(s)); return this }
  /** record a sealed value's raw bytes (for the fixed-length side-channel check). */
  bytes(b) { if (b) this.blobs.push(Buffer.from(b)); return this }
  /** everything an operator could read, as ONE searchable string (texts + sealed bytes as latin1). */
  wire() { return this.texts.join('\n') + '\n' + this.blobs.map((b) => b.toString('latin1')).join('\n') }
  /** the sealed byte buffers captured on this surface. */
  sealed() { return this.blobs }
}

// ── the synthetic candidate battery (§7: IPv4, IPv6, LAN, relay) ──────────────────────────────────
// Distinct, easily-greppable IPs/ports so a leak of ANY of them is caught. IPs are RFC-5737/3849
// documentation ranges; ports are memorable and unlikely to collide with base64 of random ciphertext.
export const CAND_SETS = {
  ipv4:  [{ proto: 'udp4', ip: '198.51.100.23',        port: 45678, kind: 'srflx' }],
  ipv6:  [{ proto: 'udp6', ip: '2001:db8::dead:beef',  port: 51820, kind: 'host'  }],
  lan:   [{ proto: 'udp4', ip: '192.168.199.50',       port: 47001, kind: 'host'  }],
  relay: [{ proto: 'udp4', ip: '203.0.113.9',          port: 33478, kind: 'relay' }],
}

// ── the STANDING no-leak assertion (§7 A–D) — a real RED-if-violated check ─────────────────────────
/**
 * Assert a captured surface view leaks NOTHING about `cands`. THROWS (AssertionError) on any leak —
 * that is the "RED if violated". Green tests call it on real sealed surfaces (passes); the RED-proof
 * calls it on a deliberately-leaky surface (it throws, proving the detector bites).
 *
 *   A  no plaintext IP of any candidate
 *   B  no plaintext port of any candidate
 *   C  no marker/tell literal (`p2p-blob`, `candidates`)
 *   D  every sealed value is exactly SEALED_LEN (544 B) — no length side-channel
 *
 * @param {Observer} obs
 * @param {Array<{ip:string,port:number}>} cands the candidate set that was sealed onto the surface
 * @param {object} [opts]
 * @param {boolean} [opts.expectSealed=true]  assert D (fixed 544-B sealed values). Off for surfaces
 *                                            with no captured sealed buffer (e.g. plaintext mDNS).
 */
export function assertNoLeak(obs, cands, opts = {}) {
  const { expectSealed = true } = opts
  const wire = obs.wire()
  assert.ok(wire.length > 0, `[${obs.label}] observer captured nothing to check`)
  for (const c of cands) {
    assert.equal(wire.includes(c.ip), false, `[${obs.label}] A: plaintext IP ${c.ip} leaked on the wire`)
    assert.equal(wire.includes(String(c.port)), false, `[${obs.label}] B: plaintext port ${c.port} leaked on the wire`)
  }
  assert.equal(wire.includes('p2p-blob'), false, `[${obs.label}] C: the p2p-blob attribute tell is on the wire`)
  assert.equal(/"candidates"/.test(wire), false, `[${obs.label}] C: plaintext blob structure ("candidates") on the wire`)
  if (expectSealed) {
    const sealed = obs.sealed()
    assert.ok(sealed.length > 0, `[${obs.label}] D: expected at least one sealed value but captured none`)
    for (const b of sealed) {
      assert.equal(b.length, SEALED_LEN, `[${obs.label}] D: sealed value is ${b.length}B, not the fixed ${SEALED_LEN}B`)
    }
  }
}

// ── surface adapter 1: TRACKER (SDP relay) ────────────────────────────────────────────────────────
// A faithful in-memory tracker relay (ported from privacy.test.js) that feeds an Observer every SDP
// it relays AND extracts the sealed blob rides in the invite-mode SDP attribute `a=<8·[a-z]>:<b64>`.
class SpyRelay {
  constructor(observer) {
    this.obs = observer
    this.clients = new Set()
    this.parked = new Map()
  }
  register(ws) { this.clients.add(ws) }
  unregister(ws) { this.clients.delete(ws) }
  deliver(ws, obj) {
    queueMicrotask(() => { if (ws.readyState === 1 && ws.onmessage) ws.onmessage({ data: JSON.stringify(obj) }) })
  }
  onMessage(ws, data) {
    this.obs.text(data)                                   // <-- everything the tracker operator can read
    // extract the sealed blob (invite mode: pseudorandom 8-char attr name) for the length check
    for (const m of data.matchAll(/a=[a-z]{8}:([A-Za-z0-9+/=]+)/g)) {
      try { this.obs.bytes(Buffer.from(m[1], 'base64')) } catch { /* not our blob */ }
    }
    let msg
    try { msg = JSON.parse(data) } catch { return }
    if (msg.action !== 'announce') return
    ws._peerId = msg.peer_id; ws._ih = msg.info_hash
    if (msg.answer && msg.to_peer_id) {
      for (const c of this.clients) {
        if (c._peerId === msg.to_peer_id) this.deliver(c, { info_hash: msg.info_hash, peer_id: msg.peer_id, offer_id: msg.offer_id, answer: msg.answer })
      }
      return
    }
    for (const o of msg.offers || []) {
      for (const c of this.clients) {
        if (c === ws || c._ih !== msg.info_hash) continue
        this.deliver(c, { info_hash: msg.info_hash, peer_id: msg.peer_id, offer_id: o.offer_id, offer: o.offer })
      }
      if (!this.parked.has(msg.info_hash)) this.parked.set(msg.info_hash, [])
      this.parked.get(msg.info_hash).push({ peer_id: msg.peer_id, offer_id: o.offer_id, offer: o.offer, from: ws })
    }
    for (const p of this.parked.get(msg.info_hash) || []) {
      if (p.from === ws) continue
      this.deliver(ws, { info_hash: msg.info_hash, peer_id: p.peer_id, offer_id: p.offer_id, offer: p.offer })
    }
  }
}

/**
 * A tracker surface wired to a fresh Observer.
 * @returns {{ observer:Observer, WebSocket:Function }} pass WebSocket to createTracker({WebSocket,...}).
 */
export function trackerSurface(label = 'tracker') {
  const observer = new Observer(label)
  const relay = new SpyRelay(observer)
  const WebSocket = class FakeWS {
    constructor() {
      this.readyState = 0
      relay.register(this)
      queueMicrotask(() => { this.readyState = 1; this.onopen && this.onopen() })
    }
    send(data) { relay.onMessage(this, data) }
    close() { if (this.readyState === 3) return; this.readyState = 3; relay.unregister(this); this.onclose && this.onclose() }
  }
  return { observer, WebSocket }
}

// ── surface adapter 2: DHT (BEP44 storing node) ───────────────────────────────────────────────────
/**
 * An injected DHT backend that RECORDS every BEP44 put value (the storing node's view) into an
 * Observer, and serves gets from an in-memory store — no live DHT.
 * @returns {{ observer:Observer, backend:object }} pass backend to createDht({dht:backend,...}).
 */
export function dhtSurface(label = 'dht') {
  const observer = new Observer(label)
  const store = new Map() // target hex -> item
  const backend = {
    puts: [],
    async bep44Put(item) { this.puts.push(item); observer.bytes(item.v); store.set(item.target.toString('hex'), item); return { stored: 8 } },
    async bep44Get(target) { return { item: store.get(target.toString('hex')) || null } },
    async getPeers() { return { peers: [], announced: 0, queried: 0, tokenNodes: 0 } },
    close() {},
    _store: store,
  }
  return { observer, backend }
}

// ── surface adapter 3: mDNS (multicast bus) — LAN-only, see the MDNS-1 note in leak-monitor.test ───
// In-memory multicast bus (ported from mdns.test.js) so createMdns runs with no real network.
export function mdnsBus() {
  const socks = []
  const factory = () => {
    const s = {
      _handlers: {},
      on(ev, cb) { (this._handlers[ev] ||= []).push(cb) },
      emit(ev, ...a) { for (const cb of this._handlers[ev] || []) cb(...a) },
      bind(_p, cb) { if (cb) setImmediate(cb); return this },
      addMembership() {}, setMulticastTTL() {}, setMulticastLoopback() {},
      send(buf, _p, _a, cb) { for (const o of socks) if (o !== s) o.emit('message', buf, { address: 'mock', port: 5353 }); if (cb) cb() },
      close() { const i = socks.indexOf(s); if (i >= 0) socks.splice(i, 1) },
    }
    socks.push(s)
    return s
  }
  return { factory }
}

/** Settle microtasks + the queueMicrotask relay hops (30 ms mirrors privacy.test.js). */
export const settle = () => new Promise((r) => setTimeout(r, 30))
