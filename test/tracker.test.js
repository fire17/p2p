// test/tracker.test.js — live WSS matchmaker (v1.1), driven over an in-memory relay mock that
// mirrors a WebTorrent tracker: it parks a peer's offers and relays them to later arrivers, and
// routes answers to the addressed peer. No real network. (Live proof = the 2-process scratch run.)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createTracker, infoHashFor, TRACKERS, trackerProbe, randId20 } from '../src/rendezvous/tracker.js'

// ── in-memory tracker relay + fake WebSocket ──────────────────────────────────
class FakeRelay {
  constructor() {
    this.clients = new Set()
    this.parked = new Map() // info_hash -> [{peer_id, offer_id, offer, from}]
  }
  register(ws) { this.clients.add(ws) }
  unregister(ws) { this.clients.delete(ws) }
  deliver(ws, obj) {
    queueMicrotask(() => { if (ws.readyState === 1 && ws.onmessage) ws.onmessage({ data: JSON.stringify(obj) }) })
  }
  onMessage(ws, data) {
    let m
    try { m = JSON.parse(data) } catch { return }
    if (m.action !== 'announce') return
    ws._peerId = m.peer_id
    ws._ih = m.info_hash
    this.deliver(ws, { action: 'announce', info_hash: m.info_hash, interval: 120, complete: 0, incomplete: 1 })
    if (m.answer && m.to_peer_id) {
      for (const c of this.clients) {
        if (c._peerId === m.to_peer_id) this.deliver(c, { info_hash: m.info_hash, peer_id: m.peer_id, offer_id: m.offer_id, answer: m.answer })
      }
      return
    }
    for (const o of m.offers || []) {
      // relay to everyone else already registered under this infohash
      for (const c of this.clients) {
        if (c === ws || c._ih !== m.info_hash) continue
        this.deliver(c, { info_hash: m.info_hash, peer_id: m.peer_id, offer_id: o.offer_id, offer: o.offer })
      }
      // park for future arrivers (the tracker retains offers ~120s)
      if (!this.parked.has(m.info_hash)) this.parked.set(m.info_hash, [])
      this.parked.get(m.info_hash).push({ peer_id: m.peer_id, offer_id: o.offer_id, offer: o.offer, from: ws })
    }
    // hand this newcomer the offers parked by others
    for (const p of this.parked.get(m.info_hash) || []) {
      if (p.from === ws) continue
      this.deliver(ws, { info_hash: m.info_hash, peer_id: p.peer_id, offer_id: p.offer_id, offer: p.offer })
    }
  }
}
function fakeWebSocket(relay) {
  return class FakeWS {
    constructor() {
      this.readyState = 0
      relay.register(this)
      queueMicrotask(() => { this.readyState = 1; this.onopen && this.onopen() })
    }
    send(data) { relay.onMessage(this, data) }
    close() { if (this.readyState === 3) return; this.readyState = 3; relay.unregister(this); this.onclose && this.onclose() }
  }
}
const settle = () => new Promise((r) => setTimeout(r, 20))

// ── tests ─────────────────────────────────────────────────────────────────────
test('infoHashFor: deterministic, 20 printable-ASCII chars, guards input', () => {
  const rid = Buffer.alloc(20, 0x42)
  const a = infoHashFor(rid)
  assert.equal(a.length, 20)
  assert.equal(a, infoHashFor(Buffer.from(rid))) // deterministic
  assert.ok([...a].every((c) => c.charCodeAt(0) >= 0x21 && c.charCodeAt(0) <= 0x7d)) // JSON-safe
  assert.notEqual(a, infoHashFor(Buffer.alloc(20, 0x43))) // different rid → different infohash
  assert.throws(() => infoHashFor(Buffer.alloc(19)), TypeError)
})

test('descriptor shape + existing exports intact', () => {
  const ch = createTracker({ WebSocket: fakeWebSocket(new FakeRelay()), trackers: ['wss://mock'] })
  assert.equal(ch.name, 'tracker')
  assert.equal(ch.ridLen, 20)
  for (const m of ['announce', 'lookup', 'close']) assert.equal(typeof ch[m], 'function')
  ch.close()
  assert.equal(TRACKERS.length, 3)
  assert.equal(typeof trackerProbe, 'function')
  assert.equal(typeof randId20, 'function')
})

test('matchmaker: dialer discovers a listener\'s candidates VIA the tracker (parked-offer relay)', async () => {
  const relay = new FakeRelay()
  const WS = fakeWebSocket(relay)
  const rid = Buffer.alloc(20, 0x07)
  const listenerCands = [{ proto: 'udp4', ip: '203.0.113.5', port: 5000, kind: 'srflx' }]

  const listener = createTracker({ WebSocket: WS, trackers: ['wss://mock'], now: () => 1000 })
  listener.announce(rid, { candidates: listenerCands })
  await settle() // listener registers + parks its offers

  const dialer = createTracker({ WebSocket: WS, trackers: ['wss://mock'], now: () => 2000 })
  const got = []
  for await (const rec of dialer.lookup(rid, { timeout: 500 })) { got.push(rec); break }

  assert.equal(got.length, 1)
  assert.equal(got[0].channel, 'tracker')
  assert.deepEqual(got[0].candidates, listenerCands)
  assert.equal(got[0].ts, 1000) // listener's announce clock, carried in the blob
  listener.close()
  dialer.close()
})

test('matchmaker: listener answers a dialer offer (answer-path relay)', async () => {
  const relay = new FakeRelay()
  const WS = fakeWebSocket(relay)
  const rid = Buffer.alloc(20, 0x09)
  const listenerCands = [{ proto: 'udp6', ip: '2001:db8::1', port: 6000, kind: 'host' }]

  // dialer announces FIRST (nothing parked yet), listener joins after and must answer the offer
  const dialer = createTracker({ WebSocket: WS, trackers: ['wss://mock'], now: () => 1 })
  const got = []
  const pump = (async () => { for await (const rec of dialer.lookup(rid, { timeout: 800 })) { got.push(rec); break } })()
  await settle()
  const listener = createTracker({ WebSocket: WS, trackers: ['wss://mock'], now: () => 42 })
  listener.announce(rid, { candidates: listenerCands })
  await pump

  assert.ok(got.length >= 1)
  assert.deepEqual(got[0].candidates, listenerCands)
  listener.close()
  dialer.close()
})

test('lookup surfaces nobody for an unknown rid, ends on timeout', async () => {
  const relay = new FakeRelay()
  const WS = fakeWebSocket(relay)
  const dialer = createTracker({ WebSocket: WS, trackers: ['wss://mock'], now: () => 1 })
  const got = []
  for await (const rec of dialer.lookup(Buffer.alloc(20, 0xfe), { timeout: 120 })) got.push(rec)
  assert.equal(got.length, 0)
  dialer.close()
})

test('announce is idempotent per rid; close tears down connections', async () => {
  const relay = new FakeRelay()
  const WS = fakeWebSocket(relay)
  const t = createTracker({ WebSocket: WS, trackers: ['wss://mock'] })
  const rid = Buffer.alloc(20, 0x11)
  t.announce(rid, { candidates: [] })
  const before = relay.clients.size
  t.announce(rid, { candidates: [{ proto: 'udp4', ip: '1.1.1.1', port: 1, kind: 'host' }] }) // refresh, no new conn
  await settle()
  assert.equal(relay.clients.size, before, 're-announce reuses the existing connection')
  t.close()
  await settle()
  assert.equal(relay.clients.size, 0, 'close() tears down all tracker connections')
})

test('rid must be a Buffer (announce + lookup guards)', () => {
  const t = createTracker({ WebSocket: fakeWebSocket(new FakeRelay()), trackers: ['wss://mock'] })
  assert.throws(() => t.announce('nope', {}), TypeError)
  assert.rejects(async () => { for await (const _ of t.lookup('nope')) void _ }, TypeError)
  t.close()
})
