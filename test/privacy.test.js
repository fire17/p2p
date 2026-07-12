// test/privacy.test.js — the ADVERSARIAL suite for invite mode.
//
// It proves the exact privacy claim of research/metadata-privacy.md §10:
//   • an observer holding the reusable identity string S but NOT K_inv can neither LOCATE the
//     record (rid_inv is K_inv-derived) nor DECRYPT it (candidates are sealed under k_ip);
//   • nothing an infra operator (tracker relay / DHT storing node) sees contains an IP — or even
//     the constant `p2p-blob` attribute name that used to identify a p2p user on sight;
//   • the DHT never carries a plaintext ip:port in invite mode (BEP44 value, not announce_peer).
// Deterministic, offline: an in-memory tracker relay + an injected DHT backend, both of which
// RECORD everything they see — that recording IS the adversary's view.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createTracker } from '../src/rendezvous/tracker.js'
import { createDht } from '../src/rendezvous/dht.js'
import { createInvite, generateInviteSecret, openBlob, deriveInviteRid } from '../src/invite.js'
import { generateIdentity, deriveRid } from '../src/key.js'

const EPOCH = '2026-07-12'
const IP = '198.51.100.23'
const PORT = 45678
const CANDS = [{ proto: 'udp4', ip: IP, port: PORT, kind: 'srflx' }]

// ── in-memory tracker that RECORDS every byte it relays (the operator's view) ────────────────────
class SpyRelay {
  constructor() { this.clients = new Set(); this.parked = new Map(); this.seen = [] }
  register(ws) { this.clients.add(ws) }
  unregister(ws) { this.clients.delete(ws) }
  deliver(ws, obj) {
    queueMicrotask(() => { if (ws.readyState === 1 && ws.onmessage) ws.onmessage({ data: JSON.stringify(obj) }) })
  }
  onMessage(ws, data) {
    this.seen.push(data)                      // <-- everything the tracker operator can read
    let m
    try { m = JSON.parse(data) } catch { return }
    if (m.action !== 'announce') return
    ws._peerId = m.peer_id; ws._ih = m.info_hash
    if (m.answer && m.to_peer_id) {
      for (const c of this.clients) {
        if (c._peerId === m.to_peer_id) this.deliver(c, { info_hash: m.info_hash, peer_id: m.peer_id, offer_id: m.offer_id, answer: m.answer })
      }
      return
    }
    for (const o of m.offers || []) {
      for (const c of this.clients) {
        if (c === ws || c._ih !== m.info_hash) continue
        this.deliver(c, { info_hash: m.info_hash, peer_id: m.peer_id, offer_id: o.offer_id, offer: o.offer })
      }
      if (!this.parked.has(m.info_hash)) this.parked.set(m.info_hash, [])
      this.parked.get(m.info_hash).push({ peer_id: m.peer_id, offer_id: o.offer_id, offer: o.offer, from: ws })
    }
    for (const p of this.parked.get(m.info_hash) || []) {
      if (p.from === ws) continue
      this.deliver(ws, { info_hash: m.info_hash, peer_id: p.peer_id, offer_id: p.offer_id, offer: p.offer })
    }
  }
  /** every SDP the operator relayed, concatenated */
  wire() { return this.seen.join('\n') }
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
const settle = () => new Promise((r) => setTimeout(r, 30))

/** An injected DHT backend: a dumb BEP44 store that records every put (the storing node's view). */
function spyDhtBackend() {
  const store = new Map() // target hex -> {k, salt, seq, v, sig}
  return {
    puts: [],
    async bep44Put(item) { this.puts.push(item); store.set(item.target.toString('hex'), item); return { stored: 8 } },
    async bep44Get(target) { return { item: store.get(target.toString('hex')) || null } },
    async getPeers() { return { peers: [], announced: 0, queried: 0, tokenNodes: 0 } },
    close() {},
    _store: store,
  }
}

// ── 1. TRACKER: the sealed blob reaches the invitee; the operator sees only ciphertext ───────────

test('tracker invite mode: invitee gets the candidates; the tracker operator sees no IP and no tell', async () => {
  const relay = new SpyRelay()
  const WS = fakeWebSocket(relay)
  const inv = createInvite(generateInviteSecret())            // Alice mints K_inv, hands it to Bob
  const rid = inv.rid('tracker', EPOCH, 20)

  const alice = createTracker({ trackers: ['wss://spy'], WebSocket: WS, codec: inv.codec })
  const bob = createTracker({ trackers: ['wss://spy'], WebSocket: WS, codec: inv.codec })
  alice.announce(rid, { candidates: CANDS })
  await settle()

  const got = []
  for await (const r of bob.lookup(rid, { timeout: 120 })) got.push(r)
  alice.close(); bob.close()

  assert.ok(got.length >= 1, 'the invitee must receive the candidate blob')
  assert.deepEqual(got[0].candidates, CANDS)                  // Bob (K_inv holder) reads the IP

  const wire = relay.wire()
  assert.ok(wire.length > 0)
  assert.equal(wire.includes(IP), false, 'the tracker relayed no plaintext IP')
  assert.equal(wire.includes(String(PORT)), false, 'the tracker relayed no plaintext port')
  assert.equal(wire.includes('p2p-blob'), false, 'the p2p-blob attribute name (a fingerprint tell) is gone')
  assert.equal(/"candidates"/.test(wire), false, 'no plaintext blob structure on the wire')
})

test('tracker invite mode: an S-holder WITHOUT K_inv cannot even locate the record', async () => {
  const relay = new SpyRelay()
  const WS = fakeWebSocket(relay)
  const id = generateIdentity()                               // the identity both parties know
  const inv = createInvite(generateInviteSecret())
  const ridInv = inv.rid('tracker', EPOCH, 20)                // where Alice actually publishes

  const alice = createTracker({ trackers: ['wss://spy'], WebSocket: WS, codec: inv.codec })
  alice.announce(ridInv, { candidates: CANDS })
  await settle()

  // Mallory holds S (a reusable contact string). Every rid she can compute is the S-derived one.
  const ridS = deriveRid(id.S, 'tracker', EPOCH, 20)
  assert.notEqual(ridS.toString('hex'), ridInv.toString('hex'))

  const mallory = createTracker({ trackers: ['wss://spy'], WebSocket: WS })  // no K_inv, no codec
  const got = []
  for await (const r of mallory.lookup(ridS, { timeout: 120 })) got.push(r)
  alice.close(); mallory.close()
  assert.equal(got.length, 0, 'an S-holder without K_inv finds nothing: she cannot compute rid_inv')
})

test('tracker invite mode: even AT the right rid, a wrong K_inv decrypts nothing', async () => {
  const relay = new SpyRelay()
  const WS = fakeWebSocket(relay)
  const inv = createInvite(generateInviteSecret())
  const rid = inv.rid('tracker', EPOCH, 20)
  const mallorysKey = createInvite(generateInviteSecret())    // a DIFFERENT invite (or a guess)

  const alice = createTracker({ trackers: ['wss://spy'], WebSocket: WS, codec: inv.codec })
  alice.announce(rid, { candidates: CANDS })
  await settle()

  // Mallory somehow learns the rid (e.g. she is the tracker) and listens with her own key.
  const mallory = createTracker({ trackers: ['wss://spy'], WebSocket: WS, codec: mallorysKey.codec })
  const got = []
  for await (const r of mallory.lookup(rid, { timeout: 120 })) got.push(r)
  alice.close(); mallory.close()
  assert.equal(got.length, 0, 'the AEAD tag fails under the wrong k_ip: nothing is yielded')

  // and the raw ciphertext she captured is useless to her
  const b64 = /a=[a-z]{8}:([A-Za-z0-9+/=]+)/.exec(relay.wire())
  assert.ok(b64, 'the operator did capture the sealed blob')
  const sealed = Buffer.from(b64[1], 'base64')
  assert.equal(openBlob(mallorysKey.kIp, sealed, rid), null)  // wrong key
  assert.deepEqual(openBlob(inv.kIp, sealed, rid).candidates, CANDS) // only the invitee opens it
})

test('tracker reusable mode is UNCHANGED (legacy attr + plaintext JSON — v0.1.0 wire, still leaky)', async () => {
  const relay = new SpyRelay()
  const WS = fakeWebSocket(relay)
  const rid = Buffer.alloc(20, 7)
  const a = createTracker({ trackers: ['wss://spy'], WebSocket: WS })   // no codec → JSON default
  const b = createTracker({ trackers: ['wss://spy'], WebSocket: WS })
  a.announce(rid, { candidates: CANDS })
  await settle()
  const got = []
  for await (const r of b.lookup(rid, { timeout: 120 })) got.push(r)
  a.close(); b.close()
  assert.deepEqual(got[0].candidates, CANDS)
  // the v0.1.0 wire: the legacy attribute name, carrying base64'd PLAINTEXT JSON — i.e. the IP is
  // there for the operator to read (this is exactly the leak invite mode closes; kept for interop
  // and documented as the less-private option).
  const wire = relay.wire()
  assert.ok(wire.includes('p2p-blob'), 'reusable mode keeps the legacy attribute (v0.1.0 interop)')
  const m = /a=p2p-blob:([A-Za-z0-9+/=]+)/.exec(wire)
  const blob = JSON.parse(Buffer.from(m[1], 'base64').toString('utf8'))
  assert.equal(JSON.stringify(blob).includes(IP), true, 'reusable mode still exposes the IP to the tracker')
})

// ── 2. DHT: encrypted BEP44 instead of plaintext announce_peer ───────────────────────────────────

test('dht invite mode: BEP44 put carries a sealed fixed-length value — never an ip:port', async () => {
  const backend = spyDhtBackend()
  const inv = createInvite(generateInviteSecret())
  const rid = inv.rid('dht', EPOCH, 20)
  const dht = createDht({ dht: backend, invite: inv, now: () => 1720000000000 })

  dht.announce(rid, { candidates: CANDS })
  await settle()

  assert.equal(backend.puts.length, 1, 'invite mode PUTs a BEP44 item (never announce_peer)')
  const put = backend.puts[0]
  assert.ok(put.target.equals(inv.bep44Target(rid)))          // target = SHA1(bep_pk ‖ rid)
  assert.ok(put.k.equals(inv.bepPub))
  assert.equal(put.v.length, 544)                             // fixed-length sealed blob, « BEP44's 1000 B cap
  assert.equal(put.v.includes(Buffer.from(IP, 'utf8')), false, 'no plaintext IP in the stored value')
  assert.equal(inv.bep44Verify(rid, put.seq, put.v, put.sig), true, 'the item is signed by the K_inv-derived key')

  // the invitee fetches, verifies, and opens it
  const got = []
  for await (const r of dht.lookup(rid, {})) got.push(r)
  assert.deepEqual(got[0].candidates, CANDS)
  assert.equal(got[0].channel, 'dht')
  dht.close()
})

test('dht invite mode: an observer without K_inv can neither compute the target nor open the value', async () => {
  const backend = spyDhtBackend()
  const inv = createInvite(generateInviteSecret())
  const rid = inv.rid('dht', EPOCH, 20)
  const dht = createDht({ dht: backend, invite: inv })
  dht.announce(rid, { candidates: CANDS })
  await settle()
  dht.close()

  const mallory = createInvite(generateInviteSecret())
  // 1. she cannot LOCATE it: her rid and her target differ from Alice's
  assert.notEqual(mallory.rid('dht', EPOCH, 20).toString('hex'), rid.toString('hex'))
  assert.notEqual(mallory.bep44Target(rid).toString('hex'), inv.bep44Target(rid).toString('hex'))
  assert.equal((await backend.bep44Get(mallory.bep44Target(rid))).item, null)

  // 2. even handed the stored value, she cannot OPEN it (and her lookup at the right target yields nothing)
  const stored = backend.puts[0].v
  assert.equal(openBlob(mallory.kIp, stored, rid), null)
  const mDht = createDht({ dht: backend, invite: { ...mallory, bep44Target: () => backend.puts[0].target } })
  const got = []
  for await (const r of mDht.lookup(rid, {})) got.push(r)
  assert.equal(got.length, 0, 'wrong K_inv ⇒ signature/AEAD reject ⇒ no candidates')
  mDht.close()
})

test('dht reusable mode is UNCHANGED (announce_peer path, no BEP44)', async () => {
  const calls = []
  const backend = {
    async getPeers(rid, opts) { calls.push(opts); return { peers: ['198.51.100.23:45678'], announced: 8, queried: 8, tokenNodes: 8 } },
    async bep44Put() { throw new Error('reusable mode must NOT touch BEP44') },
    async bep44Get() { throw new Error('reusable mode must NOT touch BEP44') },
    close() {},
  }
  const dht = createDht({ dht: backend })                     // no invite → today's behaviour
  dht.announce(Buffer.alloc(20, 3), { port: 41000 })
  await settle()
  assert.equal(calls[0].announce, true)                       // announce_peer, exactly as before
  const got = []
  for await (const r of dht.lookup(Buffer.alloc(20, 3), {})) got.push(r)
  assert.deepEqual(got[0].candidates, [{ proto: 'udp4', ip: IP, port: PORT, kind: 'srflx' }])
  dht.close()
})

// ── 3. the claim, stated as an executable assertion ──────────────────────────────────────────────

test('CLAIM (§10): S alone gives an adversary neither location nor content of an invite record', () => {
  const id = generateIdentity()
  const K = generateInviteSecret()
  const inv = createInvite(K)

  for (const ch of ['dht', 'tracker', 'mdns']) {
    const len = ch === 'mdns' ? 32 : 20
    const ridS = deriveRid(id.S, ch, EPOCH, len)              // everything an S-holder can compute
    const ridInv = deriveInviteRid(K, ch, EPOCH, len)         // where the invite actually lives
    assert.notEqual(ridS.toString('hex'), ridInv.toString('hex'))
  }
  // and no key an S-holder can derive opens the blob (k_ip comes only from K_inv)
  const rid = inv.rid('tracker', EPOCH, 20)
  const sealed = inv.codec.seal({ v: 1, ts: 1, candidates: CANDS }, rid)
  for (const guess of [deriveRid(id.S, 'ip', EPOCH, 32), Buffer.alloc(32), Buffer.alloc(32, 0xff)]) {
    assert.equal(openBlob(guess, sealed, rid), null)
  }
  assert.deepEqual(openBlob(inv.kIp, sealed, rid).candidates, CANDS)
})
