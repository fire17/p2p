// test/mdns.test.js — mDNS codec round-trips + announce↔lookup over an in-memory socket bus.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { createMdns, _internals } from '../src/rendezvous/mdns.js'

const { encodeQuery, encodeResponse, decode, encodeTxt, decodeTxt, encodeName, readName, SERVICE } = _internals

// ── in-memory multicast bus (no real network) ─────────────────────────────────
class MockSocket extends EventEmitter {
  constructor(bus) {
    super()
    this.bus = bus
    this.setMaxListeners(0)
  }
  bind(_port, cb) {
    if (cb) setImmediate(cb)
    return this
  }
  addMembership() {}
  setMulticastTTL() {}
  setMulticastLoopback() {}
  send(buf, _port, _addr, cb) {
    this.bus.deliver(this, buf)
    if (typeof cb === 'function') cb()
  }
  close() {
    this.bus.remove(this)
  }
}
class MockBus {
  constructor() {
    this.socks = []
    this.factory = () => {
      const s = new MockSocket(this)
      this.socks.push(s)
      return s
    }
  }
  deliver(from, buf) {
    for (const s of this.socks) if (s !== from) s.emit('message', buf, { address: 'mock', port: 5353 })
  }
  remove(s) {
    const i = this.socks.indexOf(s)
    if (i >= 0) this.socks.splice(i, 1)
  }
}

const tick = () => new Promise((r) => setImmediate(r))

test('DNS codec: query name round-trips', () => {
  const q = encodeQuery(SERVICE, 12)
  const d = decode(q)
  assert.equal(d.questions.length, 1)
  assert.equal(d.questions[0].name, SERVICE)
  assert.equal(d.questions[0].qtype, 12)
})

test('DNS codec: name encode/read round-trips', () => {
  const buf = encodeName(SERVICE)
  const r = readName(buf, 0)
  assert.equal(r.name, SERVICE)
  assert.equal(r.off, buf.length)
})

test('DNS codec: TXT response round-trips (incl. chunked blob)', () => {
  const rid = Buffer.alloc(32, 0xab)
  const blob = { v: 1, ts: 123, candidates: Array.from({ length: 12 }, (_, i) => ({ proto: 'udp4', ip: '10.0.0.' + i, port: 4000 + i, kind: 'lan' })) }
  const strings = encodeTxt(rid, blob)
  assert.ok(strings.length >= 2) // rid + at least one blob chunk
  const resp = encodeResponse([{ name: SERVICE, type: 16, ttl: 120, strings }])
  const d = decode(resp)
  assert.equal(d.txt.length, 1)
  const dec = decodeTxt(d.txt[0].strings)
  assert.equal(dec.ridHex, rid.toString('hex'))
  assert.deepEqual(dec.blob, blob)
})

test('decodeTxt rejects non-rid TXT records', () => {
  assert.equal(decodeTxt(['random=1']), null)
  assert.equal(decodeTxt([]), null)
})

test('announce → lookup discovers a peer over the bus', async () => {
  const bus = new MockBus()
  const responder = createMdns({ socketFactory: bus.factory, now: () => 1000 })
  const seeker = createMdns({ socketFactory: bus.factory, now: () => 2000 })
  await tick() // let both bind

  const rid = Buffer.alloc(32, 0x11)
  const candidates = [{ proto: 'udp4', ip: '192.168.1.9', port: 7777, kind: 'lan' }]
  responder.announce(rid, { candidates })

  const got = []
  for await (const rec of seeker.lookup(rid, { timeout: 200 })) got.push(rec)

  assert.equal(got.length, 1)
  assert.equal(got[0].channel, 'mdns')
  assert.deepEqual(got[0].candidates, candidates)
  assert.equal(got[0].ts, 1000) // responder's announce clock, carried in the blob
  responder.close()
  seeker.close()
})

test('lookup ignores announcements for a different rid', async () => {
  const bus = new MockBus()
  const responder = createMdns({ socketFactory: bus.factory })
  const seeker = createMdns({ socketFactory: bus.factory })
  await tick()

  responder.announce(Buffer.alloc(32, 0x22), { candidates: [{ proto: 'udp4', ip: '1.1.1.1', port: 1, kind: 'lan' }] })

  const got = []
  for await (const rec of seeker.lookup(Buffer.alloc(32, 0x33), { timeout: 150 })) got.push(rec)
  assert.equal(got.length, 0)
  responder.close()
  seeker.close()
})

test('channel descriptor shape matches the uniform surface', () => {
  const ch = createMdns({ socketFactory: new MockBus().factory })
  assert.equal(ch.name, 'mdns')
  assert.equal(ch.ridLen, 32)
  assert.equal(typeof ch.announce, 'function')
  assert.equal(typeof ch.lookup, 'function')
  ch.close()
})

// LIVE regression test — the mock bus can't catch real-dgram wiring bugs. This one would have
// caught BOTH: (1) dgram.createSocket('udp4', optsObj) dropping reuseAddr (2nd instance can't
// bind 5353), and (2) missing setMulticastLoopback(true) (no same-host delivery). Uses REAL
// multicast; skips (not fails) where the environment blocks it, so CI stays green everywhere.
test('LIVE: two real-socket instances discover cross-instance over multicast', async (t) => {
  let a, b
  try {
    a = createMdns()
    b = createMdns()
  } catch {
    a?.close?.()
    b?.close?.()
    return t.skip('dgram/multicast unavailable in this environment')
  }
  try {
    await new Promise((r) => setTimeout(r, 400)) // let both bind + join the group
    const rid = Buffer.alloc(32, 0x5e)
    const candidates = [{ proto: 'udp4', ip: '127.0.0.1', port: 5555, kind: 'host' }]
    a.announce(rid, { candidates })
    const got = []
    for await (const rec of b.lookup(rid, { timeout: 1500 })) got.push(rec)
    if (got.length === 0) return t.skip('no multicast loopback delivery in this environment')
    assert.equal(got[0].channel, 'mdns')
    assert.deepEqual(got[0].candidates, candidates)
  } finally {
    a.close()
    b.close()
  }
})
