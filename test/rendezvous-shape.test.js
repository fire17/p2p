// test/rendezvous-shape.test.js — all three rendezvous channels expose the SAME uniform
// descriptor so createRace can consume them interchangeably. Backends are mocked → offline.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { createMdns } from '../src/rendezvous/mdns.js'
import { createDht } from '../src/rendezvous/dht.js'
import { createTracker } from '../src/rendezvous/tracker.js'

// inert dgram socket (mdns needs no real network for a shape check)
const inertSocket = () => {
  const s = new EventEmitter()
  s.bind = (_p, cb) => cb && setImmediate(cb)
  s.addMembership = () => {}
  s.setMulticastTTL = () => {}
  s.send = () => {}
  s.close = () => {}
  return s
}

function mockDht() {
  return {
    calls: [],
    getPeers(rid, o) {
      this.calls.push({ ridHex: rid.toString('hex'), o })
      return Promise.resolve({ peers: ['1.2.3.4:5', '6.7.8.9:10'] })
    },
    close() {
      this.closed = true
    },
  }
}

const DESCRIPTOR_KEYS = ['announce', 'close', 'lookup', 'name', 'ridLen']

function makeAll() {
  const dhtBackend = mockDht()
  const probed = []
  return {
    dhtBackend,
    probed,
    mdns: createMdns({ socketFactory: inertSocket }),
    dht: createDht({ dht: dhtBackend, now: () => 1000 }),
    tracker: createTracker({ probe: (url, ih) => (probed.push({ url, ih }), Promise.resolve({ ok: true })), trackers: ['wss://x'] }),
  }
}

test('all three factories return the identical uniform descriptor shape', () => {
  const { mdns, dht, tracker } = makeAll()
  for (const [ch, name, ridLen] of [[mdns, 'mdns', 32], [dht, 'dht', 20], [tracker, 'tracker', 20]]) {
    assert.deepEqual(Object.keys(ch).sort(), DESCRIPTOR_KEYS, `${name} descriptor keys`)
    assert.equal(ch.name, name)
    assert.equal(ch.ridLen, ridLen)
    assert.equal(typeof ch.announce, 'function')
    assert.equal(typeof ch.lookup, 'function')
    assert.equal(typeof ch.close, 'function')
    const it = ch.lookup(Buffer.alloc(ridLen, 7))
    assert.equal(typeof it[Symbol.asyncIterator], 'function', `${name}.lookup is async-iterable`)
    it.return?.() // don't leave the generator open
  }
  mdns.close()
  dht.close()
  tracker.close()
})

test('createDht: announce → announce_peer with marker port; lookup yields ip:port candidates', async () => {
  const backend = mockDht()
  const dht = createDht({ dht: backend, now: () => 4242 })
  const rid = Buffer.alloc(20, 0xa1)

  const h = dht.announce(rid, { port: 6881 })
  assert.equal(typeof h.stop, 'function') // optional {stop} honored
  assert.equal(backend.calls.length, 1)
  assert.equal(backend.calls[0].o.announce, true)
  assert.equal(backend.calls[0].o.port, 6881)

  const out = []
  for await (const rec of dht.lookup(rid)) out.push(rec)
  assert.equal(out.length, 1)
  assert.equal(out[0].channel, 'dht')
  assert.equal(out[0].ts, 4242)
  assert.deepEqual(out[0].candidates, [
    { proto: 'udp4', ip: '1.2.3.4', port: 5, kind: 'srflx' },
    { proto: 'udp4', ip: '6.7.8.9', port: 10, kind: 'srflx' },
  ])
  dht.close()
  assert.equal(backend.closed, true)
})

test('createDht: lookup yields nothing when no peers found', async () => {
  const backend = { getPeers: () => Promise.resolve({ peers: [] }), close() {} }
  const dht = createDht({ dht: backend })
  const out = []
  for await (const rec of dht.lookup(Buffer.alloc(20, 1))) out.push(rec)
  assert.equal(out.length, 0)
})

test('createTracker: announce echoes to tracker (hex info_hash); lookup empty in v1 (relay is P1)', async () => {
  const probed = []
  const tracker = createTracker({ probe: (url, ih) => (probed.push({ url, ih }), Promise.resolve({ ok: true })), trackers: ['wss://t'] })
  const rid = Buffer.alloc(20, 0x5c)
  tracker.announce(rid, { v: 1, candidates: [] })
  await Promise.resolve() // let the fire-and-forget microtask run
  assert.equal(probed.length, 1)
  assert.equal(probed[0].url, 'wss://t')
  assert.equal(probed[0].ih, rid.toString('hex'))

  const out = []
  for await (const rec of tracker.lookup(rid)) out.push(rec)
  assert.equal(out.length, 0)
  tracker.close()
})

test('rid must be a Buffer across dht + tracker', () => {
  const dht = createDht({ dht: mockDht() })
  const tracker = createTracker({ probe: () => Promise.resolve({}) })
  assert.throws(() => dht.announce('nope', {}), TypeError)
  assert.throws(() => tracker.announce('nope'), TypeError)
  // lookup guards too (generator throws on first pull)
  assert.rejects(async () => { for await (const _ of dht.lookup('nope')) void _ }, TypeError)
  assert.rejects(async () => { for await (const _ of tracker.lookup('nope')) void _ }, TypeError)
})

test('createRace consumes all three uniformly (integration smoke)', async () => {
  const { createRace } = await import('../src/rendezvous/race.js')
  const { mdns, dht, tracker } = makeAll()
  const race = createRace({ channels: [mdns, dht, tracker], now: () => Date.parse('2026-07-11T12:00:00Z') })
  // publishAll must not throw wiring all three
  const handle = race.publishAll('0QNPVP2F1Y1W9WHCRY3ZCPC5MJ', { candidates: () => [{ proto: 'udp4', ip: '2.2.2.2', port: 9, kind: 'host' }], on() {}, off() {} })
  handle.stop()
  // resolve merges dht candidates (mdns/tracker mocks surface none here)
  const out = []
  // short lookup window: mdns/tracker mocks surface nothing, dht mock resolves immediately
  for await (const c of race.resolve('0QNPVP2F1Y1W9WHCRY3ZCPC5MJ', { timeout: 100 })) out.push(c)
  assert.ok(out.some((c) => c.channel === 'dht'))
  mdns.close()
  dht.close()
  tracker.close()
})
