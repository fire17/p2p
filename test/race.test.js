// test/race.test.js — orchestrator: publish fan-out, epoch/pre-announce, netchange, and the
// merged/deduped/ranked/capped resolve stream. Channels are mocked.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import {
  createRace,
  epochStr,
  msUntilRollover,
  announceEpochs,
  resolveEpochs,
  candidateKey,
} from '../src/rendezvous/race.js'
import { deriveRid } from '../src/key.js'

const S = '0QNPVP2F1Y1W9WHCRY3ZCPC5MJ' // valid frozen contact string (from key.test.js KAT)
const MIDDAY = Date.parse('2026-07-11T12:00:00Z')
const NEAR_ROLLOVER = Date.parse('2026-07-11T23:30:00Z')

function mockChannel(name, ridLen, lookupRecords = []) {
  const announced = []
  return {
    name,
    ridLen,
    announce(rid, info) {
      announced.push({ ridHex: rid.toString('hex'), info })
    },
    async *lookup() {
      for (const rec of lookupRecords) yield rec
    },
    _announced: announced,
  }
}

// ── pure epoch helpers ────────────────────────────────────────────────────────
test('epoch helpers', () => {
  assert.equal(epochStr(MIDDAY), '2026-07-11')
  assert.equal(msUntilRollover(MIDDAY), 12 * 3600_000)
  assert.equal(msUntilRollover(NEAR_ROLLOVER), 30 * 60_000)
  assert.deepEqual(announceEpochs(MIDDAY), ['2026-07-11']) // not near rollover
  assert.deepEqual(announceEpochs(NEAR_ROLLOVER), ['2026-07-11', '2026-07-12']) // pre-announce
  assert.deepEqual(resolveEpochs(MIDDAY), ['2026-07-10', '2026-07-11', '2026-07-12'])
  assert.equal(candidateKey({ proto: 'udp4', ip: '1.2.3.4', port: 9 }), 'udp4:1.2.3.4:9')
})

// ── publishAll fan-out ────────────────────────────────────────────────────────
test('publishAll fans out per-channel rid (today only, midday)', () => {
  const mdns = mockChannel('mdns', 32)
  const dht = mockChannel('dht', 20)
  const race = createRace({ channels: [mdns, dht], now: () => MIDDAY })
  const endpoint = {
    candidates: () => [
      { proto: 'udp4', ip: '9.9.9.9', port: 5000, kind: 'srflx' },
      { proto: 'tcp', ip: '9.9.9.9', port: 5001, kind: 'host' },
    ],
    on() {},
    off() {},
  }
  const handle = race.publishAll(S, endpoint)

  assert.equal(mdns._announced.length, 1)
  assert.equal(dht._announced.length, 1)
  // rid matches key.deriveRid for this channel/epoch/len
  assert.equal(mdns._announced[0].ridHex, deriveRid(S, 'mdns', '2026-07-11', 32).toString('hex'))
  assert.equal(dht._announced[0].ridHex, deriveRid(S, 'dht', '2026-07-11', 20).toString('hex'))
  // mdns gets the FULL blob; dht gets port only (DESIGN D6)
  assert.deepEqual(mdns._announced[0].info.candidates.length, 2)
  assert.deepEqual(dht._announced[0].info, { port: 5000 }) // first udp candidate's port
  handle.stop()
})

test('publishAll pre-announces tomorrow within 1h of rollover', () => {
  const mdns = mockChannel('mdns', 32)
  const race = createRace({ channels: [mdns], now: () => NEAR_ROLLOVER })
  const handle = race.publishAll(S, { candidates: () => [], on() {}, off() {} })
  assert.equal(mdns._announced.length, 2)
  assert.equal(mdns._announced[0].ridHex, deriveRid(S, 'mdns', '2026-07-11', 32).toString('hex'))
  assert.equal(mdns._announced[1].ridHex, deriveRid(S, 'mdns', '2026-07-12', 32).toString('hex'))
  handle.stop()
})

test('publishAll re-announces on netchange', () => {
  const mdns = mockChannel('mdns', 32)
  const race = createRace({ channels: [mdns], now: () => MIDDAY })
  const endpoint = new EventEmitter()
  endpoint.candidates = () => [{ proto: 'udp4', ip: '1.1.1.1', port: 1, kind: 'host' }]
  const handle = race.publishAll(S, endpoint)
  assert.equal(mdns._announced.length, 1)
  endpoint.emit('netchange')
  assert.equal(mdns._announced.length, 2)
  handle.stop()
  endpoint.emit('netchange') // after stop: no more announces
  assert.equal(mdns._announced.length, 2)
})

// ── resolve merge / dedup / rank / cap ─────────────────────────────────────────
const C = (ip, port, proto = 'udp4', kind = 'host') => ({ proto, ip, port, kind })

test('resolve dedups mDNS candidates across epochs, tagging channel + score', async () => {
  const mdns = mockChannel('mdns', 32, [{ candidates: [C('192.168.0.2', 22, 'udp4', 'lan'), C('5.5.5.5', 100)], channel: 'mdns', ts: MIDDAY }])
  const race = createRace({ channels: [mdns], now: () => MIDDAY })

  const out = []
  for await (const c of race.resolve(S, { lanGraceMs: 0 })) out.push(c)

  // mdns is queried once per epoch (yesterday/today/tomorrow) → the same 2 candidates arrive 3×
  // and must dedup to 2 unique, each tagged + scored
  const keys = out.map(candidateKey).sort()
  assert.deepEqual(keys, ['udp4:192.168.0.2:22', 'udp4:5.5.5.5:100'])
  for (const c of out) {
    assert.equal(c.channel, 'mdns')
    assert.equal(typeof c.score, 'number')
  }
})

test('resolve skips DHT when mDNS finds a peer; falls back to DHT only when mDNS is empty (D6)', async () => {
  // (a) mDNS yields → DHT lookup must NOT run at all
  const mdnsHit = mockChannel('mdns', 32, [{ candidates: [C('192.168.0.9', 1, 'udp4', 'lan')], channel: 'mdns', ts: MIDDAY }])
  let dhtStarted = false
  const dhtSpy = { name: 'dht', ridLen: 20, announce() {}, async *lookup() { dhtStarted = true; if (false) yield {} } }
  let race = createRace({ channels: [mdnsHit, dhtSpy], now: () => MIDDAY })
  let out = []
  for await (const c of race.resolve(S, { lanGraceMs: 0 })) out.push(c)
  assert.deepEqual(out.map(candidateKey), ['udp4:192.168.0.9:1']) // 3 epochs, deduped to 1
  assert.equal(out[0].channel, 'mdns')
  assert.equal(dhtStarted, false, 'DHT lookup must NOT run when mDNS already found a peer')

  // (b) mDNS empty → DHT fallback runs and its candidates surface, ranked as dht (weight ≥ 2e6)
  const mdnsEmpty = mockChannel('mdns', 32, [])
  const dht = mockChannel('dht', 20, [{ candidates: [C('8.8.8.8', 80)], channel: 'dht', ts: MIDDAY }])
  race = createRace({ channels: [mdnsEmpty, dht], now: () => MIDDAY })
  out = []
  for await (const c of race.resolve(S, { lanGraceMs: 0 })) out.push(c)
  assert.deepEqual(out.map(candidateKey), ['udp4:8.8.8.8:80'])
  assert.equal(out[0].channel, 'dht')
  assert.ok(out[0].score >= 2e6)
})

test('resolve enforces per-channel and global dial caps', async () => {
  const many = Array.from({ length: 15 }, (_, i) => C('10.0.0.' + i, 3000 + i))
  // per-channel cap bounds a single (mDNS) channel
  let mdns = mockChannel('mdns', 32, [{ candidates: many, channel: 'mdns', ts: MIDDAY }])
  let race = createRace({ channels: [mdns], now: () => MIDDAY, perChannelCap: 8, dialCap: 20 })
  let out = []
  for await (const c of race.resolve(S, { lanGraceMs: 0 })) out.push(c)
  assert.equal(out.length, 8, 'per-channel cap (8) bounds mDNS')

  // global dialCap bounds the total
  mdns = mockChannel('mdns', 32, [{ candidates: many, channel: 'mdns', ts: MIDDAY }])
  race = createRace({ channels: [mdns], now: () => MIDDAY, perChannelCap: 20, dialCap: 5 })
  out = []
  for await (const c of race.resolve(S, { lanGraceMs: 0 })) out.push(c)
  assert.equal(out.length, 5, 'global dialCap bounds the total')
})

test('createRace rejects empty channel set', () => {
  assert.throws(() => createRace({ channels: [] }), TypeError)
  assert.throws(() => createRace({}), TypeError)
})
