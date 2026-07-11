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

test('resolve merges + dedups across channels and epochs, tagging channel + score', async () => {
  const shared = C('5.5.5.5', 100)
  const mdns = mockChannel('mdns', 32, [{ candidates: [C('192.168.0.2', 22, 'udp4', 'lan'), shared], channel: 'mdns', ts: MIDDAY }])
  const dht = mockChannel('dht', 20, [{ candidates: [shared, C('8.8.8.8', 80)], channel: 'dht', ts: MIDDAY }])
  const race = createRace({ channels: [mdns, dht], now: () => MIDDAY })

  const out = []
  for await (const c of race.resolve(S)) out.push(c)

  // unique candidates: lan, shared, 8.8.8.8 → 3 (shared appears in both but deduped once)
  const keys = out.map(candidateKey).sort()
  assert.deepEqual(keys, ['udp4:192.168.0.2:22', 'udp4:5.5.5.5:100', 'udp4:8.8.8.8:80'])
  // every candidate is channel-tagged and scored
  for (const c of out) {
    assert.ok(c.channel === 'mdns' || c.channel === 'dht')
    assert.equal(typeof c.score, 'number')
  }
  // mdns-sourced candidates rank ahead of dht-sourced (lower score)
  const lan = out.find((c) => c.ip === '192.168.0.2')
  const dhtOnly = out.find((c) => c.ip === '8.8.8.8')
  assert.ok(lan.score < dhtOnly.score)
})

test('resolve enforces per-channel and global dial caps', async () => {
  const many = Array.from({ length: 15 }, (_, i) => C('10.0.0.' + i, 3000 + i))
  const mdns = mockChannel('mdns', 32, [{ candidates: many, channel: 'mdns', ts: MIDDAY }])
  const dht = mockChannel('dht', 20, [{ candidates: many.map((c) => ({ ...c, ip: '11.0.0' + c.port })), channel: 'dht', ts: MIDDAY }])
  const race = createRace({ channels: [mdns, dht], now: () => MIDDAY, perChannelCap: 8, dialCap: 12 })

  const out = []
  for await (const c of race.resolve(S)) out.push(c)
  assert.ok(out.length <= 12, 'global dialCap respected')
  assert.ok(out.filter((c) => c.channel === 'mdns').length <= 8, 'per-channel cap respected')
})

test('createRace rejects empty channel set', () => {
  assert.throws(() => createRace({ channels: [] }), TypeError)
  assert.throws(() => createRace({}), TypeError)
})
