// test/transport-wss-epoch.test.js — the listener's relay inbox must ROLL with the UTC day.
//
// THE DEFECT (found 2026-09-13 while reading this code for the Debian-VPS join failures; NOT that
// incident's cause): src/transport-wss.js derived the listener's inbox topics ONCE, at
// createEndpoint — epochStr(now-1d), epochStr(now), epochStr(now+1d) — and nothing ever added the
// next day's topic. A dialer always knocks topicFor(S, epochStr(now())) (transport-wss's
// createWssRendezvous.resolve / transport-node.js), so a `tunnel listen` daemon still alive two UTC
// midnights later held NO subscription for the topic being knocked on: unreachable over the relay
// by any NEW dial. The MIND's listeners run for days.
//
// Deterministic: injected clock + the in-process mock MQTT broker. No network, no real broker, no
// UDP, no mDNS — this file cannot disturb a live session on this machine.

import test from 'node:test'
import assert from 'node:assert/strict'
import { createEndpoint, topicFor, epochStr } from '../src/transport-wss.js'
import { encodeFrame, decodeFrame, TYPE } from '../src/wire.js'
import { mockRelay } from './fixtures/mock-relay.mjs'

const RELAYS = ['ws://mock-relay']
const DAY_MS = 86400000
const S = '0123456789ABCDEFGHJKMNPQRS'   // a valid 26-char Crockford contact string (checksum unused by the KDF)
const delay = (ms) => new Promise((r) => setTimeout(r, ms))

/** A well-formed wire frame — what a real HELLO looks like on the relay (>= HEADER_LEN). */
const helloFrame = () => encodeFrame(TYPE.HELLO, Buffer.alloc(8), 0, 0, Buffer.from('intro'))

/** Poll until cond() or the deadline; returns cond()'s final value. */
async function until(cond, ms, step = 10) {
  const t0 = Date.now()
  while (Date.now() - t0 < ms) { if (cond()) return true; await delay(step) }
  return cond()
}

/**
 * One scenario: a listener created at day D, the clock advanced by `advanceDays`, then a fresh
 * dial-only endpoint knocking the topic for the CURRENT (advanced) day.
 */
async function scenario({ advanceDays, epochRollMs = 20 }) {
  const relay = mockRelay({ hopMs: 15 })
  let clock = Date.UTC(2026, 8, 13, 12)                     // 2026-09-13T12:00:00Z — a fixed day D
  const now = () => clock
  const opts = { relays: RELAYS, WebSocket: relay.WebSocket, now }

  const listener = createEndpoint({ S, ...opts, epochRollMs })
  const frames = []
  let connected = false
  listener.onConnection((sock) => { connected = true; sock.onMessage = (f) => frames.push(Buffer.from(f)) })
  await delay(60)                                           // CONNACK + the initial SUBACKs

  clock += advanceDays * DAY_MS
  await delay(80)                                           // >= 3 roll ticks at epochRollMs = 20

  const dialer = createEndpoint({ S: null, ...opts })
  await delay(30)
  const sock = await dialer.punch([{ proto: 'wss', topic: topicFor(S, epochStr(clock)), relays: RELAYS }])
  sock.send(helloFrame())
  const gotHello = () => frames.some((f) => { const d = decodeFrame(f); return d && d.type === TYPE.HELLO })
  const ok = await until(() => connected && gotHello(), 500)

  return {
    get connected() { return connected }, ok, frames, listener, dialer, relay, clock,
    close() {
      try { dialer.close() } catch { /* */ }
      try { listener.close() } catch { /* */ }
      relay.close()
    },
  }
}

test('EPOCH-ROLL (1): a listener two UTC days old is still reachable — the inbox rolled', async () => {
  const s = await scenario({ advanceDays: 2 })
  try {
    assert.equal(s.connected, true, 'the listener must accept a dial knocking the CURRENT day topic (RED on 1cb873a: onConnection never fires)')
    assert.equal(s.ok, true, 'a well-formed HELLO must reach the listener over the rolled topic')
    assert.ok(s.listener.topics.includes(topicFor(S, epochStr(s.clock))), `topics must now include day D+2 (${s.listener.topics.length} topics held)`)
  } finally { s.close() }
})

test('EPOCH-ROLL (2) clean case: a fresh listener is reachable on day D (green before and after the fix)', async () => {
  const s = await scenario({ advanceDays: 0 })
  try {
    assert.equal(s.connected, true, 'same-day dial must connect')
    assert.equal(s.ok, true, 'the HELLO must arrive')
    assert.equal(s.listener.topics.length, 3, 'prev/cur/next only — no new topic on day D')
  } finally { s.close() }
})

test('EPOCH-ROLL (3): close() clears the roll timer; a dial-only endpoint never arms one', async () => {
  const relay = mockRelay({ hopMs: 15 })
  const now = () => Date.UTC(2026, 8, 13, 12)
  const listener = createEndpoint({ S, relays: RELAYS, WebSocket: relay.WebSocket, now, epochRollMs: 20 })
  const dialOnly = createEndpoint({ S: null, relays: RELAYS, WebSocket: relay.WebSocket, now, epochRollMs: 20 })
  try {
    assert.equal(typeof listener._debug.rollActive, 'function', '_debug.rollActive must exist (RED on 1cb873a)')
    assert.equal(listener._debug.rollActive(), true, 'a listener arms the roll timer')
    assert.equal(dialOnly._debug.rollActive(), false, 'a dial-only endpoint (no S) arms nothing')
    listener.close()
    assert.equal(listener._debug.rollActive(), false, 'close() must clear the roll timer')
  } finally {
    try { listener.close() } catch { /* */ }
    dialOnly.close()
    relay.close()
  }
})
