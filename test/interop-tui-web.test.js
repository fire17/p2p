// test/interop-tui-web.test.js — tui↔web interop + the tui↔tui non-regression that gates it.
//
// THE BUG THIS GUARDS: the TUI's node stood up only the UDP endpoint (src/transport.js) while the
// browser speaks WebRTC + the WSS relay (src/browser/transport.js). No shared transport ⇒ a browser
// and a TUI could never meet, however well rendezvous worked. src/transport-node.js composes the
// relay into the node's DEFAULT endpoint, so they now share one.
//
// EVERYTHING HERE IS IN-PROCESS. The relay is a fake MQTT broker (test/fixtures/mock-relay.mjs) and
// UDP is loopback-only with explicit 127.0.0.1 candidates. NO mDNS, NO LAN broadcast, no network —
// this suite must never disturb a live tui↔tui session on the same machine.
//
// Real key.js / noise.js / wire.js / transport.js / transport-wss.js run underneath: the commitment
// gate and the Noise IK genuinely execute over both pipes.

import test from 'node:test'
import assert from 'node:assert/strict'
import { listen } from '../src/node.js'
import * as nodeTransport from '../src/transport-node.js'
import { createEndpoint as createWssEndpoint, createWssRendezvous } from '../src/transport-wss.js'
import * as key from '../src/key.js'
import * as noise from '../src/noise.js'
import { mockRelay } from './fixtures/mock-relay.mjs'

const RELAYS = ['ws://mock-relay']
const delay = (ms) => new Promise((r) => setTimeout(r, ms))
const crypto = () => ({
  generateIdentity: key.generateIdentity, decodeKey: key.decodeKey,
  verifyCommitment: key.verifyCommitment, encodeKey: key.encodeKey,
  initiator: noise.initiator, responder: noise.responder,
})

/** A TUI peer: node.js's DEFAULT endpoint (UDP + WSS composed), with the relay pointed at the mock. */
async function tuiPeer(relay, { resolve, wssDelayMs = 700 } = {}) {
  const id = await key.generateIdentity()
  let ep = null
  const node = await listen(id, {
    deps: {
      ...crypto(),
      createEndpoint: async (o) => (ep = await nodeTransport.createEndpoint({
        ...o, relays: RELAYS, WebSocket: relay.WebSocket, wssDelayMs,
      })),
      resolve: async (S) => resolve(String(S)),
      publishAll: () => ({ stop() {} }),          // no mDNS / DHT / tracker — nothing announced
    },
  })
  return { id, node, ep, got: collect(node) }
}

/** A BROWSER peer, modelled honestly: the WSS relay is the ONLY transport it shares with a TUI. */
async function webPeer(relay) {
  const id = await key.generateIdentity()
  const ep = createWssEndpoint({ S: id.S, relays: RELAYS, WebSocket: relay.WebSocket })
  const rv = createWssRendezvous({ relays: RELAYS })
  const node = await listen(id, {
    endpoint: ep,
    deps: { ...crypto(), createEndpoint: async () => ep, resolve: (S) => rv.resolve(String(S)), publishAll: () => ({ stop() {} }) },
  })
  return { id, node, ep, got: collect(node) }
}

function collect(node) {
  const got = []
  node.on('message', (_p, m) => got.push(m.toString()))
  return got
}

/** The peer record the LISTENER ends up with (its 'peer' event, or the one already established). */
function listenerPeer(node, ms = 8000) {
  const live = node.peers().find((p) => p.connected)
  if (live) return Promise.resolve(live)
  return new Promise((res, rej) => {
    const t = setTimeout(() => rej(new Error('listener never established a peer')), ms)
    node.on('peer', (p) => { clearTimeout(t); res(p) })
  })
}

const race = (p, ms, what) => Promise.race([p, delay(ms).then(() => { throw new Error('timed out: ' + what) })])

// ── tui ↔ web ────────────────────────────────────────────────────────────────────────────────────

test('tui↔web: a BROWSER peer dials a TUI peer and they exchange messages over the relay', async () => {
  const relay = mockRelay()
  const tui = await tuiPeer(relay, { resolve: () => [] })          // no UDP candidates in play at all
  const web = await webPeer(relay)

  const p = await race(web.node.connect(tui.id.S), 10000, 'web -> tui connect')
  const tuiSide = await race(listenerPeer(tui.node), 10000, 'tui accept')

  await race(p.send('hello from the browser'), 8000, 'web -> tui msg')
  await race(tuiSide.send('hello from the TUI'), 8000, 'tui -> web msg')
  await delay(50)

  assert.deepEqual(tui.got, ['hello from the browser'])
  assert.deepEqual(web.got, ['hello from the TUI'])
  assert.equal(tui.node._peers.size, 1, 'one dial => exactly one peer record on the TUI')
  web.node.close(); tui.node.close(); relay.close()
})

test('tui↔web: a TUI peer dials a BROWSER peer (zero UDP candidates — the relay topic comes from S)', async () => {
  const relay = mockRelay()
  const web = await webPeer(relay)
  // The browser publishes NO udp candidates, so rendezvous yields none. The dial must still work:
  // transport-node derives the relay topic from the peer's S (HKDF(S,…)) — no rendezvous needed.
  const tui = await tuiPeer(relay, { resolve: () => [] })

  const p = await race(tui.node.connect(web.id.S), 10000, 'tui -> web connect')
  const webSide = await race(listenerPeer(web.node), 10000, 'web accept')

  await race(p.send('tui dialed you'), 8000, 'tui -> web msg')
  await race(webSide.send('browser answered'), 8000, 'web -> tui msg')
  await delay(50)

  assert.deepEqual(web.got, ['tui dialed you'])
  assert.deepEqual(tui.got, ['browser answered'])
  assert.equal(web.node._peers.size, 1, 'one dial => exactly one peer record on the browser')
  tui.node.close(); web.node.close(); relay.close()
})

// ── tui ↔ tui (the coupling: composing WSS in must NOT regress the TUI pair) ─────────────────────

test('tui↔tui: still connects over LOOPBACK UDP — and never touches the relay', async () => {
  const relay = mockRelay()
  const eps = new Map()                                            // S -> endpoint (for loopback candidates)
  const resolve = (S) => {
    const ep = eps.get(S)
    return ep ? [{ proto: 'udp4', ip: '127.0.0.1', port: ep.port4, kind: 'lan' }] : []
  }
  const a = await tuiPeer(relay, { resolve }); eps.set(a.id.S, a.ep)
  const b = await tuiPeer(relay, { resolve }); eps.set(b.id.S, b.ep)

  const p = await race(a.node.connect(b.id.S), 10000, 'tui -> tui connect')
  const bSide = await race(listenerPeer(b.node), 10000, 'tui accept')
  await race(p.send('over udp'), 8000, 'a -> b')
  await race(bSide.send('over udp back'), 8000, 'b -> a')
  await delay(50)

  assert.deepEqual(b.got, ['over udp'])
  assert.deepEqual(a.got, ['over udp back'])
  assert.equal(b.node._peers.size, 1, 'one dial => one peer record')
  // The relay leg is held back 700ms and skipped outright once UDP delivers first contact: a TUI pair
  // must not silently bounce its chat off a public broker.
  assert.equal(relay.published, 0, `tui↔tui published ${relay.published} frames to the relay (must be 0)`)
  a.node.close(); b.node.close(); relay.close()
})

test('tui↔tui: UDP dead ⇒ the relay leg carries the dial (the ladder floor still holds)', async () => {
  const relay = mockRelay()
  // Candidates that will never answer (a closed loopback port) — the UDP punch fails, the relay must
  // pick it up. wssDelayMs is dropped to 50ms so the test does not pay the full head start.
  const b = await tuiPeer(relay, { resolve: () => [], wssDelayMs: 50 })
  const a = await tuiPeer(relay, {
    resolve: () => [{ proto: 'udp4', ip: '127.0.0.1', port: 1, kind: 'lan' }],   // black hole
    wssDelayMs: 50,
  })

  const p = await race(a.node.connect(b.id.S), 15000, 'relay-fallback connect')
  const bSide = await race(listenerPeer(b.node), 10000, 'relay accept')
  await race(p.send('via relay'), 8000, 'a -> b')
  await delay(50)
  assert.deepEqual(b.got, ['via relay'])
  assert.ok(relay.published > 0, 'the relay actually carried this dial')
  assert.ok(bSide.connected)
  a.node.close(); b.node.close(); relay.close()
})

// ── glare: racing two transports must yield ONE session ──────────────────────────────────────────

test('GLARE: 10 raced dials (UDP + relay legs, relay winning) each yield ONE session, 10/10 delivered', async () => {
  let ok = 0
  const detail = []
  for (let i = 0; i < 10; i++) {
    const relay = mockRelay({ hopMs: 1 })                          // relay is FAST here: it wins the race
    const b = await tuiPeer(relay, { resolve: () => [], wssDelayMs: 0 })
    const a = await tuiPeer(relay, {
      resolve: () => [{ proto: 'udp4', ip: '127.0.0.1', port: 1, kind: 'lan' }],  // UDP leg races but is dead
      wssDelayMs: 0,                                               // no head start ⇒ both legs run together
    })
    try {
      const p = await race(a.node.connect(b.id.S), 15000, 'connect#' + i)
      const bSide = await race(listenerPeer(b.node), 8000, 'accept#' + i)
      await race(p.send('m' + i), 8000, 'a2b#' + i)
      await race(bSide.send('r' + i), 8000, 'b2a#' + i)
      await delay(30)
      const clean = b.got.length === 1 && a.got.length === 1 && b.node._peers.size === 1 && a.node._peers.size === 1
      if (clean) ok++
      detail.push(`#${i} a2b=${b.got.length} b2a=${a.got.length} peersB=${b.node._peers.size}`)
    } catch (e) {
      detail.push(`#${i} FAILED: ${e.message}`)
    }
    a.node.close(); b.node.close(); relay.close()
  }
  assert.equal(ok, 10, `only ${ok}/10 raced dials produced one clean session:\n` + detail.join('\n'))
})
