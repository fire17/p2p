// test/browser-duplicate-identity.test.js — the "connected, but no messages" bug and its guard.
//
// THE BUG (reproduced below, at the protocol layer): a browser tab with no `#id=` boots the DEFAULT
// slot, and the default slot is ONE IndexedDB record — so two ordinary tabs are the SAME peer with
// the SAME static keypair. Both subscribe the same rendezvous topic (HKDF(S,…)), both ACCEPT the
// same incoming dial, and both complete a genuine Noise IK (each really does hold the private key —
// no protocol check can separate them). The dialer binds to whichever answered first; every other
// tab shows "✅ secure channel established" and receives NOTHING. It reads as ~50% message loss,
// because the messages are landing in the other tab.
//
// THE GUARD: claimIdentity() — an identity may be ONLINE in exactly one tab (a Web Lock named for S,
// held for the node's lifetime). Fails OPEN where Web Locks are unavailable: this catches a footgun,
// it must never be the reason someone cannot get online.
//
// In-process: real key/noise/wire + a mock MQTT relay. No mDNS, no LAN UDP, no network.

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { listen } from '../src/node.js'
import { claimIdentity } from '../src/browser/p2p.js'
import { createEndpoint as wssEndpoint, createWssRendezvous } from '../src/transport-wss.js'
import * as key from '../src/key.js'
import * as noise from '../src/noise.js'
import { mockRelay } from './fixtures/mock-relay.mjs'

const delay = (ms) => new Promise((r) => setTimeout(r, ms))

/** A LockManager with the two behaviours we depend on: exclusivity, and ifAvailable ⇒ cb(null). */
function fakeLocks() {
  const held = new Set()
  return {
    held,
    request(name, opts, cb) {
      if (opts && opts.ifAvailable && held.has(name)) return Promise.resolve(cb(null))
      held.add(name)
      return Promise.resolve(cb({ name })).finally(() => held.delete(name))
    },
  }
}

// ── the guard ────────────────────────────────────────────────────────────────────────────────────

test('claimIdentity: the FIRST tab holds the identity; a SECOND tab on the same S is refused', async () => {
  const locks = fakeLocks()
  const tab1 = await claimIdentity('SSSS', locks)
  assert.equal(tab1.held, true, 'the first tab comes online')

  const tab2 = await claimIdentity('SSSS', locks)
  assert.equal(tab2.held, false, 'a second tab on the SAME identity must NOT come online')

  // A different identity is unaffected — the lock is per-S, not a global mutex.
  const other = await claimIdentity('TTTT', locks)
  assert.equal(other.held, true, 'a different identity still comes online')
})

test('claimIdentity: closing the holding tab frees the identity for the next one', async () => {
  const locks = fakeLocks()
  const tab1 = await claimIdentity('SSSS', locks)
  assert.equal(tab1.held, true)
  assert.equal((await claimIdentity('SSSS', locks)).held, false)

  tab1.release()                                   // the tab closed / node.close()
  await delay(0)                                   // the lock callback settles
  assert.equal((await claimIdentity('SSSS', locks)).held, true, 'the identity is claimable again')
})

test('claimIdentity: FAILS OPEN — no Web Locks API, or a throwing one, must never keep a user offline', async () => {
  assert.equal((await claimIdentity('SSSS', undefined)).held, true, 'no LockManager ⇒ come online')
  assert.equal((await claimIdentity('SSSS', {})).held, true, 'LockManager without request() ⇒ come online')
  const throwing = { request() { throw new Error('SecurityError') } }
  assert.equal((await claimIdentity('SSSS', throwing)).held, true, 'a throwing LockManager ⇒ come online')
  const rejecting = { request: () => Promise.reject(new Error('nope')) }
  assert.equal((await claimIdentity('SSSS', rejecting)).held, true, 'a rejecting LockManager ⇒ come online')
})

// ── the failure the guard exists to prevent (protocol-level, unguarded) ──────────────────────────

test('UNGUARDED duplicate identity: BOTH tabs "connect", only ONE ever receives — the zombie tab', async () => {
  // Every timer in this stack is unref'd (mock relay + node's tick), so nothing holds the event loop
  // open while we await the dial. Pin it for the duration of the test.
  const hold = setInterval(() => {}, 50)
  const relay = mockRelay()
  const RELAYS = ['ws://mock-relay']
  const rv = createWssRendezvous({ relays: RELAYS })
  const deps = () => ({
    generateIdentity: key.generateIdentity, decodeKey: key.decodeKey,
    verifyCommitment: key.verifyCommitment, encodeKey: key.encodeKey,
    initiator: noise.initiator, responder: noise.responder,
    resolve: (S) => rv.resolve(String(S)), publishAll: () => ({ stop() {} }),
  })
  /** A tab. Two tabs built from the SAME identity are what the default slot actually hands out. */
  const tab = async (id) => {
    const ep = wssEndpoint({ S: id.S, relays: RELAYS, WebSocket: relay.WebSocket })
    const node = await listen(id, { endpoint: ep, deps: { ...deps(), createEndpoint: async () => ep } })
    const got = []
    node.on('message', (_p, m) => got.push(m.toString()))
    return { node, got }
  }

  const dflt = await key.generateIdentity()             // the DEFAULT slot's one record
  const tab1 = await tab(dflt)
  const tab2 = await tab(dflt)                          // a second plain tab: same slot, same identity
  const fresh = await tab(await key.generateIdentity()) // the peer they are chatting with

  const peer = await fresh.node.connect(dflt.S)
  await delay(150)
  await peer.send('does this reach you?')
  await delay(300)

  const connected = [tab1, tab2].filter((t) => t.node.peers().some((p) => p.connected)).length
  const receiving = [tab1, tab2].filter((t) => t.got.length > 0).length

  assert.equal(connected, 2, 'both tabs complete a real Noise IK — the protocol cannot tell them apart')
  assert.equal(receiving, 1, 'but only ONE of them ever receives the message')
  // …which is precisely the user-visible bug: a tab that says "connected" and is deaf forever.
  assert.equal(connected - receiving, 1, 'exactly one CONNECTED-but-silent zombie tab')

  tab1.node.close(); tab2.node.close(); fresh.node.close(); relay.close()
  clearInterval(hold)
})

// ── the guarded path: the zombie must be STRUCTURALLY IMPOSSIBLE ─────────────────────────────────

test('GUARDED: a second tab auto-adopts a fresh identity — two REAL peers, and NO connected-but-silent tab', async () => {
  const hold = setInterval(() => {}, 50)
  const relay = mockRelay()
  const RELAYS = ['ws://mock-relay']
  const rv = createWssRendezvous({ relays: RELAYS })
  const locks = fakeLocks()                            // ONE LockManager = one browser, many tabs
  const deps = () => ({
    generateIdentity: key.generateIdentity, decodeKey: key.decodeKey,
    verifyCommitment: key.verifyCommitment, encodeKey: key.encodeKey,
    initiator: noise.initiator, responder: noise.responder,
    resolve: (S) => rv.resolve(String(S)), publishAll: () => ({ stop() {} }),
  })

  /**
   * A tab going online exactly as app.js now does: claim the identity; if it is already live in
   * another tab, adopt a FRESH one (app.js does this by minting the next free slot) and claim that.
   * A tab therefore either owns its identity or has a different one — it never runs as a duplicate.
   */
  const goOnline = async (want) => {
    let id = want
    let lease = await claimIdentity(id.S, locks)
    if (!lease.held) {                                 // already open in another tab -> become a new peer
      id = await key.generateIdentity()                // (app.js: nextFreeSlot() -> identity({slot}))
      lease = await claimIdentity(id.S, locks)
      assert.equal(lease.held, true, 'the freshly adopted identity must be claimable')
    }
    const ep = wssEndpoint({ S: id.S, relays: RELAYS, WebSocket: relay.WebSocket })
    const node = await listen(id, { endpoint: ep, deps: { ...deps(), createEndpoint: async () => ep } })
    const got = []
    node.on('message', (_p, m) => got.push(m.toString()))
    return { id, node, got, lease }
  }

  const dflt = await key.generateIdentity()            // the default slot's record
  const tab1 = await goOnline(dflt)
  const tab2 = await goOnline(dflt)                    // a second plain tab asking for the SAME identity
  assert.notEqual(tab2.id.S, tab1.id.S, 'the second tab must NOT come online as the same peer')

  const fresh = await goOnline(await key.generateIdentity())

  // Both tabs are now real, dialable peers — which is what the user wanted from two tabs.
  const p1 = await fresh.node.connect(tab1.id.S)
  await delay(100)
  await p1.send('for tab1')
  const p2 = await fresh.node.connect(tab2.id.S)
  await delay(100)
  await p2.send('for tab2')
  await delay(300)

  assert.deepEqual(tab1.got, ['for tab1'], 'tab1 receives its own message')
  assert.deepEqual(tab2.got, ['for tab2'], 'tab2 receives its own message')

  // THE INVARIANT: no tab may report a live peer while receiving nothing. That is the zombie, and
  // after the fix it cannot exist — a tab either owns its identity, or it is a different peer.
  const zombies = [tab1, tab2].filter((t) => t.node.peers().some((p) => p.connected) && t.got.length === 0)
  assert.deepEqual(zombies, [], 'a CONNECTED-but-silent tab must be structurally impossible')

  tab1.node.close(); tab2.node.close(); fresh.node.close(); relay.close()
  clearInterval(hold)
})

// ── app.js cannot run under node --test (it needs the DOM), so tripwire its wiring in the source ──

test('TRIPWIRE: app.js still wires the auto-adopt path (it cannot be exercised headlessly)', async () => {
  const src = await readFile(new URL('../src/browser/app.js', import.meta.url), 'utf8')
  // Anchor every pattern on the CALL SITE, never on a name that a function DECLARATION also contains
  // — `/readAdopted\(\)/` matches `function readAdopted()` and would pass with the wiring ripped out
  // (caught by mutating app.js and watching this test still go green).
  const must = [
    [/err\.reason !== 'identity-live' \|\| slotWasAskedFor/, 'auto-adopts ONLY on identity-live, and only for a slot the user did not name'],
    [/const next = await nextFreeSlot\(\)/, 'adopts the next free slot (the same picker ＋New identity uses)'],
    [/location\.hash = 'id=' \+ next/, 'persists the adopted slot in the URL so a reload is stable'],
    [/const adopted = readAdopted\(\)/, 'says WHY the key changed once it is back online'],
    // The reload must be anchored to the auto-adopt SEQUENCE, not matched on its own: a bare
    // /location\.reload\(\)/ also matches the idswitch handler further down the file, so deleting
    // ONLY the auto-adopt reload — which strands the tab offline — still passed. Require the three
    // steps together and in order, inside a window too tight to reach the idswitch reload.
    [
      /sessionStorage\.setItem\(ADOPTED[\s\S]{0,400}?location\.hash = 'id=' \+ next[\s\S]{0,200}?location\.reload\(\)/,
      'carries the reason across the reload, sets the adopted slot in the hash, and THEN reloads — as one sequence',
    ],
  ]
  for (const [re, why] of must) assert.match(src, re, `app.js must still: ${why}`)
  // And the guard it depends on must still be exported from the module app.js imports.
  const p2p = await readFile(new URL('../src/browser/p2p.js', import.meta.url), 'utf8')
  assert.match(p2p, /export function claimIdentity/, 'p2p.js must still export claimIdentity')
  assert.match(p2p, /reason: 'identity-live'/, 'p2p.js must still tag the error app.js keys off')
  assert.match(p2p, /lease\.release\(\)/, 'node.close() must release the identity for the next tab')
})
