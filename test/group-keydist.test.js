// test/group-keydist.test.js — the LIVE bug: a member's SENDER KEY never reaches the others, so the
// group warns `no-sender-key` forever and nobody can read that member's messages.
//
// WHY test/tui-group.test.js missed it: its switchboard lets EVERY node punch to every other for
// free, so the reverse dial that group.js depends on always succeeded. Real life isn't like that.
//
// THE ASYMMETRY THAT MATTERS (modelled here): a browser — and anything behind a hostile NAT — is
// reachable, but cannot cheaply DIAL BACK. It gets a channel because someone dialed IT. group.js
// shipped every control frame (KEYDIST/KEYREQ/OP/MSG) through `node.connect(S)`, and connect() can
// never see an inbound peer (node.js keys dialed peers by S, accepted peers by 'static:'+xPub), so a
// member that cannot dial out could never hand anyone its sender key. TUI↔TUI hid it (the reverse
// dial usually works on a LAN); web and mixed groups failed exactly as the owner saw.
//
// Everything below is the SHIPPED code — key.js, noise.js, node.js, sign.js, group.js — with only
// the transport swapped for an in-memory one. Separate nodes, real pairwise Noise channels per pair.
// No mDNS, no UDP, no network.

import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { identity, listen } from '../src/node.js'
import { createSecureGroup } from '../src/group.js'

// ── an in-memory transport with a REAL-WORLD asymmetry ───────────────────────────────────────
// `oneWay(S)` = S can never punch OUT (a browser / symmetric-NAT peer). It can still be dialed, and
// the channel it accepts is fully bidirectional — exactly like a real accepted connection.
function board() {
  const eps = new Map()
  const noDialOut = new Set()
  const sock = (getPeer) => {
    let handler = null
    const inbox = []
    const s = {
      closed: false, proto: 'mem', rinfo: { address: 'mem', port: 0 },
      get onMessage() { return handler },
      set onMessage(fn) { handler = fn; if (fn) while (inbox.length) fn(inbox.shift()) },
      _recv(b) { if (handler) handler(b); else inbox.push(b) },
      send(b) { const p = getPeer(); if (!s.closed && p && !p.closed) setImmediate(() => p._recv(Buffer.from(b))) },
      close() { s.closed = true },
    }
    return s
  }
  return {
    oneWay(S) { noDialOut.add(String(S).toUpperCase()) },
    allowDialOut(S) { noDialOut.delete(String(S).toUpperCase()) },   // the TRANSIENT case: it comes back
    endpoint(S) {
      let onConn = null
      const ep = {
        onConnection(cb) { onConn = cb },
        on() {}, close() {},
        candidates() { return [{ proto: 'mem', to: S }] },
        _deliver(sk) { if (onConn) onConn(sk) },
        async punch(cands) {
          // the whole point: this peer cannot open a connection outward
          if (noDialOut.has(String(S).toUpperCase())) throw new Error('unreachable (cannot dial out)')
          const to = cands[0].to
          const a = sock(() => b)
          const b = sock(() => a)
          eps.get(to)._deliver(b)
          return a
        },
      }
      eps.set(S, ep)
      return ep
    },
  }
}

const rv = { publishAll: () => ({ stop() {} }), resolve: (S) => [{ proto: 'mem', to: String(S).toUpperCase() }] }
const wait = (ms) => new Promise((r) => setTimeout(r, ms))

async function mkNode(bd) {
  const id = await identity()
  const node = await listen(id, { endpoint: bd.endpoint(id.S), deps: { resolve: rv.resolve, publishAll: rv.publishAll } })
  return { id, node }
}

/** A group member, wired like the real clients: message sink + a record of every divergence. */
function member({ id, node }, G, { create = false, members = [] } = {}) {
  const rx = []
  const warnings = []
  const g = createSecureGroup(node, id, { secret: G, members, create })
  g.on('message', (from, data) => rx.push({ from, text: Buffer.from(data).toString('utf8') }))
  g.on('divergence', (d) => warnings.push(d.reason))
  return { id, node, g, rx, warnings }
}

// ── the owner's exact scenario: TUI admin creates + /adds a member that cannot dial back ──────
test('a member who cannot dial back (browser/NAT) is still heard — no no-sender-key', async () => {
  const bd = board()
  const A = await mkNode(bd)                 // the TUI admin — can dial
  const C = await mkNode(bd)                 // the "browser": reachable, but cannot dial OUT
  bd.oneWay(C.id.S)

  const G = randomBytes(32)
  const a = member(A, G, { create: true })   // admin creates an EMPTY group, then /adds C (the owner's flow)
  const c = member(C, G)

  await a.g.join()
  await c.g.join()
  await a.g.add(C.id.S)                      // what the TUI's `/add <KEY>` calls
  await wait(1500)                           // let key distribution settle

  // the admin can read C — this is the message that used to vanish behind `⚠ no-sender-key`
  await c.g.send('hi from the browser')
  await wait(800)

  assert.deepEqual(a.warnings.filter((w) => w === 'no-sender-key'), [],
    `the admin must hold C's sender key — got warnings: ${a.warnings.join(', ')}`)
  assert.equal(a.rx.length, 1, 'the admin must receive C\'s message')
  assert.equal(a.rx[0].text, 'hi from the browser', 'decrypted')
  assert.equal(a.rx[0].from, C.id.S, 'authorship verified to C')

  // and C can read the admin
  await a.g.send('hi from the TUI')
  await wait(800)
  assert.deepEqual(c.warnings.filter((w) => w === 'no-sender-key'), [], 'C must hold the admin\'s sender key')
  assert.equal(c.rx.filter((m) => m.text === 'hi from the TUI' && m.from === A.id.S).length, 1,
    'C must receive the admin\'s message')

  A.node.close(); C.node.close()
})

// ── mixed 3-party: TUI admin + a TUI member + a "browser" that cannot dial back ───────────────
test('mixed group: every member holds every other member\'s sender key (incl. a late-added browser)', async () => {
  const bd = board()
  const A = await mkNode(bd)                 // TUI admin
  const B = await mkNode(bd)                 // TUI member, listed at creation
  const C = await mkNode(bd)                 // browser, ADDED LATE and cannot dial out
  bd.oneWay(C.id.S)

  const G = randomBytes(32)
  const a = member(A, G, { create: true, members: [B.id.S] })
  const b = member(B, G)
  const c = member(C, G)

  await a.g.join(); await b.g.join(); await c.g.join()
  await wait(600)
  await a.g.add(C.id.S)                      // the late join — C only ever learns the group from the admin
  await wait(2000)

  // every member must end up with the SAME membership, folded from the signed chain
  for (const [who, m] of [['admin', a], ['B', b], ['C', c]]) {
    assert.deepEqual(m.g.members().sort(), [A.id.S, B.id.S, C.id.S].sort(), `${who} must see all three members`)
  }

  // every member speaks; every OTHER member must decrypt it and attribute it correctly
  await a.g.send('from A'); await wait(500)
  await b.g.send('from B'); await wait(500)
  await c.g.send('from C'); await wait(900)

  const got = (m) => m.rx.map((x) => x.text).sort()
  assert.deepEqual(got(a), ['from B', 'from C'], `admin must read B and C — warnings: ${a.warnings.join(', ')}`)
  assert.deepEqual(got(b), ['from A', 'from C'], `B must read A and C — warnings: ${b.warnings.join(', ')}`)
  assert.deepEqual(got(c), ['from A', 'from B'], `C must read A and B — warnings: ${c.warnings.join(', ')}`)

  for (const [who, m] of [['admin', a], ['B', b], ['C', c]]) {
    assert.deepEqual(m.warnings.filter((w) => w === 'no-sender-key'), [], `${who} must never warn no-sender-key`)
  }

  A.node.close(); B.node.close(); C.node.close()
})

// ── self-heal: a member whose sender key was MISSED pulls it (KEYREQ) instead of warning forever ──
test('self-heal: a missed sender key is pulled on demand, and later messages decrypt', async () => {
  const bd = board()
  const A = await mkNode(bd)
  const C = await mkNode(bd)
  bd.oneWay(C.id.S)

  const G = randomBytes(32)
  const a = member(A, G, { create: true, members: [C.id.S] })
  const c = member(C, G)

  // C joins but the admin's group does NOT hand out its key yet: C is online and in the roster, and
  // the admin only join()s afterwards. Whatever the interleaving, both sides must converge.
  await c.g.join()
  await wait(300)
  await a.g.join()
  await wait(1500)

  await c.g.send('after the heal')
  await wait(800)
  assert.equal(a.rx.filter((m) => m.text === 'after the heal' && m.from === C.id.S).length, 1,
    `the admin must converge on C's sender key — warnings: ${a.warnings.join(', ')}`)

  A.node.close(); C.node.close()
})

// ── the owner's EXACT warning: keydist missed its window, the message arrives anyway ──────────
// This is the transient form of the same root cause — the shape the owner actually screenshotted.
// C's dial-out is dead exactly when it should be handing out its sender key, and recovers before it
// speaks. So the admin gets a MESSAGE from C with no KEY for C: `⚠ no-sender-key by C`, forever,
// because nothing ever pulled the key at the moment the gap was observed.
test('the owner\'s warning: a missed keydist + a later message must trigger a KEYREQ pull, not a forever-warning', async () => {
  const bd = board()
  const A = await mkNode(bd)
  const C = await mkNode(bd)

  const G = randomBytes(32)
  const a = member(A, G, { create: true, members: [C.id.S] })
  const c = member(C, G)

  bd.oneWay(C.id.S)               // C cannot dial out during the key-distribution window
  await a.g.join()
  await c.g.join()
  await wait(1200)                // C's keydist to the admin fails here — the admin has no key for C

  bd.allowDialOut(C.id.S)         // C's route comes back (a relay reconnects, the punch lands, …)
  await c.g.send('hi')            // the message the owner watched vanish
  await wait(1500)                // a healthy client PULLS the missing key here and decrypts

  assert.equal(a.rx.filter((m) => m.text === 'hi' && m.from === C.id.S).length, 1,
    `the admin must self-heal and read C — warnings seen: ${a.warnings.join(', ') || '(none)'}`)

  A.node.close(); C.node.close()
})

// ── the self-heal must not become its own DOS ─────────────────────────────────────────────────
// A member whose key never lands is exactly the case the stash + KEYREQ pull exist for — so it is
// also the case an attacker (or a merely chatty, unreachable peer) would aim at them. Both are
// BOUNDED: held messages are capped per sender and evicted oldest-first, and one missing key costs a
// bounded number of KEYREQs — never one per dropped message.
const GMAGIC = 0x67
const T_KEYDIST = 1
const T_KEYREQ = 5
const isType = (b, t) => Buffer.isBuffer(b) && b.length > 1 && b[0] === GMAGIC && b[1] === t

/**
 * Wrap every peer this node sends through. The callback decides each frame's fate:
 *   true     → send it for real
 *   false    → silently swallow it (the send "succeeds", the frame never lands)
 *   'reject' → the send FAILS (an unreachable peer — the send promise rejects)
 * The distinction matters: only a REJECT clears group.js's `pulling` guard, which is what lets a
 * KEYREQ re-fire. A swallowed KEYREQ looks successful and is never retried.
 */
function interceptSends(node, fn) {
  const realPeers = node.peers.bind(node)
  const realConnect = node.connect.bind(node)
  const wrap = (p) => new Proxy(p, {
    get(t, k) {
      if (k === 'send') return (buf) => {
        const verdict = fn(buf)
        if (verdict === false) return Promise.resolve(0)
        if (verdict === 'reject') return Promise.reject(new Error('unreachable'))
        return t.send(buf)
      }
      const v = t[k]
      return typeof v === 'function' ? v.bind(t) : v
    },
  })
  node.peers = () => realPeers().map(wrap)
  node.connect = async (s) => wrap(await realConnect(s))
}

test('bounded self-heal: a flood from an un-keyed member cannot grow the heap or storm KEYREQs', async () => {
  const bd = board()
  const A = await mkNode(bd)
  const D = await mkNode(bd)

  // D's KEYDIST frames never make it onto the wire — the pathological case the stash+pull exist for:
  // its messages arrive, its key never does, and (because the send "succeeds") it never re-sends.
  let dropKeys = true
  interceptSends(D.node, (buf) => !(dropKeys && isType(buf, T_KEYDIST)))

  // A's KEYREQs must genuinely FAIL to reach D — D is the cannot-dial-back member, so A's pull is a
  // send into a hole. This is what makes the storm REAL: a rejected send clears group.js's `pulling`
  // guard, so the very next undecryptable message pulls again. (An earlier version of this test let
  // the KEYREQ succeed, which left `pulling` set — one request, no storm, and the assertion below
  // passed whether or not the cap existed. It proved nothing. Caught by redteam.)
  let keyreqs = 0                                            // every KEYREQ the admin ATTEMPTS
  interceptSends(A.node, (buf) => {
    if (!isType(buf, T_KEYREQ)) return true
    keyreqs++
    return 'reject'                                          // D is unreachable — the pull fails
  })

  const G = randomBytes(32)
  const a = member(A, G, { create: true, members: [D.id.S] })
  const d = member(D, G)
  await a.g.join(); await d.g.join()
  await wait(800)

  const FLOOD = 60                                           // every one of these is undecryptable for A
  for (let i = 0; i < FLOOD; i++) await d.g.send(`flood ${i}`)
  await wait(1200)

  assert.equal(a.rx.length, 0, 'the admin genuinely holds no key for D (the scenario is real)')
  // D's pubkeys ride its KEYDIST too, so with that frame dropped the admin cannot even bind D's
  // identity — the gap surfaces as msg-unknown-identity rather than no-sender-key. Either way it is
  // the same hole (we cannot read D), and both branches hold the message and pull the key.
  const gap = a.warnings.filter((w) => w === 'no-sender-key' || w === 'msg-unknown-identity').length
  assert.ok(gap >= FLOOD, `every flooded message must have observed the gap — saw ${gap} of ${FLOOD}`)

  // BOUND 1 — no KEYREQ storm. Each failed pull clears `pulling`, so WITHOUT MAX_KEYREQ every one of
  // the 60 messages re-asks: 60 KEYREQs for one missing key, aimed at a peer that cannot answer.
  // With the cap it stops at 8. Verified by removing the cap: this asserts 60, i.e. it genuinely bites.
  assert.ok(keyreqs > 0, 'the pull must actually be attempted (else this test proves nothing)')
  assert.ok(keyreqs <= 8,
    `a missing key must cost ≤8 KEYREQs, not one per message — attempted ${keyreqs} for ${FLOOD} messages`)

  // BOUND 2 — the heap is capped. Let D's key through and rotate: the admin replays what it HELD.
  // Those messages are from D's OLD chain, so each replay fails to decrypt — which makes the number
  // of held messages directly observable. Uncapped it would be 60; capped (evicting oldest) it is 16.
  dropKeys = false                                           // stop dropping (toggle, not a re-wrap)
  a.warnings.length = 0
  await d.g.rotate()
  await wait(1200)
  assert.equal(a.warnings.filter((w) => w === 'group-decrypt').length, 16,
    `the admin must hold at most MAX_STASH(16) messages per sender — replayed ${a.warnings.filter((w) => w === 'group-decrypt').length}`)

  A.node.close(); D.node.close()
})

// ── 10/10: the one-way member is heard on every one of ten independent runs ───────────────────
test('10/10: the cannot-dial-back member round-trips on every one of ten runs', async () => {
  for (let i = 0; i < 10; i++) {
    const bd = board()
    const A = await mkNode(bd)
    const C = await mkNode(bd)
    bd.oneWay(C.id.S)

    const G = randomBytes(32)
    const a = member(A, G, { create: true })
    const c = member(C, G)
    await a.g.join(); await c.g.join()
    await a.g.add(C.id.S)
    await wait(1200)

    await c.g.send(`run ${i}`)
    await wait(700)
    assert.deepEqual(a.warnings.filter((w) => w === 'no-sender-key'), [], `run ${i}: no no-sender-key`)
    assert.equal(a.rx.length, 1, `run ${i}: the admin must receive exactly one message`)
    assert.equal(a.rx[0].text, `run ${i}`, `run ${i}: decrypted`)
    assert.equal(a.rx[0].from, C.id.S, `run ${i}: authorship`)

    A.node.close(); C.node.close()
  }
})
