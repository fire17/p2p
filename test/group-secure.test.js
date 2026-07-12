// test/group-secure.test.js — sender-key groups (BC-7): fan-out with per-sender authentication,
// forged-authorship rejection, blind peer-relay through a member, and cryptographic removal.
//
// Deterministic + offline: only the TRANSPORT is in-memory. key.js, noise.js, node.js, sign.js and
// group.js are the shipped code — every message really is Noise-IK-encrypted on a pairwise link and
// really is sender-key encrypted + Ed25519 signed on top. Zero dev deps, no network.

import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { identity, listen } from '../src/node.js'
import { createSecureGroup } from '../src/group.js'

// ── in-memory switchboard (same shape as test/node.test.js) ───────────────────────────────────
function board() {
  const eps = new Map()
  const blocked = new Set()
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
    block(a, b) { blocked.add(a + '>' + b); blocked.add(b + '>' + a) },
    endpoint(S) {
      let onConn = null
      const ep = {
        onConnection(cb) { onConn = cb },
        on() {}, close() {},
        candidates() { return [{ proto: 'mem', to: S }] },
        _deliver(sk) { if (onConn) onConn(sk) },
        async punch(cands) {
          const to = cands[0].to
          if (blocked.has(S + '>' + to)) throw new Error('unreachable')
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

async function threeParty() {
  const bd = board()
  const A = await identity(), B = await identity(), C = await identity()
  const nA = await listen(A, { endpoint: bd.endpoint(A.S), deps: rv })
  const nB = await listen(B, { endpoint: bd.endpoint(B.S), deps: rv })
  const nC = await listen(C, { endpoint: bd.endpoint(C.S), deps: rv })
  const G = randomBytes(32)
  const gA = createSecureGroup(nA, A, { secret: G, members: [B.S, C.S], create: true }) // A is admin
  const gB = createSecureGroup(nB, B, { secret: G })
  const gC = createSecureGroup(nC, C, { secret: G })
  const got = { A: [], B: [], C: [] }
  const div = { A: [], B: [], C: [] }
  for (const [k, g] of [['A', gA], ['B', gB], ['C', gC]]) {
    g.on('message', (from, d) => got[k].push({ from, text: d.toString() }))
    g.on('divergence', (x) => div[k].push(x.reason))
  }
  await gA.join(); await wait(120)
  await gB.join(); await gC.join(); await wait(120)
  return { bd, A, B, C, nA, nB, nC, gA, gB, gC, got, div, close: () => { nA.close(); nB.close(); nC.close() } }
}

test('group: one secret → the same groupId and the same folded membership on every member', async () => {
  const t = await threeParty()
  assert.equal(t.gA.groupId, t.gB.groupId)
  assert.equal(t.gB.groupId, t.gC.groupId)
  for (const g of [t.gA, t.gB, t.gC]) {
    assert.deepEqual(g.members().sort(), [t.A.S, t.B.S, t.C.S].sort()) // deterministic fold, no server
    assert.equal(g.admin(), t.A.S)                                     // the create author is admin
  }
  t.close()
})

test('group: one encryption fans out to n, and every message is attributed to its real author', async () => {
  const t = await threeParty()
  await t.gA.send('from A'); await wait(150)
  await t.gB.send('from B'); await wait(150)

  assert.deepEqual(t.got.B.map((m) => m.text), ['from A'])
  assert.equal(t.got.B[0].from, t.A.S)                    // per-sender Ed25519 auth, not "the link"
  assert.deepEqual(t.got.C.map((m) => m.text).sort(), ['from A', 'from B'])
  assert.deepEqual(t.got.A.map((m) => m.text), ['from B'])
  assert.equal(t.got.A[0].from, t.B.S)
  t.close()
})

test('group: a member CANNOT forge another member’s authorship (signature gate fails closed)', async () => {
  const t = await threeParty()
  // C hand-crafts a group MSG envelope claiming s = A.S, with a bogus signature.
  const body = Buffer.from(JSON.stringify({ s: t.A.S, q: 99, p: [], c: 'AAAA', g: 'AAAA' }), 'utf8')
  const env = Buffer.allocUnsafe(2 + 32 + body.length)
  env[0] = 0x67; env[1] = 2                                // GMAGIC, T.MSG
  Buffer.from(t.gA.groupId, 'hex').copy(env, 2)
  body.copy(env, 34)
  const cToB = t.nC.peers().find((p) => p.key === t.B.S)
  await cToB.send(env); await wait(150)

  assert.ok(t.div.B.includes('msg-signature'), 'B must reject the forged authorship')
  assert.equal(t.got.B.length, 0, 'and must deliver nothing to the app')
  t.close()
})

test('group: a member unreachable directly is still served, blind-relayed through another member', async () => {
  const t = await threeParty()
  for (const p of t.nA.peers()) p.close()
  for (const p of t.nC.peers()) p.close()
  t.bd.block(t.A.S, t.C.S)                                  // A and C can no longer connect at all
  await wait(80)

  const r = await t.gA.send('relayed'); await wait(300)
  assert.equal(r.relayed.length, 1)                         // A knows it could not reach C directly
  assert.deepEqual(t.got.C.map((m) => m.text), ['relayed']) // …and C got it anyway, forwarded by B
  assert.equal(t.got.C[0].from, t.A.S)                      // still provably authored by A
  t.close()
})

test('group: removal is cryptographic — after rotation the removed member decrypts nothing', async () => {
  const t = await threeParty()
  await t.gA.remove(t.C.S); await wait(200)

  assert.deepEqual(t.gA.members().sort(), [t.A.S, t.B.S].sort())
  const cBefore = t.got.C.length
  const bBefore = t.got.B.length
  await t.gA.send('post-removal'); await wait(250)

  assert.equal(t.got.C.length, cBefore, 'the removed member must receive NOTHING readable')
  assert.equal(t.got.B.length, bBefore + 1, 'survivors keep working across the rotation')
  assert.equal(t.got.B.at(-1).text, 'post-removal')
  t.close()
})
