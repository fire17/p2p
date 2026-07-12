// test/tui-group.test.js — the TUI/CLI group surface (`p2p group new` / `p2p group join`).
//
// It drives the EXACT helpers bin/p2p-group.js uses at runtime (newGroupCode / parseGroupCode /
// makeGroup), so a pass proves the shipped CLI path, not a re-implementation of it.
//
// Deterministic + OFFLINE: only the transport is an in-memory switchboard (same shape as
// test/group-secure.test.js). key.js, noise.js, node.js, sign.js and group.js are the shipped code —
// every group message really is Noise-IK-encrypted on a pairwise link and really is sender-key
// encrypted + Ed25519-signed on top. No mDNS, no UDP, no LAN broadcast, zero dev deps.

import test from 'node:test'
import assert from 'node:assert/strict'
import { identity, listen } from '../src/node.js'
import { newGroupCode, parseGroupCode, makeGroup } from '../bin/p2p-group.js'

// ── in-memory switchboard ────────────────────────────────────────────────────────────────────
function board() {
  const eps = new Map()
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
    endpoint(S) {
      let onConn = null
      const ep = {
        onConnection(cb) { onConn = cb },
        on() {}, close() {},
        candidates() { return [{ proto: 'mem', to: S }] },
        _deliver(sk) { if (onConn) onConn(sk) },
        async punch(cands) {
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

/** A node on the switchboard — the CLI's `mod.listen(id)`, with only the transport swapped out. */
async function mkNode(bd) {
  const id = await identity()
  const node = await listen(id, { endpoint: bd.endpoint(id.S), deps: { resolve: rv.resolve, publishAll: rv.publishAll } })
  return { id, node }
}

/** Wire a member exactly like bin/p2p-group.js does: makeGroup → on('message') → join(). */
async function member({ id, node }, code, { create = false, members = [] } = {}) {
  const rx = []
  const g = makeGroup(node, id, { code, members, create })
  g.on('message', (from, data) => rx.push({ from, text: Buffer.from(data).toString('utf8') }))
  return { id, node, g, rx }
}

// ── the group code (what `p2p group new` prints and `p2p group join` takes) ───────────────────
test('group code: fresh code is a 32-byte secret; a typo is refused LOUDLY', () => {
  const code = newGroupCode()
  assert.equal(parseGroupCode(code).length, 32, 'a fresh code must decode to the 32-byte group secret G')
  assert.equal(parseGroupCode(code).toString('base64'), code, 'round-trip must be exact')

  // A truncated/typo'd code must THROW — never silently yield a different groupId (which would look
  // like "joined" while nobody can ever hear you).
  assert.throws(() => parseGroupCode(code.slice(0, 20)), /bad group code/, 'truncated code must be refused')
  assert.throws(() => parseGroupCode(''), /no group code/, 'empty code must be refused')
  assert.throws(() => parseGroupCode('not a real code'), /bad group code/, 'garbage must be refused')
})

// ── the deliverable: create → share code → join → send → the other member receives it ─────────
test('p2p group new -> join -> send: a group message round-trips, decrypted + authorship-verified', async () => {
  const bd = board()
  const A = await mkNode(bd)   // runs `p2p group new <B.S>`
  const B = await mkNode(bd)   // runs `p2p group join <CODE>`

  const code = newGroupCode()                                   // what `p2p group new` prints
  const a = await member(A, code, { create: true, members: [B.id.S] })
  const b = await member(B, code)                               // joiner gets ONLY the code

  await a.g.join()
  await b.g.join()
  await wait(400)                                               // sender-key distribution over the Noise links

  assert.equal(a.g.groupId, b.g.groupId, 'the same code must yield the same groupId on both members')
  assert.deepEqual(a.g.members().sort(), [A.id.S, B.id.S].sort(), 'creator sees both members')
  assert.equal(a.g.admin(), A.id.S, 'the creator is the admin')

  await a.g.send('hello group, from the creator')
  await wait(300)
  assert.equal(b.rx.length, 1, 'the joiner must receive the creator\'s message')
  assert.equal(b.rx[0].text, 'hello group, from the creator', 'plaintext must survive the round-trip')
  assert.equal(b.rx[0].from, A.id.S, 'authorship must verify to the creator\'s key')

  await b.g.send('hi back, from the joiner')                    // and the other way
  await wait(300)
  assert.equal(a.rx.length, 1, 'the creator must receive the joiner\'s message')
  assert.equal(a.rx[0].text, 'hi back, from the joiner')
  assert.equal(a.rx[0].from, B.id.S, 'authorship must verify to the joiner\'s key')

  A.node.close(); B.node.close()
})

// ── /add: the admin grows the group after creation (the empty-group path) ─────────────────────
test('in-chat /add: the admin adds a third member, who then sends and receives', async () => {
  const bd = board()
  const A = await mkNode(bd)
  const B = await mkNode(bd)
  const C = await mkNode(bd)

  const code = newGroupCode()
  const a = await member(A, code, { create: true, members: [B.id.S] })
  const b = await member(B, code)
  const c = await member(C, code)                               // C joins with the code, not yet a member

  await a.g.join(); await b.g.join(); await c.g.join()
  await wait(400)

  await a.g.add(C.id.S)                                         // what `/add <KEY>` calls
  await wait(600)
  assert.ok(a.g.members().includes(C.id.S), 'the admin\'s membership must include the added member')
  assert.ok(b.g.members().includes(C.id.S), 'every member folds the SAME membership from the signed chain')
  assert.ok(c.g.members().includes(C.id.S), 'the newcomer learns it is in')

  await c.g.send('third member here')
  await wait(400)
  assert.equal(a.rx.filter((m) => m.text === 'third member here' && m.from === C.id.S).length, 1, 'admin receives the newcomer\'s message')
  assert.equal(b.rx.filter((m) => m.text === 'third member here' && m.from === C.id.S).length, 1, 'the other member receives it too')

  await a.g.send('welcome')
  await wait(400)
  assert.equal(c.rx.filter((m) => m.text === 'welcome' && m.from === A.id.S).length, 1, 'the newcomer receives group traffic')

  A.node.close(); B.node.close(); C.node.close()
})

// ── 10/10: the round-trip is not a fluke (fresh identities, fresh code, fresh nodes each run) ──
test('10/10: create -> join -> send round-trips on every one of ten independent runs', async () => {
  for (let i = 0; i < 10; i++) {
    const bd = board()
    const A = await mkNode(bd)
    const B = await mkNode(bd)
    const code = newGroupCode()
    const a = await member(A, code, { create: true, members: [B.id.S] })
    const b = await member(B, code)
    await a.g.join(); await b.g.join()
    await wait(300)

    await a.g.send(`run ${i}`)
    await wait(250)
    assert.equal(b.rx.length, 1, `run ${i}: the joiner must receive exactly one message`)
    assert.equal(b.rx[0].text, `run ${i}`, `run ${i}: plaintext`)
    assert.equal(b.rx[0].from, A.id.S, `run ${i}: authorship`)

    A.node.close(); B.node.close()
  }
})
