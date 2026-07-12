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
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { identity, listen } from '../src/node.js'
import { newGroupCode, parseGroupCode, encodeGroupCode, makeGroup } from '../bin/p2p-group.js'

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
// CODE = base64( G(32B) ‖ SHA256(G)[0..3) ). A deterministic vector keeps the mutation sweep below
// flake-free: a random code could, with ~1-in-16.7M luck per mutation, collide on the checksum.
const G_VEC = createHash('sha256').update('tui-group test vector').digest()   // 32 bytes, fixed
const CODE_VEC = encodeGroupCode(G_VEC)

test('group code: a fresh code carries the 32-byte secret + a checksum; garbage is refused LOUDLY', () => {
  const code = newGroupCode()
  assert.equal(parseGroupCode(code).length, 32, 'a code must decode to the 32-byte group secret G')
  assert.equal(encodeGroupCode(parseGroupCode(code)), code, 'encode/parse must round-trip exactly')
  assert.equal(Buffer.from(code, 'base64').length, 35, 'the wire code is G(32) + a 3-byte checksum')

  assert.throws(() => parseGroupCode(code.slice(0, 20)), /bad group code/, 'truncated code must be refused')
  assert.throws(() => parseGroupCode(''), /no group code/, 'empty code must be refused')
  assert.throws(() => parseGroupCode('not a real code'), /bad group code/, 'garbage must be refused')
})

// ── the GHOST GROUP (the bug the checksum exists to kill) ─────────────────────────────────────
// Before the checksum, the code was raw base64(G) with zero redundancy: one mistyped character that
// still decoded gave a DIFFERENT G ⇒ a different groupId ⇒ the victim saw a cheerful "joined" while
// sitting alone in a group nobody else was in — no error, ever. These are the exact probes the
// red-team lane found (a middle-char typo and a last-char change both used to be ACCEPTED as a
// different group). They must now THROW.
test('ghost group: a mistyped code THROWS — it never silently becomes a different group', () => {
  const mid = CODE_VEC.length >> 1
  const midTypo = CODE_VEC.slice(0, mid) + (CODE_VEC[mid] === 'A' ? 'B' : 'A') + CODE_VEC.slice(mid + 1)
  assert.notEqual(midTypo, CODE_VEC, 'the probe must really differ from the real code')
  assert.throws(() => parseGroupCode(midTypo), /checksum failed|not valid base64|expected 35/,
    'a MIDDLE-character typo must be refused, not accepted as a different group')

  // last-char probe (redteam's 'w' -> 'A'): the final base64 char carries real bytes of G
  const lastTypo = CODE_VEC.slice(0, -2) + (CODE_VEC.at(-2) === 'A' ? 'B' : 'A') + CODE_VEC.at(-1)
  assert.notEqual(lastTypo, CODE_VEC, 'the probe must really differ from the real code')
  assert.throws(() => parseGroupCode(lastTypo), /checksum failed|not valid base64|expected 35/,
    'a LAST-character typo must be refused, not accepted as a different group')

  // The strong form: EVERY single-character mutation of a real code is refused. Nothing slips.
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
  let mutations = 0
  const accepted = []
  for (let i = 0; i < CODE_VEC.length; i++) {
    for (const ch of ALPHABET) {
      if (ch === CODE_VEC[i]) continue
      const bad = CODE_VEC.slice(0, i) + ch + CODE_VEC.slice(i + 1)
      mutations++
      try { parseGroupCode(bad); accepted.push(bad) } catch { /* refused, as it must be */ }
    }
  }
  assert.ok(mutations > 3000, `the sweep must be real (${mutations} mutations)`)
  assert.deepEqual(accepted, [], `every single-char typo must be refused — ${accepted.length} slipped through`)
})

// ── browser <-> CLI: one format, byte-identical ───────────────────────────────────────────────
// The interop is the whole point: a code minted in the browser must join from the terminal and vice
// versa. app.js needs a DOM, so it cannot be imported here — instead this mirrors the browser's
// algorithm EXACTLY as written in src/browser/app.js and asserts the bytes agree in both mint
// directions, plus a source-level tripwire so the two copies cannot silently drift apart.
test('browser<->CLI: the same code format, the same checksum bytes, both mint directions', () => {
  // verbatim mirror of src/browser/app.js
  const browserSum = (G) => createHash('sha256').update(G).digest().subarray(0, 3)
  const browserMint = (G) => Buffer.concat([Buffer.from(G), browserSum(G)]).toString('base64')
  const browserParse = (code) => {
    const raw = Buffer.from(String(code).trim(), 'base64')
    if (raw.length !== 35) throw new Error('bad group code')
    const G = raw.subarray(0, 32)
    if (!browserSum(G).equals(raw.subarray(32))) throw new Error('bad group code (checksum failed)')
    return Buffer.from(G)
  }

  // CLI mints -> the browser parses it back to the SAME G (a terminal code joins in the browser)
  const cliCode = newGroupCode()
  assert.deepEqual(browserParse(cliCode), parseGroupCode(cliCode), 'browser must recover the CLI code\'s G')

  // browser mints -> the CLI parses it back to the SAME G (a browser code joins in the terminal)
  const browserCode = browserMint(G_VEC)
  assert.equal(browserCode, CODE_VEC, 'both clients must mint the IDENTICAL code for the same G')
  assert.deepEqual(parseGroupCode(browserCode), G_VEC, 'the CLI must recover the browser code\'s G')

  // and the browser rejects a typo exactly like the CLI does
  assert.throws(() => browserParse(CODE_VEC.slice(0, -2) + 'AA'), /bad group code/)

  // drift tripwire: the browser's copy of the format must still BE this format.
  const appjs = readFileSync(new URL('../src/browser/app.js', import.meta.url), 'utf8')
  assert.match(appjs, /createHash\('sha256'\)\.update\(G\)\.digest\(\)\.subarray\(0, 3\)/, 'app.js must use the same 3-byte SHA-256 checksum')
  assert.match(appjs, /raw\.length !== 35/, 'app.js must expect the same 35-byte code')
  assert.match(appjs, /checksum failed/, 'app.js must refuse a bad checksum')
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
