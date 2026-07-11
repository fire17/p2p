// test/group.test.js — pairwise fan-out groups (DESIGN D10). Seams mocked; real wire.js
// underneath. Zero deps.

import test from 'node:test'
import assert from 'node:assert/strict'
import { listen } from '../src/node.js'
import { createGroup } from '../src/group.js'

class TypoError extends Error {}
function mkIdentity(S, tag) {
  return { S, edPub: Buffer.from(tag + '-ed'), edPriv: Buffer.from(tag + '-edk'), xPub: Buffer.from(tag + '-x'), xPriv: Buffer.from(tag + '-xk') }
}

function makeBoard() {
  const eps = new Map(), registry = new Map()
  function sock(getPeer) {
    let handler = null; const inbox = []
    const s = {
      closed: false, rinfo: { address: 'mock', port: 0 },
      get onMessage() { return handler },
      set onMessage(fn) { handler = fn; if (fn) while (inbox.length) fn(inbox.shift()) },
      _recv(buf) { if (handler) handler(buf); else inbox.push(buf) },
      send(buf) { if (s.closed) return; const p = getPeer(); if (p && !p.closed) p._recv(Buffer.from(buf)) },
      close() { s.closed = true },
    }
    return s
  }
  return {
    eps, registry,
    makeEndpoint() {
      let onConn = null
      const ep = {
        onConnection(cb) { onConn = cb }, on() {}, close() {},
        deliver(s) { if (onConn) onConn(s) },
        punch(cands) { const t = eps.get(cands[0].to); const a = sock(() => b); const b = sock(() => a); t.deliver(b); return Promise.resolve(a) },
      }
      return ep
    },
    register(S, ep) { eps.set(S, ep) },
  }
}

function baseNoise() {
  const cipher = (tag) => ({
    encrypt: (pt) => Buffer.concat([Buffer.from([tag]), Buffer.from(pt)]),
    decrypt: (ct) => { if (ct[0] !== tag) throw new Error('decrypt'); return Buffer.from(ct.subarray(1)) },
  })
  return {
    initiator: () => ({
      writeMessage: (p) => Buffer.concat([Buffer.from('I1'), Buffer.from(p)]),
      readMessage: (b) => { if (b.subarray(0, 2).toString() !== 'R2') throw new Error('HandshakeError'); return Buffer.from(b.subarray(2)) },
      split: () => ({ tx: cipher(0x61), rx: cipher(0x62), handshakeHash: Buffer.alloc(32) }),
    }),
    responder: () => ({
      readMessage: (b) => { if (b.subarray(0, 2).toString() !== 'I1') throw new Error('HandshakeError'); return Buffer.from(b.subarray(2)) },
      writeMessage: (p) => Buffer.concat([Buffer.from('R2'), Buffer.from(p)]),
      split: () => ({ tx: cipher(0x62), rx: cipher(0x61), handshakeHash: Buffer.alloc(32) }),
    }),
  }
}

function baseDeps(board, over = {}) {
  const noise = baseNoise()
  return {
    generateIdentity: () => mkIdentity('SELF', 'self'),
    decodeKey: (s) => { const id = board.registry.get(String(s).toUpperCase()); if (!id) throw new TypoError('bad key'); return { version: 0, flags: 0, commitment: id.xPub } },
    verifyCommitment: (c, _ed, x) => Buffer.compare(Buffer.from(c), Buffer.from(x)) === 0,
    createEndpoint: async () => board.makeEndpoint(),
    initiator: noise.initiator, responder: noise.responder,
    resolve: async (s) => [{ to: String(s).toUpperCase() }],
    publishAll: async () => {},
    ...over,
  }
}

async function buildNode(board, S, tag, over = {}) {
  const id = mkIdentity(S, tag)
  board.registry.set(S, id)
  const ep = board.makeEndpoint()
  board.register(S, ep)
  const node = await listen(id, { endpoint: ep, deps: baseDeps(board, over), now: () => 0, keepaliveMs: 1e12 })
  return { node, id, ep }
}
const nextTick = () => new Promise((r) => setImmediate(r))

const KA = 'AAAAAAAAAAAAAAAAAAAAAAAAAA'
const KB = 'BBBBBBBBBBBBBBBBBBBBBBBBBB'
const KC = 'CCCCCCCCCCCCCCCCCCCCCCCCCC'

test('group.send fans out to every member; all receive; results carry acks', async () => {
  const board = makeBoard()
  const A = await buildNode(board, KA, 'alice')
  const C = await buildNode(board, KC, 'carol')
  const S = await buildNode(board, KB, 'sender')

  const got = []
  A.node.on('message', (_p, d) => got.push(['A', d.toString()]))
  C.node.on('message', (_p, d) => got.push(['C', d.toString()]))

  const group = S.node.group([KA, KC])
  const results = await group.send('gm team')
  await nextTick()

  assert.equal(group.size, 2)
  assert.equal(results.length, 2)
  assert.ok(results.every((r) => r.error === undefined && r.ack === 0), 'every leg acked')
  assert.deepEqual(got.sort(), [['A', 'gm team'], ['C', 'gm team']])
})

test('group dedups member keys and normalizes to uppercase', () => {
  const g = createGroup({}, [KA, KA, KA.toLowerCase()])
  assert.equal(g.size, 1)
  assert.deepEqual(g.members(), [KA])
})

test('partial failure: a bad member yields {error}, others still deliver', async () => {
  const board = makeBoard()
  const A = await buildNode(board, KA, 'alice')
  await buildNode(board, KC, 'carol')
  // Sender's gate fails ONLY for KC (decodeKey returns a mismatching commitment for it).
  const S = await buildNode(board, KB, 'sender', {
    decodeKey: (s) => {
      const up = String(s).toUpperCase()
      const id = board.registry.get(up)
      if (!id) throw new TypoError('bad key')
      return { version: 0, flags: 0, commitment: up === KC ? Buffer.from('mismatch') : id.xPub }
    },
  })
  const gotA = []
  A.node.on('message', (_p, d) => gotA.push(d.toString()))

  const results = await S.node.group([KA, KC]).send('hi')
  await nextTick()

  const byKey = Object.fromEntries(results.map((r) => [r.key, r]))
  assert.equal(byKey[KA].ack, 0, 'KA delivered')
  assert.ok(byKey[KC].error instanceof Error, 'KC failed gracefully')
  assert.deepEqual(gotA, ['hi'])
})
