// test/node.test.js — node.js lifecycle logic, seams mocked (transport/noise/key/rendezvous).
// Real wire.js runs underneath, so ARQ + framing are genuinely exercised. Zero deps.

import test from 'node:test'
import assert from 'node:assert/strict'
import { listen, identity } from '../src/node.js'
import { decodeFrame, TYPE } from '../src/wire.js'

// --- mock seams -----------------------------------------------------------
class TypoError extends Error {}

function mkIdentity(S, tag) {
  return {
    S,
    edPub: Buffer.from(tag + '-ed'), edPriv: Buffer.from(tag + '-edk'),
    xPub: Buffer.from(tag + '-x'), xPriv: Buffer.from(tag + '-xk'),
  }
}

// In-memory switchboard: punch(cands) connects to the node registered under cands[0].to.
function makeBoard() {
  const eps = new Map()          // S -> endpoint
  const registry = new Map()     // S -> identity (for decodeKey/gate)
  let severed = false            // simulates the network going dark (peer death)
  function sock(getPeer, getDrop) {
    let handler = null; const inbox = []
    const s = {
      closed: false, rinfo: { address: 'mock', port: 0 },
      get onMessage() { return handler },
      set onMessage(fn) { handler = fn; if (fn) while (inbox.length) fn(inbox.shift()) },  // flush buffered
      _recv(buf) { if (handler) handler(buf); else inbox.push(buf) },
      send(buf) {
        if (s.closed || severed) return
        const cp = Buffer.from(buf)
        const drop = getDrop && getDrop()
        if (drop && drop(cp)) return
        const p = getPeer()
        if (p && !p.closed) p._recv(cp)
      },
      close() { s.closed = true },
    }
    return s
  }
  const board = {
    eps, registry,
    makeEndpoint() {
      let onConn = null, dropPred = null
      const ep = {
        onConnection(cb) { onConn = cb },
        on() {}, close() {},
        setDrop(p) { dropPred = p }, getDrop() { return dropPred },
        deliver(s) { if (onConn) onConn(s) },
        punch(cands) {
          const target = eps.get(cands[0].to)
          const a = sock(() => b, () => ep.getDrop())          // dialer side (this ep's drop)
          const b = sock(() => a, () => target.getDrop())      // target side (target's drop)
          target.deliver(b)
          return Promise.resolve(a)
        },
      }
      return ep
    },
    register(S, ep) { eps.set(S, ep) },
    sever() { severed = true },            // peer death: all datagrams silently vanish
    heal() { severed = false },
  }
  return board
}

function baseNoise() {
  const cipher = (tag) => ({
    encrypt: (pt) => Buffer.concat([Buffer.from([tag]), Buffer.from(pt)]),
    decrypt: (ct) => { if (ct[0] !== tag) throw new Error('decrypt: bad tag'); return Buffer.from(ct.subarray(1)) },
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
    decodeKey: (s) => {
      const id = board.registry.get(String(s).toUpperCase())
      if (!id) throw new TypoError('bad key')
      return { version: 0, flags: 0, commitment: id.xPub }
    },
    verifyCommitment: (c, _ed, x) => Buffer.compare(Buffer.from(c), Buffer.from(x)) === 0,
    // mock of key.encodeKey: map a pubkey pair back to its registered 26-char contact string
    encodeKey: (_ed, x) => {
      for (const [S, id] of board.registry) {
        if (Buffer.from(id.xPub).equals(Buffer.from(x))) return S
      }
      return 'UNKNOWN'
    },
    createEndpoint: async () => board.makeEndpoint(),
    initiator: noise.initiator,
    responder: noise.responder,
    resolve: async (s) => [{ to: String(s).toUpperCase() }],
    publishAll: async () => {},
    ...over,
  }
}

async function buildNode(board, S, tag, over = {}, listenOpts = {}) {
  const id = mkIdentity(S, tag)
  board.registry.set(S, id)
  const ep = board.makeEndpoint()
  board.register(S, ep)
  const node = await listen(id, {
    endpoint: ep, deps: baseDeps(board, over),
    now: listenOpts.now || (() => 0),
    keepaliveMs: listenOpts.keepaliveMs ?? 1e12,
    livenessMs: listenOpts.livenessMs,
    tickMs: listenOpts.tickMs,
  })
  return { node, id, ep }
}

const nextTick = () => new Promise((r) => setImmediate(r))
const delay = (ms) => new Promise((r) => setTimeout(r, ms))

// --- tests ----------------------------------------------------------------
test('identity() delegates to key.generateIdentity via deps', async () => {
  const id = await identity({ deps: baseDeps(makeBoard()) })
  assert.equal(id.S, 'SELF')
  assert.ok(Buffer.isBuffer(id.xPub))
})

test('connect: gate + IK handshake, first-ack resolves, peer/message/ack events', async () => {
  const board = makeBoard()
  const A = await buildNode(board, 'AAAAAAAAAAAAAAAAAAAAAAAAAA', 'alice')
  const B = await buildNode(board, 'BBBBBBBBBBBBBBBBBBBBBBBBBB', 'bob')

  let aPeerEvents = 0, aMsgs = []
  A.node.on('peer', () => aPeerEvents++)
  A.node.on('message', (_p, data) => aMsgs.push(data.toString()))

  const peer = await B.node.connect('AAAAAAAAAAAAAAAAAAAAAAAAAA')
  assert.equal(peer.connected, true, 'connect resolves only after first-ack, connected')
  assert.equal(aPeerEvents, 1, 'A emitted peer on accept')

  let ackSeq = -1
  B.node.on('ack', (_p, seq) => { ackSeq = seq })
  const seq = await peer.send('hello alice')
  await nextTick()
  assert.deepEqual(aMsgs, ['hello alice'])
  assert.equal(seq, 0)
  assert.equal(ackSeq, 0, 'B saw ack for seq 0')
})

test('bidirectional: accepter can send back to the dialer', async () => {
  const board = makeBoard()
  const A = await buildNode(board, 'CCCCCCCCCCCCCCCCCCCCCCCCCC', 'a2')
  const B = await buildNode(board, 'DDDDDDDDDDDDDDDDDDDDDDDDDD', 'b2')
  const bMsgs = []
  B.node.on('message', (_p, d) => bMsgs.push(d.toString()))
  await B.node.connect('CCCCCCCCCCCCCCCCCCCCCCCCCC')
  await nextTick()
  const aPeerToB = A.node.peers()[0]
  await aPeerToB.send('reply from A')
  await nextTick()
  assert.deepEqual(bMsgs, ['reply from A'])
})

test('gate failure: commitment mismatch rejects connect + emits divergence (no auth from HELLO)', async () => {
  const board = makeBoard()
  await buildNode(board, 'EEEEEEEEEEEEEEEEEEEEEEEEEE', 'a3')
  const B = await buildNode(board, 'FFFFFFFFFFFFFFFFFFFFFFFFFF', 'b3', { verifyCommitment: () => false })
  let div = null
  B.node.on('divergence', (_p, info) => { div = info })
  await assert.rejects(B.node.connect('EEEEEEEEEEEEEEEEEEEEEEEEEE'), /gate/)
  assert.equal(div.reason, 'gate')
})

test('handshake failure: bad HS2 fails CLOSED (reject + divergence)', async () => {
  const board = makeBoard()
  // A responds with a corrupt HS2 -> B.readMessage throws -> fail closed.
  const badNoise = baseNoise()
  const goodWrite = badNoise.responder
  await buildNode(board, 'GGGGGGGGGGGGGGGGGGGGGGGGGG', 'a4', {
    responder: () => {
      const hs = goodWrite()
      return { readMessage: hs.readMessage, writeMessage: () => Buffer.from('XXcorrupt'), split: hs.split }
    },
  })
  const B = await buildNode(board, 'HHHHHHHHHHHHHHHHHHHHHHHHHH', 'b4')
  let div = null
  B.node.on('divergence', (_p, info) => { div = info })
  await assert.rejects(B.node.connect('GGGGGGGGGGGGGGGGGGGGGGGGGG'), /handshake/)
  assert.equal(div.reason, 'handshake')
})

test('typo key: decodeKey throws before any network work', async () => {
  const board = makeBoard()
  const B = await buildNode(board, 'IIIIIIIIIIIIIIIIIIIIIIIIII', 'b5')
  await assert.rejects(B.node.connect('UNKNOWNKEYUNKNOWNKEYUNKNOW'), TypoError)
})

test('real-path shapes: listen announces via publishAll(S,endpoint); connect drains a streaming resolve', async () => {
  const board = makeBoard()
  const published = []
  async function* streamResolve(s) { yield { to: String(s).toUpperCase() } }  // like createRace.resolve (async gen)
  const A = await buildNode(board, 'LLLLLLLLLLLLLLLLLLLLLLLLLL', 'astream', {
    resolve: (s) => streamResolve(s),
    publishAll: async (s, ep) => { published.push([s, !!ep]) },
  })
  const B = await buildNode(board, 'MMMMMMMMMMMMMMMMMMMMMMMMMM', 'bstream', {
    resolve: (s) => streamResolve(s), publishAll: async () => {},
  })
  await nextTick()
  assert.deepEqual(published, [['LLLLLLLLLLLLLLLLLLLLLLLLLL', true]], 'listen announced S with an endpoint')

  const aMsgs = []
  A.node.on('message', (_p, d) => aMsgs.push(d.toString()))
  const peer = await B.node.connect('LLLLLLLLLLLLLLLLLLLLLLLLLL')   // resolve here is an async generator
  await peer.send('via stream')
  await nextTick()
  assert.equal(peer.connected, true)
  assert.deepEqual(aMsgs, ['via stream'])
})

test('resend buffer + exactly-once across reconnect (dropped app-ack, then replay)', async () => {
  const board = makeBoard()
  const A = await buildNode(board, 'JJJJJJJJJJJJJJJJJJJJJJJJJJ', 'a6')
  const B = await buildNode(board, 'KKKKKKKKKKKKKKKKKKKKKKKKKK', 'b6')

  const aMsgs = []
  A.node.on('message', (_p, d) => aMsgs.push(d.toString()))

  const peer = await B.node.connect('JJJJJJJJJJJJJJJJJJJJJJJJJJ')
  await peer.send('first')                         // acked normally
  await nextTick()
  assert.deepEqual(aMsgs, ['first'])

  // A now drops its outgoing DATA frames -> B never gets the app-ack for 'second'.
  A.ep.setDrop((buf) => decodeFrame(buf)?.type === TYPE.DATA)
  let secondAckResolved = false
  const secondAck = peer.send('second').then(() => { secondAckResolved = true })
  await nextTick()
  assert.deepEqual(aMsgs, ['first', 'second'], 'A delivered second exactly once')
  assert.equal(secondAckResolved, false, 'B has NOT been acked yet (app-ack dropped)')

  // Reconnect: tear down, stop dropping, redial. Outbox replays 'second'.
  peer.close()
  A.ep.setDrop(null)
  const peer2 = await B.node.connect('JJJJJJJJJJJJJJJJJJJJJJJJJJ')
  await nextTick()
  await secondAck                                   // replayed ack now resolves
  assert.equal(secondAckResolved, true)
  assert.deepEqual(aMsgs, ['first', 'second'], 'no duplicate delivery after replay (exactly-once)')
  assert.equal(peer2.connected, true)
})

test('friends: BOTH sides learn the other peer\'s real 26-char key (peer.key + remoteEd)', async () => {
  const board = makeBoard()
  const KA = 'RRRRRRRRRRRRRRRRRRRRRRRRRR', KB = 'SSSSSSSSSSSSSSSSSSSSSSSSSS'
  const A = await buildNode(board, KA, 'fa')
  const B = await buildNode(board, KB, 'fb')

  const bAccepted = []
  B.node.on('peer', (p) => bAccepted.push(p))       // key must be readable IN the handler

  const aPeer = await A.node.connect(KB)
  await nextTick()

  // dialer derived the key it dialed
  assert.equal(aPeer.key, KB, "dialer's peer.key === the key it dialed (B's S)")
  assert.ok(Buffer.isBuffer(aPeer.remoteEd) && Buffer.isBuffer(aPeer.remoteStatic))

  // listener derived the DIALER's real shareable key — this is what makes friends work
  assert.equal(bAccepted.length, 1)
  assert.equal(bAccepted[0].key, KA, "listener's accepted peer.key === the dialer's real key (A's S)")
  assert.ok(Buffer.isBuffer(bAccepted[0].remoteEd), 'listener captured the dialer edPub')
  assert.ok(bAccepted[0].remoteStatic.equals(A.id.xPub), 'listener captured the dialer xPub')

  A.node.close(); B.node.close()
})

test('peer RESTART (fresh instance) reply is NOT deduped against the dead session (bidirectional)', async () => {
  const board = makeBoard()
  const KA = 'PPPPPPPPPPPPPPPPPPPPPPPPPP', KB = 'QQQQQQQQQQQQQQQQQQQQQQQQQQ'
  const echoOnMsg = (n) => n.on('message', (peer, d) => { peer.send(Buffer.from('echo:' + d.toString())) })
  const A = await buildNode(board, KA, 'ra')
  let B = await buildNode(board, KB, 'rb')
  echoOnMsg(B.node)

  const aGot = []
  A.node.on('message', (_p, d) => aGot.push(d.toString()))

  const peer = await A.node.connect(KB)
  await peer.send('m1')                              // A->B m1 (seq0); B echoes -> A.delivered gets B seq0
  await nextTick(); await nextTick()
  assert.deepEqual(aGot, ['echo:m1'], 'A received echo:m1 (populates A dedup with B seq0)')

  // B "restarts": brand-new node, SAME identity/key (deterministic), but a FRESH _instance
  // (its outbound appSeq resets to 0). Re-registers its endpoint under the same key.
  B.node.close()
  B = await buildNode(board, KB, 'rb')
  echoOnMsg(B.node)

  const peer2 = await A.node.connect(KB)             // redial the restarted peer
  await peer2.send('m2')                             // B2 replies echo:m2 with seq reset to 0
  await nextTick(); await nextTick()
  assert.deepEqual(aGot, ['echo:m1', 'echo:m2'],
    'restarted peer reply delivered (instance-scoped dedup) — not silently dropped')
  A.node.close(); B.node.close()
})

test('interval-driven tick: keepalive holds a peer past livenessMs, then death (silence) => disconnect + reconnect', async () => {
  // REAL setInterval + real clock (small windows). livenessMs=200, keepalive=40 -> if the
  // node were NOT driving tick(), the peer would die at 200ms even while linked. Surviving
  // 300ms linked proves keepalive PING/PONG is actually firing on the interval.
  const board = makeBoard()
  const opts = { now: Date.now, keepaliveMs: 40, livenessMs: 200, tickMs: 20 }
  const A = await buildNode(board, 'NNNNNNNNNNNNNNNNNNNNNNNNNN', 'liveA', {}, opts)
  const B = await buildNode(board, 'OOOOOOOOOOOOOOOOOOOOOOOOOO', 'liveB', {}, opts)
  try {
    const peer = await B.node.connect('NNNNNNNNNNNNNNNNNNNNNNNNNN')
    let disconnects = 0
    B.node.on('disconnect', () => disconnects++)

    await delay(300)                                   // > livenessMs while linked
    assert.equal(peer.connected, true, 'keepalive (interval-driven) held the peer past livenessMs')
    assert.equal(disconnects, 0)

    board.sever()                                      // peer death: network goes dark, no PONG
    await delay(320)                                   // > livenessMs of silence
    assert.equal(peer.connected, false, 'dead peer detected, connected flipped false')
    assert.equal(disconnects, 1, 'disconnect emitted exactly once')

    board.heal()                                       // peer restarts / network returns
    const peer2 = await B.node.connect('NNNNNNNNNNNNNNNNNNNNNNNNNN')
    assert.equal(peer2.connected, true, 'redial RE-HANDSHAKES a fresh session (not the corpse)')
  } finally { A.node.close(); B.node.close() }
})
