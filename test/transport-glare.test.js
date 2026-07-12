// test/transport-glare.test.js — GLARE: what happens when a dial RACES two transports.
//
// The browser endpoint (src/browser/transport.js) fans onConnection to BOTH sub-endpoints and
// composes both punches, so ONE dial produces TWO inbound sockets on the listener. This file
// reproduces that shape in-process — real key.js / noise.js / wire.js, mock transports, NO UDP,
// NO mDNS, no network — and asserts the invariant that must hold: one dial => exactly ONE logical
// session, and every app message delivers.

import test from 'node:test'
import assert from 'node:assert/strict'
import { listen } from '../src/node.js'
import { composePunch } from '../src/browser/transport.js'
import * as key from '../src/key.js'
import * as noise from '../src/noise.js'

const delay = (ms) => new Promise((r) => setTimeout(r, ms))

/**
 * A two-leg in-memory board. Each leg is an independent "transport": its own socket pair per dial,
 * its own inbound accept on the listener — exactly the browser's WebRTC + WSS shape.
 * `lat(leg)` / `up(leg)` let a test order the race deterministically or shuffle it.
 */
function makeBoard({ legs = ['legA', 'legB'], lat = () => 0, up = () => 0 } = {}) {
  const eps = new Map() // S -> endpoint

  function sock(leg, getPeer) {
    let handler = null
    const inbox = []
    const s = {
      closed: false, leg, rinfo: { address: leg, port: 0 },
      get onMessage() { return handler },
      set onMessage(fn) {
        handler = typeof fn === 'function' ? fn : null
        if (handler) while (inbox.length) handler(inbox.shift(), s.rinfo)
      },
      _recv(buf) { if (handler) handler(buf, s.rinfo); else inbox.push(buf) },
      send(buf) {
        if (s.closed) return
        const cp = Buffer.from(buf)
        setTimeout(() => { const p = getPeer(); if (p && !p.closed && !s.closed) p._recv(cp) }, lat(leg))
      },
      close() { s.closed = true },
    }
    return s
  }

  const board = {
    eps,
    makeEndpoint(S) {
      let onConn = null
      const ep = {
        S,
        accepts: [],                       // every inbound socket this endpoint was handed
        onConnection(cb) { onConn = cb },  // the browser fans this to EVERY sub-endpoint
        on() {}, close() {},
        _accept(sk) { ep.accepts.push(sk); if (onConn) onConn(sk) },
        /** One dial, N legs: N socket pairs, N inbound accepts on the far side, one composite here. */
        punch(cands) {
          const target = eps.get(cands[0].to)
          const attempts = legs.map((leg) => new Promise((res) => {
            let a, b
            a = sock(leg, () => b)
            b = sock(leg, () => a)
            setTimeout(() => { target._accept(b); res(a) }, up(leg))
          }))
          return composePunch(attempts)
        },
      }
      if (S) eps.set(S, ep)
      return ep
    },
  }
  return board
}

/** Real crypto (key + noise + wire), mock transport. The gate and the Noise IK genuinely run. */
function realDeps(board, ep) {
  return {
    generateIdentity: key.generateIdentity,
    decodeKey: key.decodeKey,
    verifyCommitment: key.verifyCommitment,
    encodeKey: key.encodeKey,
    createEndpoint: async () => ep,
    initiator: noise.initiator,
    responder: noise.responder,
    resolve: async (S) => [{ to: String(S) }],
    publishAll: () => ({ stop() {} }),
  }
}

async function buildNode(board, id) {
  const ep = board.makeEndpoint(id.S)
  const node = await listen(id, { endpoint: ep, deps: realDeps(board, ep), tickMs: 20 })
  return { node, ep }
}

/** One dial + a message each way. Returns {ok, alice, bob} — ok=false on any drop/timeout. */
async function roundTrip(board, timeoutMs = 2000) {
  const idA = await key.generateIdentity()
  const idB = await key.generateIdentity()
  const A = await buildNode(board, idA)   // dialer
  const B = await buildNode(board, idB)   // listener

  const gotB = []
  const gotA = []
  B.node.on('message', (_p, m) => gotB.push(m.toString()))
  A.node.on('message', (_p, m) => gotA.push(m.toString()))

  const peer = await A.node.connect(idB.S)
  const bPeer = await new Promise((res, rej) => {
    const t = setTimeout(() => rej(new Error('listener never got a peer')), timeoutMs)
    const p = B.node.peers()[0]
    if (p) { clearTimeout(t); return res(p) }
    B.node.on('peer', (pp) => { clearTimeout(t); res(pp) })
  })

  const race = (p) => Promise.race([p, delay(timeoutMs).then(() => { throw new Error('send timed out (message never acked)') })])
  let ok = true
  try {
    await race(peer.send('a2b'))          // dialer -> listener
    await race(bPeer.send('b2a'))         // listener -> dialer
  } catch { ok = false }

  A.node.close(); B.node.close()
  return { ok, gotA, gotB, acceptsOnB: B.ep.accepts.length, peersOnB: B.node._peers.size }
}

test('GLARE: a two-transport race delivers app messages 10/10 (one dial => one session)', async () => {
  const results = []
  for (let i = 0; i < 10; i++) {
    // Shuffle which leg wins the race — a real WebRTC/WSS race has no fixed order.
    const fast = i % 2 === 0 ? 'legA' : 'legB'
    const board = makeBoard({
      up: (leg) => (leg === fast ? 0 : 5),        // the other leg comes up a beat later
      lat: (leg) => (leg === fast ? 1 : 3),       // ...and is slower on the wire
    })
    results.push(await roundTrip(board))
  }
  const delivered = results.filter((r) => r.ok && r.gotA.length === 1 && r.gotB.length === 1).length
  const detail = results.map((r, i) => `#${i} ok=${r.ok} a2b=${r.gotB.length} b2a=${r.gotA.length} accepts=${r.acceptsOnB} peers=${r.peersOnB}`).join('\n')
  assert.equal(delivered, 10, `only ${delivered}/10 round-trips delivered:\n${detail}`)
})

test('GLARE: the listener ends with exactly ONE peer record for one dialer', async () => {
  const board = makeBoard({ up: (l) => (l === 'legA' ? 0 : 4), lat: () => 1 })
  const r = await roundTrip(board)
  assert.equal(r.peersOnB, 1, `listener minted ${r.peersOnB} peer records for one dialer`)
})
