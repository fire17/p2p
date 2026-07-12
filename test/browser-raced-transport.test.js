// test/browser-raced-transport.test.js — the raced transport races to first PEER CONTACT, not first
// socket. Regression guard for the bug the werift gate exposed: the WSS punch resolves optimistically
// (tracker SUBACK, before any peer answers), so a naive Promise.any picks it and STARVES a peer that
// is only reachable over WebRTC — the dial then hangs on the wrong pipe. composePunch fixes it with a
// composite socket that forwards inbound from every leg and locks outbound to whichever leg delivers
// the first frame (the peer's HELLO). Deterministic, no browser/network.

import test from 'node:test'
import assert from 'node:assert/strict'
import { composePunch } from '../src/browser/transport.js'

/** A fake sub-socket matching the socketLike seam (send/onMessage/close/closed/rinfo). */
function fakeSocket(label) {
  return {
    label,
    closed: false,
    rinfo: { address: label, port: 0 },
    sent: [],
    onMessage: null,
    send(f) { this.sent.push(f) },
    close() { this.closed = true },
    deliver(buf) { if (this.onMessage) this.onMessage(buf, this.rinfo) }, // simulate an inbound frame
  }
}

test('composePunch: outbound locks to the leg that DELIVERS a frame, not the one that resolved first', async () => {
  const optimistic = fakeSocket('optimistic') // resolves FAST, never delivers (the WSS-SUBACK trap)
  const realPeer = fakeSocket('realPeer') // resolves SLOWER, delivers the HELLO

  const composite = await composePunch([
    Promise.resolve(optimistic), // wins the "first socket" race
    new Promise((r) => setTimeout(() => r(realPeer), 20)), // the actual peer, a beat later
  ])

  // node.js sets its handler on the composite, then waits for a HELLO.
  const got = []
  composite.onMessage = (buf) => got.push(buf)

  // The real peer answers on the SLOWER leg.
  await new Promise((r) => setTimeout(r, 40))
  realPeer.deliver(Buffer.from('HELLO'))
  assert.deepEqual(got.map((b) => b.toString()), ['HELLO'], 'the delivered frame must reach node.js')

  // Now node.js replies (HS1). It MUST go over the leg that delivered the HELLO, not the optimistic one.
  composite.send(Buffer.from('HS1'))
  assert.equal(realPeer.sent.length, 1, 'reply must go to the delivering leg')
  assert.equal(optimistic.sent.length, 0, 'reply must NOT go to the silent optimistic leg')
})

test('composePunch: before any inbound, a send broadcasts to all legs (offer routing unknown yet)', async () => {
  const a = fakeSocket('a')
  const b = fakeSocket('b')
  const composite = await composePunch([Promise.resolve(a), Promise.resolve(b)])
  composite.send(Buffer.from('x')) // no leg has answered yet → broadcast so the right peer hears it
  assert.equal(a.sent.length, 1)
  assert.equal(b.sent.length, 1)
})

test('composePunch: rejects only when EVERY leg fails', async () => {
  await assert.rejects(
    composePunch([Promise.reject(new Error('webrtc timeout')), Promise.reject(new Error('wss down'))]),
    /all paths failed.*webrtc timeout.*wss down/s,
  )
  // one good leg ⇒ resolves
  const ok = fakeSocket('ok')
  const c = await composePunch([Promise.reject(new Error('dead')), Promise.resolve(ok)])
  assert.ok(c && typeof c.send === 'function')
})

test('composePunch: no attempts ⇒ rejects with a clear message', async () => {
  await assert.rejects(composePunch([]), /no usable candidate/)
})

test('composePunch: close() tears down every leg', async () => {
  const a = fakeSocket('a')
  const b = fakeSocket('b')
  const c = await composePunch([Promise.resolve(a), new Promise((r) => setTimeout(() => r(b), 10))])
  await new Promise((r) => setTimeout(r, 20)) // let b wire in
  c.close()
  assert.equal(a.closed, true)
  assert.equal(b.closed, true)
})
