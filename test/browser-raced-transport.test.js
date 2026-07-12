// test/browser-raced-transport.test.js — the raced transport races to first PEER CONTACT, not first
// socket. Regression guard for the bug the werift gate exposed: the WSS punch resolves optimistically
// (tracker SUBACK, before any peer answers), so a naive Promise.any picks it and STARVES a peer that
// is only reachable over WebRTC — the dial then hangs on the wrong pipe. composePunch fixes it with a
// composite socket that forwards inbound from every leg and locks outbound to whichever leg delivers
// the first frame (the peer's HELLO). Deterministic, no browser/network.

import test from 'node:test'
import assert from 'node:assert/strict'
import { composePunch } from '../src/browser/transport.js'
import { encodeFrame, TYPE } from '../src/wire.js'

/** A well-formed wire frame — the shape the peer's real HELLO takes (≥ HEADER_LEN). */
const helloFrame = () => encodeFrame(TYPE.HELLO, Buffer.alloc(8), 0, 0, Buffer.from('intro'))

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

  // The real peer answers on the SLOWER leg with a well-formed HELLO frame.
  await new Promise((r) => setTimeout(r, 40))
  const hello = helloFrame()
  realPeer.deliver(hello)
  assert.equal(got.length, 1, 'the delivered frame must reach node.js')
  assert.equal(Buffer.compare(got[0], hello), 0, 'the delivered frame reaches node.js byte-exact')

  // Now node.js replies (HS1). It MUST go over the leg that delivered the HELLO, not the optimistic one.
  composite.send(Buffer.from('HS1'))
  assert.equal(realPeer.sent.length, 1, 'reply must go to the delivering leg')
  assert.equal(optimistic.sent.length, 0, 'reply must NOT go to the silent optimistic leg')
})

test('BRW-1: a bogus runt from a hostile relay does NOT win the outbound lock; the real HELLO does', async () => {
  const relay = fakeSocket('hostile-relay') // resolves first, injects junk before the peer answers
  const realPeer = fakeSocket('realPeer')   // the peer only reachable on the OTHER leg

  const composite = await composePunch([Promise.resolve(relay), Promise.resolve(realPeer)])
  const got = []
  composite.onMessage = (buf) => got.push(buf)

  // Hostile relay injects a sub-header runt (the transport-wss KNOCK byte, or any garbage).
  relay.deliver(Buffer.from([0]))
  relay.deliver(Buffer.from('not-a-frame'))
  assert.equal(got.length, 2, 'junk is still forwarded up (node.js drops it via its own decodeFrame)')

  // node.js replies before the real peer answered: NO leg is locked yet ⇒ broadcast, so the real
  // peer still hears it. Critically, outbound must NOT have locked to the relay's runt.
  composite.send(Buffer.from('early'))
  assert.equal(relay.sent.length, 1, 'pre-lock send broadcasts to every leg')
  assert.equal(realPeer.sent.length, 1, 'pre-lock send broadcasts to every leg')

  // The real peer delivers a well-formed HELLO ⇒ it wins the lock.
  realPeer.deliver(helloFrame())
  composite.send(Buffer.from('HS1'))
  assert.equal(realPeer.sent.length, 2, 'reply routes to the leg that delivered the real frame')
  assert.equal(relay.sent.length, 1, 'reply must NOT route to the hostile relay leg')
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
