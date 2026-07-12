// test/fixtures/browser-mitm.mjs — adversarial proof, on the browser stack (shim crypto + shared
// src/key.js + src/noise.js). Spawned by test/browser-mitm.test.js. Prints markers on success;
// exits nonzero if the MITM ever succeeds.
//
// Threat: an attacker (Mallory) controls the trackers, STUN, and the WebRTC/DTLS layer end to end
// — exactly the TUI's threat model, just a different pipe. She does NOT hold Alice's X25519 static
// private key. She must not be able to impersonate Alice or read the channel.

import { register } from 'node:module'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'
import assert from 'node:assert/strict'

const HERE = dirname(fileURLToPath(import.meta.url))
register(pathToFileURL(join(HERE, 'shim-hooks.mjs'))) // node:crypto -> browser shim, inside src/

const { Buffer: ShimBuffer } = await import('../../src/browser/shim/buffer.js')
globalThis.Buffer = ShimBuffer

const { generateIdentity, decodeKey, verifyCommitment } = await import('../../src/key.js')
const { initiator, responder } = await import('../../src/noise.js')

const alice = generateIdentity() // the peer Bob wants
const mallory = generateIdentity() // the attacker on the signaling path
const bob = generateIdentity()
const dec = decodeKey(alice.S) // Bob holds Alice's 26-char key

// 1. Mallory substitutes HER pubkeys in the HELLO. The commitment gate must reject them.
assert.equal(verifyCommitment(dec.commitment, mallory.edPub, mallory.xPub), false, 'gate accepted the attacker!')
assert.equal(verifyCommitment(dec.commitment, alice.edPub, alice.xPub), true, 'gate must accept the real keys')
console.log('  ✔ gate REJECTS substituted keys (second-preimage 2^110)')

// 2. Even past the gate (she can't get there — but assume it), Bob runs IK pinned to ALICE's
//    static key. Mallory answering with her own key must make Bob's handshake fail closed.
const hsBob = initiator({ localX: { pub: bob.xPub, priv: bob.xPriv }, remoteXPub: alice.xPub })
const hsMal = responder({ localX: { pub: mallory.xPub, priv: mallory.xPriv } })
const msg1 = hsBob.writeMessage(Buffer.alloc(0))
let failedClosed = false
try {
  // msg1 carries `es`/`ss` to ALICE's key — Mallory cannot even decrypt Bob's static, and her
  // msg2 cannot produce an ack Bob accepts. Either step throws; the handshake fails closed.
  hsMal.readMessage(msg1)
  const msg2 = hsMal.writeMessage(Buffer.alloc(0))
  hsBob.readMessage(msg2)
} catch {
  failedClosed = true
}
assert.equal(failedClosed, true, 'MITM handshake did NOT fail closed — CATASTROPHIC')
console.log('  ✔ MITM handshake FAILED CLOSED (impostor cannot produce a decryptable ack)')

// 3. The honest path still works, and the mutual handshake hash IS the shared proof.
const hsBob2 = initiator({ localX: { pub: bob.xPub, priv: bob.xPriv }, remoteXPub: alice.xPub })
const hsAlice = responder({ localX: { pub: alice.xPub, priv: alice.xPriv } })
hsAlice.readMessage(hsBob2.writeMessage(Buffer.alloc(0)))
hsBob2.readMessage(hsAlice.writeMessage(Buffer.alloc(0)))
const a = hsBob2.split()
const b = hsAlice.split()
assert.equal(a.handshakeHash.equals(b.handshakeHash), true, 'honest handshake hashes must match')
console.log('  ✔ real handshake completes with matching handshake hash')

console.log('MITM-RESISTANT OK')
