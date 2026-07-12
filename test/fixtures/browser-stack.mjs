// test/fixtures/browser-stack.mjs — run the REAL protocol source on the BROWSER stack.
//
// This is the heart of the browser client's interop claim. We take src/noise.js and src/key.js
// — the same files the TUI runs, not a port — and we swap out everything the browser doesn't
// have:
//     node:crypto  ->  src/browser/shim/node-crypto.js   (vendored noble primitives)
//     Buffer       ->  src/browser/shim/buffer.js        (Uint8Array subclass)
// ...then run the OFFICIAL Noise KAT vector through it and assert byte-exactness.
//
// If this passes, the browser produces the same handshake bytes as the TUI — because it is
// literally the same state machine, and both match the same audited third-party vector.
//
// Run as a child process (test/browser-noise-parity.test.js spawns it) so that overriding the
// global Buffer can't disturb the test runner itself. Prints "BROWSER-STACK OK" on success;
// throws (nonzero exit) on any mismatch.

import { register } from 'node:module'
import { readFileSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { join, dirname } from 'node:path'
import assert from 'node:assert/strict'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..', '..')

// 1. Redirect `node:crypto` -> the browser shim, but ONLY for imports coming from src/ protocol
//    modules (so this file, and node's own internals, keep the real thing).
register(pathToFileURL(join(HERE, 'shim-hooks.mjs')))

// 2. Replace the global Buffer with the browser shim, exactly as a browser would see it.
const { Buffer: ShimBuffer } = await import('../../src/browser/shim/buffer.js')
const NodeBuffer = globalThis.Buffer
globalThis.Buffer = ShimBuffer

// 3. Import the REAL protocol source. It now runs entirely on browser-available primitives.
const { initiator, responder } = await import('../../src/noise.js')
const { generateIdentity, encodeKey, decodeKey, verifyCommitment, deriveRid } = await import('../../src/key.js')

const hex = (h) => ShimBuffer.from(h, 'hex')
const VEC = JSON.parse(readFileSync(join(ROOT, 'test', 'vectors', 'noise_ik_25519_chachapoly_sha256.json'), 'utf8'))

// sanity: we really are on the shim (a real Node Buffer would be a different class)
assert.equal(ShimBuffer.alloc(1) instanceof NodeBuffer, false, 'shim Buffer must NOT be node Buffer')

const shimCrypto = await import('../../src/browser/shim/node-crypto.js')
const X_PKCS8 = ShimBuffer.from('302e020100300506032b656e04220420', 'hex') // == src/noise.js:45

/** raw X25519 private scalar -> raw public key, through the SHIM (noble), never node:crypto */
function xPubFromPriv(priv) {
  return shimCrypto
    .createPublicKey(shimCrypto.createPrivateKey({ key: ShimBuffer.concat([X_PKCS8, priv]), format: 'der', type: 'pkcs8' }))
    .export({ type: 'spki', format: 'der' })
    .subarray(-32)
}

// ── (a) official KAT vector, byte-exact, on the browser stack ──
for (const [name, o] of Object.entries(VEC.extracted)) {
  const v = o.vector
  const initStatic = hex(v.init_static)
  const respStatic = hex(v.resp_static)
  const respStaticPub = xPubFromPriv(respStatic)

  // the shim must derive the same responder static pub the vector publishes
  assert.equal(respStaticPub.toString('hex'), v.init_remote_static, `[${name}] resp static pub == init_remote_static`)

  const hs_i = initiator({
    localX: { priv: initStatic, pub: xPubFromPriv(initStatic) },
    remoteXPub: hex(v.init_remote_static),
    prologue: hex(v.init_prologue),
    _ephemeral: hex(v.init_ephemeral),
  })
  const hs_r = responder({
    localX: { priv: respStatic, pub: respStaticPub },
    prologue: hex(v.resp_prologue),
    _ephemeral: hex(v.resp_ephemeral),
  })

  const m = v.messages

  const msg1 = hs_i.writeMessage(hex(m[0].payload))
  assert.equal(msg1.toString('hex'), m[0].ciphertext, `[${name}] msg1 ciphertext must be byte-exact`)
  assert.deepEqual(hs_r.readMessage(msg1), hex(m[0].payload), `[${name}] msg1 payload`)

  const msg2 = hs_r.writeMessage(hex(m[1].payload))
  assert.equal(msg2.toString('hex'), m[1].ciphertext, `[${name}] msg2 (THE ACK) ciphertext must be byte-exact`)
  assert.deepEqual(hs_i.readMessage(msg2), hex(m[1].payload), `[${name}] msg2 payload`)

  const si = hs_i.split()
  const sr = hs_r.split()
  if (v.handshake_hash) {
    assert.equal(si.handshakeHash.toString('hex'), v.handshake_hash, `[${name}] handshake hash`)
  }

  for (let k = 2; k < m.length; k++) {
    const initToResp = k % 2 === 0
    const sender = initToResp ? si.tx : sr.tx
    const receiver = initToResp ? sr.rx : si.rx
    const ct = sender.encrypt(hex(m[k].payload))
    assert.equal(ct.toString('hex'), m[k].ciphertext, `[${name}] transport msg ${k}`)
    assert.deepEqual(receiver.decrypt(hex(m[k].ciphertext)), hex(m[k].payload), `[${name}] transport msg ${k} decrypt`)
  }
  console.log(`  ✔ KAT byte-exact on the browser stack vs ${name}`)
}

// ── (b) key.js on the browser stack: identity, 26-char string, gate, rid ──
const id = generateIdentity()
assert.equal(id.S.length, 26, 'contact string is 26 chars')
const dec = decodeKey(id.S)
assert.equal(verifyCommitment(dec.commitment, id.edPub, id.xPub), true, 'gate accepts the real keys')
assert.equal(verifyCommitment(dec.commitment, id.xPub, id.edPub), false, 'gate rejects swapped keys')
assert.equal(encodeKey(id.edPub, id.xPub, 0), id.S, 'encodeKey round-trips')
console.log('  ✔ key.js: identity + 26-char string + commitment gate on the browser stack')

// ── (c) the rid the browser derives MUST equal the rid the TUI derives (shared rendezvous) ──
// Print it; the parent test compares against node-native key.js for the same S.
const rid = deriveRid(id.S, 'tracker', '2026-07-12', 20)
console.log('RID ' + id.S + ' ' + ShimBuffer.from(rid).toString('hex'))

console.log('BROWSER-STACK OK')
