// test/browser-shim.test.js — G1a: the browser crypto shim is byte-identical to node:crypto.
//
// This is THE interop gate for the browser client. The browser runs the same protocol source as
// the TUI (src/noise.js, src/key.js, …) with `node:crypto` swapped for src/browser/shim. If every
// primitive the protocol touches is byte-for-byte equal to Node's, then the protocol bytes are
// equal too — and a browser peer and a TUI peer provably speak the same Noise.
//
// So we assert equality on EVERY function in the shim's surface, against the real node:crypto.
// (browser-noise-parity.test.js then runs the official Noise KAT through src/noise.js driven by
// the shim — belt and braces: primitives here, whole handshake there.)

import test from 'node:test'
import assert from 'node:assert/strict'
import * as real from 'node:crypto'
import * as shim from '../src/browser/shim/node-crypto.js'
import { Buffer as ShimBuffer } from '../src/browser/shim/buffer.js'

const hex = (b) => Buffer.from(b).toString('hex')

test('sha256: shim === node, incl. multi-chunk streaming', () => {
  const cases = [[], [Buffer.alloc(0)], [Buffer.from('abc')], [Buffer.from('p2p-id-v1'), Buffer.alloc(32, 7), Buffer.alloc(32, 9)]]
  for (const parts of cases) {
    const a = real.createHash('sha256')
    const b = shim.createHash('sha256')
    for (const p of parts) { a.update(p); b.update(p) }
    assert.equal(hex(b.digest()), hex(a.digest()), 'sha256 mismatch')
  }
})

test('hmac-sha256: shim === node', () => {
  for (const keyLen of [0, 1, 32, 64, 100]) {
    const key = real.randomBytes(keyLen)
    const data = real.randomBytes(77)
    const a = real.createHmac('sha256', key).update(data).digest()
    const b = shim.createHmac('sha256', key).update(data).digest()
    assert.equal(hex(b), hex(a), `hmac mismatch (key ${keyLen}B)`)
  }
})

test('hkdfSync: shim === node (the deriveRid path)', () => {
  for (const len of [1, 20, 32, 64]) {
    const ikm = Buffer.from('ABCDEFGHJKMNPQRSTVWXYZ0123', 'ascii') // a 26-char contact string
    const salt = 'p2p-rv-tracker-v1'
    const info = '2026-07-12'
    const a = Buffer.from(real.hkdfSync('sha256', ikm, salt, info, len))
    const b = shim.hkdfSync('sha256', ikm, salt, info, len)
    assert.equal(hex(b), hex(a), `hkdf mismatch (L=${len})`)
  }
})

test('X25519: shim keygen/DH agrees with node, both directions', () => {
  // node keypair <-> shim keypair must agree on the shared secret (this is the cross-runtime case:
  // a browser peer doing DH against a TUI peer's key)
  const nodeKp = real.generateKeyPairSync('x25519')
  const nodePriv = Buffer.from(nodeKp.privateKey.export({ type: 'pkcs8', format: 'der' })).subarray(-32)
  const nodePub = Buffer.from(nodeKp.publicKey.export({ type: 'spki', format: 'der' })).subarray(-32)

  const shimKp = shim.generateKeyPairSync('x25519')
  const shimPriv = shimKp.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32)
  const shimPub = shimKp.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)

  // shim's private key, node's public key
  const ss1 = shim.diffieHellman({
    privateKey: shim.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), shimPriv]), format: 'der', type: 'pkcs8' }),
    publicKey: shim.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), nodePub]), format: 'der', type: 'spki' }),
  })
  // node's private key, shim's public key — must be the SAME secret
  const ss2 = real.diffieHellman({
    privateKey: real.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(nodePriv)]), format: 'der', type: 'pkcs8' }),
    publicKey: real.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(shimPub)]), format: 'der', type: 'spki' }),
  })
  assert.equal(hex(ss1), hex(ss2), 'X25519 shared secret mismatch across runtimes')
})

test('X25519: shim public key derivation === node, for the SAME private scalar', () => {
  const priv = real.randomBytes(32)
  const der = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), priv])
  const nodePub = Buffer.from(real.createPublicKey(real.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })).export({ type: 'spki', format: 'der' })).subarray(-32)
  const shimPub = shim.createPublicKey(shim.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })).export({ type: 'spki', format: 'der' }).subarray(-32)
  assert.equal(hex(shimPub), hex(nodePub), 'X25519 pubkey derivation diverges')
})

test('Ed25519: shim public key derivation + JWK export === node (the identity path)', () => {
  const kp = shim.generateKeyPairSync('ed25519')
  const priv = kp.privateKey.export({ format: 'jwk' }).d
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(priv, 'base64url')])
  const nodeJwk = real.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }).export({ format: 'jwk' })
  const shimJwk = kp.privateKey.export({ format: 'jwk' })
  assert.equal(shimJwk.x, nodeJwk.x, 'Ed25519 pubkey (jwk.x) diverges')
  assert.equal(shimJwk.d, nodeJwk.d, 'Ed25519 privkey (jwk.d) diverges')
  assert.equal(shimJwk.crv, 'Ed25519')
})

test('ChaCha20-Poly1305: shim encrypt === node encrypt (ciphertext AND tag)', () => {
  const key = real.randomBytes(32)
  const nonce = Buffer.alloc(12)
  nonce.writeBigUInt64LE(42n, 4) // the Noise nonce shape: 4 zero bytes || u64 LE counter
  const ad = real.randomBytes(32)
  const pt = Buffer.from('the first ack is the MITM proof')

  const rc = real.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 })
  rc.setAAD(ad, { plaintextLength: pt.length })
  const rct = Buffer.concat([rc.update(pt), rc.final()])
  const rtag = rc.getAuthTag()

  const sc = shim.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 })
  sc.setAAD(ad, { plaintextLength: pt.length })
  const sct = Buffer.concat([sc.update(pt), sc.final()])
  const stag = sc.getAuthTag()

  assert.equal(hex(sct), hex(rct), 'ciphertext diverges')
  assert.equal(hex(stag), hex(rtag), 'auth tag diverges')
})

test('ChaCha20-Poly1305: shim decrypts node ciphertext (and vice versa)', () => {
  const key = real.randomBytes(32)
  const nonce = Buffer.alloc(12)
  const ad = Buffer.from('handshake hash')
  const pt = Buffer.from('hello from the TUI')

  const rc = real.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 })
  rc.setAAD(ad, { plaintextLength: pt.length })
  const ct = Buffer.concat([rc.update(pt), rc.final()])
  const tag = rc.getAuthTag()

  const sd = shim.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 })
  sd.setAAD(ad, { plaintextLength: ct.length })
  sd.setAuthTag(tag)
  const out = Buffer.concat([sd.update(ct), sd.final()])
  assert.equal(out.toString(), pt.toString(), 'browser could not decrypt a TUI frame')
})

test('ChaCha20-Poly1305: shim FAILS CLOSED on a tampered tag', () => {
  const key = real.randomBytes(32)
  const nonce = Buffer.alloc(12)
  const c = shim.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 })
  c.setAAD(Buffer.alloc(0))
  const ct = Buffer.concat([c.update(Buffer.from('secret')), c.final()])
  const tag = Buffer.from(c.getAuthTag())
  tag[0] ^= 1 // flip one bit

  const d = shim.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 })
  d.setAAD(Buffer.alloc(0))
  d.setAuthTag(tag)
  d.update(ct)
  assert.throws(() => d.final(), 'a tampered tag MUST throw')
})

test('timingSafeEqual: matches node semantics (equal, unequal, length mismatch throws)', () => {
  const a = Buffer.alloc(14, 3)
  const b = Buffer.alloc(14, 3)
  const c = Buffer.alloc(14, 4)
  assert.equal(shim.timingSafeEqual(a, b), true)
  assert.equal(shim.timingSafeEqual(a, c), false)
  assert.throws(() => shim.timingSafeEqual(a, Buffer.alloc(13)), RangeError)
})

test('randomBytes: right length, not constant', () => {
  const a = shim.randomBytes(32)
  const b = shim.randomBytes(32)
  assert.equal(a.length, 32)
  assert.notEqual(hex(a), hex(b))
})

test('Buffer shim: the exact surface our protocol modules use', () => {
  const B = ShimBuffer
  assert.equal(B.alloc(4).length, 4)
  assert.equal(hex(B.from('ff00', 'hex')), 'ff00')
  assert.equal(B.from('hi').toString(), 'hi')
  assert.equal(hex(B.concat([B.from([1]), B.from([2])])), '0102')
  assert.equal(B.isBuffer(B.alloc(1)), true)
  assert.equal(B.isBuffer(new Uint8Array(1)), false, 'a bare Uint8Array is NOT a Buffer (matches Node)')

  // readUInt32BE / writeUInt32BE round-trip (wire.js seq/ack)
  const w = B.alloc(4)
  w.writeUInt32BE(0xdeadbeef, 0)
  assert.equal(w.readUInt32BE(0), 0xdeadbeef)

  // writeBigUInt64LE (the Noise nonce counter)
  const n = B.alloc(12)
  n.writeBigUInt64LE(1n, 4)
  assert.equal(hex(n), '000000000100000000000000')

  // copy + subarray + equals (used all over noise.js/wire.js)
  const src = B.from('0102030405', 'hex')
  const dst = B.alloc(3)
  src.copy(dst, 0, 1, 4)
  assert.equal(hex(dst), '020304')
  assert.equal(src.subarray(1, 3) instanceof B, true, 'subarray must stay a Buffer')
  assert.equal(src.subarray(0, 2).equals(B.from('0102', 'hex')), true)

  // Buffer.from(view) must COPY, not alias (aliasing here would be a silent corruption bug)
  const view = new Uint8Array([9, 9])
  const copy = B.from(view)
  view[0] = 1
  assert.equal(copy[0], 9, 'Buffer.from(view) must copy')
})
