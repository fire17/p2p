// test/noise.test.js — node:test native runner, zero dev deps.
//
// THE ASSURANCE REGIME (DESIGN D5):
//  (a) official Noise_IK_25519_ChaChaPoly_SHA256 KAT vector (rweather/noise-c) asserted
//      byte-exact: handshake msg1/msg2, every transport message, and the handshake hash.
//  (b) fail-closed negative suite: tampered tag, truncated msg1, wrong static, all-zero /
//      low-order X25519 point, nonce rollover, within-session replay / out-of-turn.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { createPublicKey, createPrivateKey } from 'node:crypto'
import { initiator, responder, HandshakeError } from '../src/noise.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const VEC = JSON.parse(readFileSync(join(HERE, 'vectors', 'noise_ik_25519_chachapoly_sha256.json'), 'utf8'))

const hex = (h) => Buffer.from(h, 'hex')
const X_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')

/** Derive a raw 32-byte X25519 public key from a raw 32-byte private key (test-side, node native). */
function xPubFromPriv(rawPriv) {
  const priv = createPrivateKey({ key: Buffer.concat([X_PKCS8_PREFIX, rawPriv]), format: 'der', type: 'pkcs8' })
  return Buffer.from(createPublicKey(priv).export({ type: 'spki', format: 'der' }).subarray(-32))
}

// ── (a) official KAT vectors, byte-exact — TWO independent sources ──────────────
// The committed vector file carries the Noise_IK_25519_ChaChaPoly_SHA256 entry from
// centromere/cacophony AND mcginty/snow (two independently-audited Noise impls). BOTH
// must match byte-exact: handshake msg1/msg2, every transport message, and (where the
// source publishes it) the handshake hash. This is the interop assurance DESIGN D5 demands.
const SOURCES = Object.entries(VEC.extracted).map(([name, o]) => ({ name, url: o.source_url, v: o.vector }))

for (const src of SOURCES) {
  test(`KAT byte-exact vs ${src.name}: Noise_IK_25519_ChaChaPoly_SHA256`, () => {
    const v = src.v
    const initStatic = hex(v.init_static)
    const respStatic = hex(v.resp_static)
    const respStaticPub = xPubFromPriv(respStatic)

    // sanity: the vector's init_remote_static IS the responder's static public key.
    assert.equal(respStaticPub.toString('hex'), v.init_remote_static, 'resp static pub == init_remote_static')

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

    // msg1: initiator -> responder
    const msg1 = hs_i.writeMessage(hex(m[0].payload))
    assert.equal(msg1.toString('hex'), m[0].ciphertext, 'msg1 ciphertext')
    assert.deepEqual(hs_r.readMessage(msg1), hex(m[0].payload), 'msg1 payload decrypts')

    // msg2: responder -> initiator (THE ACK)
    const msg2 = hs_r.writeMessage(hex(m[1].payload))
    assert.equal(msg2.toString('hex'), m[1].ciphertext, 'msg2 ciphertext')
    assert.deepEqual(hs_i.readMessage(msg2), hex(m[1].payload), 'msg2 payload decrypts')

    assert.equal(hs_i.complete, true)
    assert.equal(hs_r.complete, true)

    const si = hs_i.split()
    const sr = hs_r.split()
    assert.deepEqual(si.handshakeHash, sr.handshakeHash, 'both sides derive same handshake hash')
    if (v.handshake_hash) {
      assert.equal(si.handshakeHash.toString('hex'), v.handshake_hash, 'handshake hash == vector')
    }

    // transport messages: alternate starting with the initiator (Noise test-vector convention).
    for (let k = 2; k < m.length; k++) {
      const initToResp = k % 2 === 0
      const sender = initToResp ? si.tx : sr.tx
      const receiver = initToResp ? sr.rx : si.rx
      const ct = sender.encrypt(hex(m[k].payload))
      assert.equal(ct.toString('hex'), m[k].ciphertext, `transport msg ${k} ciphertext`)
      assert.deepEqual(receiver.decrypt(hex(m[k].ciphertext)), hex(m[k].payload), `transport msg ${k} decrypts`)
    }
  })
}

// ── full random handshake: both derive matching keys, both directions roundtrip ──
function randomIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519')
  return {
    priv: Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32)),
    pub: Buffer.from(publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)),
  }
}
import * as crypto from 'node:crypto'

function runHandshake(prologue) {
  const alice = randomIdentity() // responder (owner)
  const bob = randomIdentity() // initiator
  const hs_i = initiator({ localX: bob, remoteXPub: alice.pub, prologue })
  const hs_r = responder({ localX: alice, prologue })
  const msg1 = hs_i.writeMessage(Buffer.from('hello'))
  assert.deepEqual(hs_r.readMessage(msg1), Buffer.from('hello'))
  const msg2 = hs_r.writeMessage(Buffer.from('ack'))
  assert.deepEqual(hs_i.readMessage(msg2), Buffer.from('ack'))
  return { si: hs_i.split(), sr: hs_r.split(), alice, bob, hs_i, hs_r }
}

test('full IK handshake: matching keys + bidirectional transport roundtrip', () => {
  const { si, sr } = runHandshake(Buffer.alloc(0))
  assert.deepEqual(si.handshakeHash, sr.handshakeHash)

  // initiator -> responder
  const a = si.tx.encrypt(Buffer.from('from bob'))
  assert.deepEqual(sr.rx.decrypt(a), Buffer.from('from bob'))
  // responder -> initiator
  const b = sr.tx.encrypt(Buffer.from('from alice'))
  assert.deepEqual(si.rx.decrypt(b), Buffer.from('from alice'))

  // multiple messages advance the nonce independently per direction.
  for (let i = 0; i < 5; i++) {
    const pt = Buffer.from('msg' + i)
    assert.deepEqual(sr.rx.decrypt(si.tx.encrypt(pt)), pt)
  }
  // authenticated additional-data binds: wrong ad fails to decrypt.
  const withAd = si.tx.encrypt(Buffer.from('bound'), Buffer.from('ad1'))
  assert.throws(() => sr.rx.decrypt(withAd, Buffer.from('ad2')), HandshakeError)
})

// ── (b) negative suite — every case MUST fail closed ────────────────────────────

test('negative: tampered AEAD tag in msg1 is rejected', () => {
  const alice = randomIdentity()
  const bob = randomIdentity()
  const hs_i = initiator({ localX: bob, remoteXPub: alice.pub })
  const hs_r = responder({ localX: alice })
  const msg1 = hs_i.writeMessage(Buffer.from('x'))
  const tampered = Buffer.from(msg1)
  tampered[tampered.length - 1] ^= 0x01 // flip last tag byte
  assert.throws(() => hs_r.readMessage(tampered), HandshakeError)
})

test('negative: tampered encrypted static in msg1 is rejected', () => {
  const alice = randomIdentity()
  const bob = randomIdentity()
  const hs_i = initiator({ localX: bob, remoteXPub: alice.pub })
  const hs_r = responder({ localX: alice })
  const msg1 = hs_i.writeMessage(Buffer.from('x'))
  const tampered = Buffer.from(msg1)
  tampered[40] ^= 0x01 // inside the encrypted static block
  assert.throws(() => hs_r.readMessage(tampered), HandshakeError)
})

test('negative: truncated msg1 is rejected', () => {
  const alice = randomIdentity()
  const bob = randomIdentity()
  const hs_i = initiator({ localX: bob, remoteXPub: alice.pub })
  const hs_r = responder({ localX: alice })
  const msg1 = hs_i.writeMessage(Buffer.from('x'))
  assert.throws(() => hs_r.readMessage(msg1.subarray(0, 20)), HandshakeError)
  assert.throws(() => hs_r.readMessage(msg1.subarray(0, msg1.length - 1)), HandshakeError)
})

test('negative: wrong pinned static key breaks the handshake (impersonation blocked)', () => {
  const alice = randomIdentity()
  const bob = randomIdentity()
  const impostor = randomIdentity()
  // Bob pins the impostor's key (a MITM substituted it at the rendezvous) but talks to real Alice.
  const hs_i = initiator({ localX: bob, remoteXPub: impostor.pub })
  const hs_r = responder({ localX: alice })
  const msg1 = hs_i.writeMessage(Buffer.from('x'))
  // Alice used her real static → es/ss mismatch → AEAD auth fails. Fails closed.
  assert.throws(() => hs_r.readMessage(msg1), HandshakeError)
})

test('negative: all-zero / low-order X25519 static point is rejected', () => {
  const bob = randomIdentity()
  const hs_i = initiator({ localX: bob, remoteXPub: Buffer.alloc(32) }) // all-zero pinned static
  assert.throws(() => hs_i.writeMessage(Buffer.from('x')), HandshakeError)
})

test('negative: nonce counter exhaustion throws instead of reusing a nonce', () => {
  const { si } = runHandshake(Buffer.alloc(0))
  si.tx._cs.n = (1n << 64n) - 1n // force MAX_NONCE
  assert.throws(() => si.tx.encrypt(Buffer.from('boom')), HandshakeError)
})

test('negative: within-session replay / out-of-turn calls fail closed', () => {
  const alice = randomIdentity()
  const bob = randomIdentity()
  const hs_i = initiator({ localX: bob, remoteXPub: alice.pub })
  const hs_r = responder({ localX: alice })
  const msg1 = hs_i.writeMessage(Buffer.from('x'))
  // initiator cannot write twice in a row (out of turn).
  assert.throws(() => hs_i.writeMessage(Buffer.from('again')), HandshakeError)
  hs_r.readMessage(msg1)
  // responder cannot read the same msg1 again (already advanced).
  assert.throws(() => hs_r.readMessage(msg1), HandshakeError)
  const msg2 = hs_r.writeMessage(Buffer.from('ack'))
  hs_i.readMessage(msg2)
  // both complete → further handshake ops throw; split is required instead.
  assert.throws(() => hs_i.readMessage(msg2), HandshakeError)
  assert.throws(() => hs_r.writeMessage(Buffer.from('x')), HandshakeError)
})

test('negative: split before completion throws', () => {
  const alice = randomIdentity()
  const bob = randomIdentity()
  const hs_i = initiator({ localX: bob, remoteXPub: alice.pub })
  assert.throws(() => hs_i.split(), HandshakeError)
})
