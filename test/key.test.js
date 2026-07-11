// test/key.test.js — node:test native runner, zero dev deps.
// Frozen KAT vectors are generated once from src/key.js and pinned here so encoding, checksum,
// commitment, and rid derivation stay byte-stable across refactors.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateIdentity,
  encodeKey,
  decodeKey,
  verifyCommitment,
  deriveRid,
  TypoError,
} from '../src/key.js'

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

// ── Frozen known-answer vectors (arbitrary but fixed 32-byte raw pubkeys) ──────
const KAT = {
  edPub: Buffer.from('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex'),
  xPub: Buffer.from('ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100', 'hex'),
  S: '0QNPVP2F1Y1W9WHCRY3ZCPC5MJ',
  commitmentHex: 'bd6dbb09e1f0789e4598f0fecb30',
  ridDht: 'dcdd8a771a2193c22d94c210e1e0d0b6a6cb7e28',
  ridTracker: 'bffab2ca424d48aebaceb2c1506aaefe4c2bdc0e',
  ridMdns: 'd9d90d7bdba11c00fa8a6ded4d14fdf2ed68c6d078f9390eeb222e7ba1b1174d',
}

test('encodeKey is stable against the frozen vector', () => {
  assert.equal(encodeKey(KAT.edPub, KAT.xPub, 0), KAT.S)
  assert.equal(KAT.S.length, 26)
})

test('decodeKey returns the frozen commitment / version / flags', () => {
  const d = decodeKey(KAT.S)
  assert.equal(d.version, 0)
  assert.equal(d.flags, 0)
  assert.equal(d.commitment.length, 14)
  assert.equal(d.commitment.toString('hex'), KAT.commitmentHex)
  // low 2 bits of the 14th byte are always zero (110-bit commitment, left-aligned)
  assert.equal(d.commitment[13] & 0x03, 0)
})

test('round-trip: encode → decode → verifyCommitment for a random identity', () => {
  for (let i = 0; i < 50; i++) {
    const id = generateIdentity()
    assert.equal(id.S.length, 26)
    assert.equal(id.edPub.length, 32)
    assert.equal(id.xPub.length, 32)
    assert.equal(id.edPriv.length, 32)
    assert.equal(id.xPriv.length, 32)
    const d = decodeKey(id.S)
    assert.equal(d.version, 0)
    // canonical re-encode is idempotent
    assert.equal(encodeKey(id.edPub, id.xPub, 0), id.S)
    // gate accepts the true keypair
    assert.equal(verifyCommitment(d.commitment, id.edPub, id.xPub), true)
  }
})

test('version field round-trips across the full 0..31 range', () => {
  const { edPub, xPub } = generateIdentity()
  for (let v = 0; v < 32; v++) {
    const s = encodeKey(edPub, xPub, v)
    assert.equal(decodeKey(s).version, v)
  }
  assert.throws(() => encodeKey(edPub, xPub, 32), RangeError)
  assert.throws(() => encodeKey(edPub, xPub, -1), RangeError)
})

test('every single-char typo (all 26 positions × all 31 other chars) flips the checksum', () => {
  // Deterministic over the frozen S → 806 mutations, all must throw TypoError. Verified 0
  // survivors at authoring time (a 15-bit checksum admits ~1/32768 undetectable collisions;
  // the frozen vector has none across its whole mutation space, so this can never flake).
  let checked = 0
  for (let i = 0; i < 26; i++) {
    for (const c of ALPHABET) {
      if (c === KAT.S[i]) continue
      const mut = KAT.S.slice(0, i) + c + KAT.S.slice(i + 1)
      assert.throws(() => decodeKey(mut), TypoError, `expected typo at pos ${i} → ${c} to be caught`)
      checked++
    }
  }
  assert.equal(checked, 806)
})

test('ambiguous-char + case normalization decodes identically', () => {
  // lowercase, with 0→o and 1→l (Crockford ambiguity mapping O→0, L→1)
  const variant = KAT.S.split('')
    .map((ch) => (ch === '0' ? 'o' : ch === '1' ? 'l' : ch.toLowerCase()))
    .join('')
  assert.notEqual(variant, KAT.S) // genuinely different input bytes
  assert.deepEqual(decodeKey(variant), decodeKey(KAT.S))
  // explicit I→1 and O→0 spot checks
  const withI = KAT.S.replaceAll('1', 'I')
  assert.deepEqual(decodeKey(withI), decodeKey(KAT.S))
  const withO = KAT.S.replaceAll('0', 'O')
  assert.deepEqual(decodeKey(withO), decodeKey(KAT.S))
})

test('decodeKey rejects wrong length and non-alphabet chars', () => {
  assert.throws(() => decodeKey(KAT.S.slice(0, 25)), TypoError) // too short
  assert.throws(() => decodeKey(KAT.S + '0'), TypoError) // too long
  assert.throws(() => decodeKey('U'.repeat(26)), TypoError) // U is not in Crockford alphabet
  assert.throws(() => decodeKey('0QNPVP2F1Y1W9WHCRY3ZCPC5M '), TypoError) // space
  assert.throws(() => decodeKey('0QNPVP2F1Y1W9WHCRY3ZCPC5M!'), TypoError) // punctuation
  assert.throws(() => decodeKey(12345), TypoError) // non-string
})

test('verifyCommitment: positive and negative', () => {
  const id = generateIdentity()
  const { commitment } = decodeKey(id.S)
  // positive
  assert.equal(verifyCommitment(commitment, id.edPub, id.xPub), true)
  // negative: tampered edPub (flip one bit)
  const badEd = Buffer.from(id.edPub)
  badEd[0] ^= 0x01
  assert.equal(verifyCommitment(commitment, badEd, id.xPub), false)
  // negative: swapped ed/x pins (mix-and-match must fail — D2)
  assert.equal(verifyCommitment(commitment, id.xPub, id.edPub), false)
  // negative: wrong commitment (from a different identity)
  const other = decodeKey(generateIdentity().S).commitment
  assert.equal(verifyCommitment(other, id.edPub, id.xPub), false)
  // negative: malformed inputs
  assert.equal(verifyCommitment(Buffer.alloc(13), id.edPub, id.xPub), false)
  assert.equal(verifyCommitment(commitment, Buffer.alloc(31), id.xPub), false)
  assert.equal(verifyCommitment('nope', id.edPub, id.xPub), false)
})

test('deriveRid is a stable known-answer and honors length + domain separation', () => {
  assert.equal(deriveRid(KAT.S, 'dht', '2026-07-11', 20).toString('hex'), KAT.ridDht)
  assert.equal(deriveRid(KAT.S, 'tracker', '2026-07-11', 20).toString('hex'), KAT.ridTracker)
  assert.equal(deriveRid(KAT.S, 'mdns', '2026-07-11', 32).toString('hex'), KAT.ridMdns)
  // lengths
  assert.equal(deriveRid(KAT.S, 'dht', '2026-07-11', 20).length, 20)
  assert.equal(deriveRid(KAT.S, 'mdns', '2026-07-11', 32).length, 32)
  // canonical KDF input: lowercase S yields identical rid
  assert.deepEqual(deriveRid(KAT.S.toLowerCase(), 'dht', '2026-07-11', 20), deriveRid(KAT.S, 'dht', '2026-07-11', 20))
  // domain separation: channel and epoch both change the output
  assert.notDeepEqual(
    deriveRid(KAT.S, 'dht', '2026-07-11', 20),
    deriveRid(KAT.S, 'tracker', '2026-07-11', 20),
  )
  assert.notDeepEqual(
    deriveRid(KAT.S, 'dht', '2026-07-11', 20),
    deriveRid(KAT.S, 'dht', '2026-07-12', 20),
  )
})
