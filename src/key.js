// src/key.js — identity keygen, contact-string encode/decode, commitment gate, rid derivation.
// Zero deps. ESM. Node >= 22. Buffers on the wire, one canonical UPPERCASE string for humans.
//
// Contract: docs/INTERFACES.md §Canonical + §src/key.js. Semantics: DESIGN.md D2/D3/D12.
// Rationale: research/crypto-firstcontact.md §1 (encoding math), §10 (security statement), §11.
//
// 130-bit payload = 26 Crockford-base32 chars, laid out MSB-first:
//   bits[0..5)   version/flags   (5 bits — see NOTE below)
//   bits[5..115) commitment      first 110 bits, big-endian, of
//                                SHA256("p2p-id-v1" ‖ edPub32 ‖ xPub32)
//   bits[115..130) checksum      first 15 bits of
//                                SHA256("p2p-ck-v1" ‖ first115bits packed big-endian
//                                       into 15 bytes, low 5 bits of last byte zero)
//
// NOTE to main (seam observation, non-blocking): INTERFACES pins bits[0..5) as the unit
// "version/flags" and decodeKey must return {version, flags}, but encodeKey exposes only a
// `version` param (no flags) and DESIGN D12 makes flags ("one-time invite", "mutual-expected")
// a P2 feature. This implementation reads the whole 5-bit field as `version` (0..31) and
// returns flags:0 (reserved) for v1 — the literal reading that honors every signature and
// round-trips exactly. If main wants a fixed version/flags sub-split, that is a one-line change
// here; flag it and I'll adjust.

import { createHash, generateKeyPairSync, hkdfSync, timingSafeEqual } from 'node:crypto'

/** Crockford base32 alphabet (canonical uppercase). Excludes I L O U. 32 symbols → 5 bits/char. */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** Domain-separation prefixes (ASCII). */
const ID_PREFIX = Buffer.from('p2p-id-v1', 'ascii')
const CK_PREFIX = Buffer.from('p2p-ck-v1', 'ascii')

/** Thrown on a malformed contact string: wrong length, non-alphabet char, or checksum mismatch. */
export class TypoError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message)
    this.name = 'TypoError'
  }
}

// ── bit/byte helpers ─────────────────────────────────────────────────────────

/**
 * Big-endian Buffer → BigInt.
 * @param {Buffer} buf
 * @returns {bigint}
 */
function bufToBig(buf) {
  return buf.length ? BigInt('0x' + buf.toString('hex')) : 0n
}

/**
 * BigInt → big-endian Buffer of exactly `n` bytes (value must fit).
 * @param {bigint} v
 * @param {number} n
 * @returns {Buffer}
 */
function bigToBuf(v, n) {
  const b = Buffer.alloc(n)
  for (let i = n - 1; i >= 0; i--) {
    b[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return b
}

/**
 * Normalize a single contact-string char to its base32 value.
 * Case-insensitive; ambiguity mapping I→1, L→1, O→0 (INTERFACES §Canonical).
 * @param {string} ch
 * @returns {number} 0..31
 */
function charValue(ch) {
  let up = ch.toUpperCase()
  if (up === 'I' || up === 'L') up = '1'
  else if (up === 'O') up = '0'
  const idx = ALPHABET.indexOf(up)
  if (idx === -1) throw new TypoError('invalid character: ' + JSON.stringify(ch))
  return idx
}

/**
 * Canonicalize a contact string to its UPPERCASE Crockford form (validates length + alphabet;
 * does NOT verify the checksum). Used for KDF input — "all KDF input uses the canonical ASCII
 * bytes of S" (INTERFACES §Canonical).
 * @param {string} s
 * @returns {string} 26-char canonical S
 */
function canonicalize(s) {
  if (typeof s !== 'string' || s.length !== 26) {
    throw new TypoError('key must be 26 chars, got ' + (typeof s === 'string' ? s.length : typeof s))
  }
  let out = ''
  for (const ch of s) out += ALPHABET[charValue(ch)]
  return out
}

/**
 * The 14-byte (110-bit, low 2 bits zero) identity commitment for a keypair.
 * commitment = first 110 bits, big-endian, of SHA256("p2p-id-v1" ‖ edPub32 ‖ xPub32).
 * @param {Buffer} edPub 32-byte raw Ed25519 public key
 * @param {Buffer} xPub  32-byte raw X25519 public key
 * @returns {Buffer} 14 bytes
 */
function commitmentFromKeys(edPub, xPub) {
  if (!Buffer.isBuffer(edPub) || edPub.length !== 32) throw new TypeError('edPub must be a 32-byte Buffer')
  if (!Buffer.isBuffer(xPub) || xPub.length !== 32) throw new TypeError('xPub must be a 32-byte Buffer')
  const h = createHash('sha256').update(ID_PREFIX).update(edPub).update(xPub).digest()
  const c = Buffer.alloc(14)
  h.copy(c, 0, 0, 14)
  c[13] &= 0xfc // keep top 6 bits of byte 13 → 110 meaningful bits, low 2 bits zero
  return c
}

/**
 * Compute the 15-bit checksum for a 115-bit (version‖commitment) prefix value.
 * @param {bigint} first115 the 115-bit value (version in high 5 bits, commitment in low 110)
 * @returns {bigint} 15-bit checksum
 */
function checksumOf(first115) {
  const buf15 = bigToBuf(first115 << 5n, 15) // 115 bits left-aligned in 120, low 5 bits zero
  const ck = createHash('sha256').update(CK_PREFIX).update(buf15).digest()
  return bufToBig(ck) >> 241n // top 15 bits of the 256-bit digest (256 - 15 = 241)
}

// ── public API ───────────────────────────────────────────────────────────────

/**
 * Generate a fresh identity: an Ed25519 signing pair + an X25519 static pair, bound together by
 * one commitment (DESIGN D3). Public keys are exported raw (32 bytes each); private keys are raw
 * 32-byte seeds/scalars.
 * @returns {{edPub:Buffer, edPriv:Buffer, xPub:Buffer, xPriv:Buffer, S:string}}
 */
export function generateIdentity() {
  const ed = generateKeyPairSync('ed25519')
  const x = generateKeyPairSync('x25519')
  const edJwkPub = ed.publicKey.export({ format: 'jwk' })
  const edJwkPriv = ed.privateKey.export({ format: 'jwk' })
  const xJwkPub = x.publicKey.export({ format: 'jwk' })
  const xJwkPriv = x.privateKey.export({ format: 'jwk' })
  const edPub = Buffer.from(edJwkPub.x, 'base64url')
  const edPriv = Buffer.from(edJwkPriv.d, 'base64url')
  const xPub = Buffer.from(xJwkPub.x, 'base64url')
  const xPriv = Buffer.from(xJwkPriv.d, 'base64url')
  const S = encodeKey(edPub, xPub, 0)
  return { edPub, edPriv, xPub, xPriv, S }
}

/**
 * Encode a keypair into the canonical 26-char contact string S.
 * @param {Buffer} edPub 32-byte raw Ed25519 public key
 * @param {Buffer} xPub  32-byte raw X25519 public key
 * @param {number} [version=0] 0..31 (occupies the 5-bit version/flags field; see file NOTE)
 * @returns {string} 26-char uppercase Crockford base32
 */
export function encodeKey(edPub, xPub, version = 0) {
  if (!Number.isInteger(version) || version < 0 || version > 31) {
    throw new RangeError('version must be an integer 0..31')
  }
  const commitmentBuf = commitmentFromKeys(edPub, xPub) // validates key lengths
  const version5 = BigInt(version)
  const commitment110 = bufToBig(commitmentBuf) >> 2n // 112-bit buf, low 2 zero → 110-bit value
  const first115 = (version5 << 110n) | commitment110
  const checksum15 = checksumOf(first115)
  const payload = (first115 << 15n) | checksum15 // 130 bits
  let s = ''
  for (let g = 0; g < 26; g++) {
    const shift = BigInt((25 - g) * 5)
    s += ALPHABET[Number((payload >> shift) & 0x1fn)]
  }
  return s
}

/**
 * Decode + checksum-validate a contact string. Case-insensitive with ambiguity mapping.
 * @param {string} s a 26-char contact string
 * @returns {{version:number, flags:number, commitment:Buffer}} commitment is 14 bytes (110 bits)
 * @throws {TypoError} on wrong length, non-alphabet char, or checksum mismatch
 */
export function decodeKey(s) {
  if (typeof s !== 'string') throw new TypoError('key must be a string, got ' + typeof s)
  if (s.length !== 26) throw new TypoError('key must be 26 chars, got ' + s.length)
  let payload = 0n
  for (const ch of s) payload = (payload << 5n) | BigInt(charValue(ch))
  const version = Number(payload >> 125n)
  const stored = payload & 0x7fffn // low 15 bits
  const first115 = payload >> 15n
  if (checksumOf(first115) !== stored) throw new TypoError('checksum mismatch')
  const commitment110 = (payload >> 15n) & ((1n << 110n) - 1n)
  const commitment = bigToBuf(commitment110 << 2n, 14) // left-aligned, low 2 bits zero
  return { version, flags: 0, commitment }
}

/**
 * Constant-time gate: does `commitment` (from decodeKey) match the keypair? (DESIGN D2/D4 gate.)
 * @param {Buffer} commitment 14-byte commitment
 * @param {Buffer} edPub 32-byte raw Ed25519 public key
 * @param {Buffer} xPub  32-byte raw X25519 public key
 * @returns {boolean}
 */
export function verifyCommitment(commitment, edPub, xPub) {
  if (!Buffer.isBuffer(edPub) || edPub.length !== 32) return false
  if (!Buffer.isBuffer(xPub) || xPub.length !== 32) return false
  if (!Buffer.isBuffer(commitment) || commitment.length !== 14) return false
  const expected = commitmentFromKeys(edPub, xPub)
  return timingSafeEqual(commitment, expected)
}

/**
 * Derive a rendezvous id from S for a channel + epoch, via HKDF-SHA256.
 * rid = HKDF-SHA256(ikm=canonical-ASCII(S), salt="p2p-rv-<channel>-v1", info=epochStr, L=len).
 * @param {string} s contact string (canonicalized to UPPERCASE for KDF input)
 * @param {string} channel e.g. "dht" | "tracker" | "mdns"
 * @param {string} epochStr UTC-day string "YYYY-MM-DD"
 * @param {number} len output byte length (20 for dht/tracker, 32 for mdns)
 * @returns {Buffer}
 */
export function deriveRid(s, channel, epochStr, len) {
  if (typeof channel !== 'string' || channel.length === 0) throw new TypeError('channel must be a non-empty string')
  if (typeof epochStr !== 'string') throw new TypeError('epochStr must be a string')
  if (!Number.isInteger(len) || len < 1 || len > 8160) throw new RangeError('len must be 1..8160')
  const ikm = Buffer.from(canonicalize(s), 'ascii')
  const salt = 'p2p-rv-' + channel + '-v1'
  return Buffer.from(hkdfSync('sha256', ikm, salt, epochStr, len))
}
