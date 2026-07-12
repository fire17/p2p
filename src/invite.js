// src/invite.js — per-invite one-time secret K_inv: the metadata-privacy primitive (v1).
//
// Design: research/metadata-privacy.md §3–§6, §9 "v1", §10. Zero deps (node:crypto only).
//
// ONE 128-bit secret, handed out-of-band to exactly ONE invitee alongside the 26-char identity
// string S, does four domain-separated jobs (§3.2):
//
//   rid_inv_<ch> = HKDF(K_inv, salt="p2p-rvk-<ch>-v1", info=epoch, L=ridLen)  // WHERE we publish
//   k_ip         = HKDF(K_inv, salt="p2p-ip-v1",       info="",    L=32)      // AEAD key for candidates
//   psk          = HKDF(K_inv, salt="p2p-psk-v1",      info="",    L=32)      // Noise IKpsk2 psk (§5)
//   bep_seed     = HKDF(K_inv, salt="p2p-bep44-v1",    info="",    L=32)      // Ed25519 seed for BEP44 (§4.2)
//
// Consequences: a non-holder of K_inv cannot even LOCATE the record (rid is K_inv-derived), cannot
// DECRYPT it (candidates are AEAD-sealed under k_ip), and cannot COMPLETE the handshake (IKpsk2).
// A different contact who holds the reusable S has none of this invite's K_inv → sees nothing.
//
// The identity core is untouched: S, its commitment, and the plain-IK wire bytes are byte-identical
// to v0.1.0. Invite mode is selected by the INVITE flag bit inside S's existing 5-bit version/flags
// field (DESIGN D12 / crypto-firstcontact §1.3 reserved it) — so `encodeKey(ed, x, INVITE_FLAG)`
// stamps it and `hasInvite(decodeKey(S).version)` reads it back. No change to src/key.js.
//
// ── AEAD nonce discipline (the §4.1 / §12 open question, closed) ──────────────────────────────
// The study wanted XChaCha20-Poly1305 (24-byte nonce → random nonces, no counter). node:crypto has
// only RFC-8439 ChaCha20-Poly1305 (12-byte nonce) and adding a dep is forbidden. Instead of
// random 12-byte nonces (birthday-bound), we use the standard extended-nonce CONSTRUCTION with the
// primitive we do have: each seal draws a fresh random 16-byte `salt`, derives a PER-SEAL subkey
//     k_seal = HKDF-SHA256(ikm=k_ip, salt=salt16, info="p2p-ip-seal-v1", L=32)
// and encrypts under an ALL-ZERO 12-byte nonce. A (key, nonce) pair therefore repeats only if the
// same 16-byte salt repeats — and each salt is used with exactly one message, so nonce reuse under
// a fixed key is impossible short of a 128-bit salt collision (~2^-128 per pair; at invite scale,
// a handful of re-announces, the union bound is negligible). This is exactly the HSalsa/HChaCha
// idea (subkey per random salt), built from HKDF instead of a core we don't have.
//
// ── Fingerprint fixes shipped here (§6) ──────────────────────────────────────────────────────
//   • plaintext is PADDED to a fixed 512 bytes before sealing → sealed blob is always 544 bytes,
//     so candidate count / IPv6 presence / LAN hints never leak from ciphertext length.
//   • the literal `a=p2p-blob:` SDP attribute name is gone (see src/rendezvous/tracker.js:
//     the attribute name is now derived pseudorandomly from the rid — no constant tell on the wire).
//
// ── Entropy: a DOCUMENTED DEVIATION from Noise §14 (study §5) ────────────────────────────────
// Noise rev-34 §14 states a MUST: "Pre-shared symmetric keys must be secret values with 256 bits of
// entropy." Our psk is a 32-BYTE value (length-compliant) but HKDF cannot manufacture entropy: with
// the DEFAULT 128-bit K_inv the psk carries ~128 bits. That is length-compliant, entropy
// NON-compliant — stated, not hidden. 128 bits is infeasible to brute-force offline, and the psk is
// additive hardening on top of IK's pinned-static DH auth, never the sole auth. For strict §14
// conformance call generateInviteSecret(256) → a 54-char tail (QR/deep-link territory) whose psk is
// fully compliant. Default = 128-bit per the study's recommendation.
//
// ── INTENDED WIRING (for main; node.js/race.js are NOT this lane's files) ────────────────────
// The API below is shaped so the hub diff is small:
//   1. node.connect(share) / listen(id, {invite}) call `parseShare(str)` → {S, secret}.
//   2. If secret: `const inv = createInvite(secret)`.
//   3. race.publishAll/resolve use `inv.rid(ch.name, epoch, ch.ridLen)` in place of
//      `deriveRid(S, ...)`, and construct channels with the blob codec:
//        createTracker({ codec: inv.codec })   // sealed SDP payload, neutral attribute name
//        createDht({ invite: inv })            // encrypted BEP44 put/get instead of announce_peer
//   4. The Noise calls take one extra option: `initiator({..., psk: inv.psk, prologue: inv.prologue(rid, epoch)})`
//      and the same on `responder(...)` → Noise_IKpsk2. Without `psk` the bytes are today's plain IK.
//   5. Publisher stamps the flag when minting an invite: `encodeKey(edPub, xPub, INVITE_FLAG)`
//      (v2's burn/rotate then stops republishing + retires K_inv after the first handshake).

import { createHash, createPrivateKey, createPublicKey, hkdfSync, randomBytes, sign as edSign, verify as edVerify, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto'
import { TypoError } from './key.js'

export { TypoError }

/** Crockford base32 (same alphabet/ambiguity rules as src/key.js — one UX for humans). */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** The reserved "one-time invite" bit inside S's 5-bit version/flags field (DESIGN D12). */
export const INVITE_FLAG = 0x10

/**
 * Fixed plaintext size (bytes) every candidate blob is padded to before sealing (§6). 512 comfortably
 * holds a realistic candidate set (host + srflx + IPv6 + relay ≈ 6 entries ≈ 350 B of JSON) while the
 * sealed blob (544 B) stays well under BEP44's 1000-byte soft cap for `v`.
 */
export const PAD_LEN = 512
/** Sealed blob is always this many bytes: 16 salt + PAD_LEN + 16 tag. */
export const SEALED_LEN = 16 + PAD_LEN + 16

const TAGLEN = 16
const ZERO_NONCE = Buffer.alloc(12)
// Ed25519 raw-seed → PKCS8 DER framing (RFC 8410 fixed prefix; same trick src/noise.js uses for X25519).
const ED_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

/** true if a decodeKey().version carries the one-time-invite flag. @param {number} version */
export function hasInvite(version) {
  return Number.isInteger(version) && (version & INVITE_FLAG) !== 0
}

// ── base32 token (secret ‖ checksum), symmetric with S's UX ───────────────────────────────────

function charValue(ch) {
  let up = ch.toUpperCase()
  if (up === 'I' || up === 'L') up = '1'
  else if (up === 'O') up = '0'
  const idx = ALPHABET.indexOf(up)
  if (idx === -1) throw new TypoError('invalid invite character: ' + JSON.stringify(ch))
  return idx
}

const bufToBig = (buf) => (buf.length ? BigInt('0x' + buf.toString('hex')) : 0n)

function bigToBuf(v, n) {
  const b = Buffer.alloc(n)
  for (let i = n - 1; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n }
  return b
}

/** checksum bits for a token of `len` secret bytes: pad up to the next 5-bit boundary, ≥12 bits. */
function ckBitsFor(len) {
  const bits = len * 8
  const chars = Math.ceil((bits + 12) / 5)
  return chars * 5 - bits // 16B → 12 bits (28 chars); 32B → 14 bits (54 chars)
}

function checksumOf(secret, nbits) {
  const h = createHash('sha256').update(Buffer.from('p2p-ick-v1', 'ascii')).update(secret).digest()
  return bufToBig(h) >> BigInt(256 - nbits) // top `nbits` of the digest
}

/**
 * Mint a fresh one-time invite secret K_inv.
 * @param {number} [bits=128] 128 (default, 28-char tail) or 256 (strict Noise-§14 psk entropy, 54-char tail)
 * @returns {Buffer} the raw secret
 */
export function generateInviteSecret(bits = 128) {
  if (bits !== 128 && bits !== 256) throw new RangeError('invite secret must be 128 or 256 bits')
  return randomBytes(bits / 8)
}

/**
 * Encode K_inv as an uppercase Crockford-base32 token with its own checksum (a typo'd invite fails
 * before any network work — §3.3).
 * @param {Buffer} secret 16 or 32 raw bytes
 * @returns {string} 28 chars (128-bit) or 54 chars (256-bit)
 */
export function encodeInvite(secret) {
  if (!Buffer.isBuffer(secret) || (secret.length !== 16 && secret.length !== 32)) {
    throw new TypeError('invite secret must be a 16- or 32-byte Buffer')
  }
  const ckBits = ckBitsFor(secret.length)
  const payload = (bufToBig(secret) << BigInt(ckBits)) | checksumOf(secret, ckBits)
  const chars = (secret.length * 8 + ckBits) / 5
  let s = ''
  for (let g = 0; g < chars; g++) s += ALPHABET[Number((payload >> BigInt((chars - 1 - g) * 5)) & 0x1fn)]
  return s
}

/**
 * Decode + checksum-validate an invite token. Case-insensitive, Crockford ambiguity mapping.
 * @param {string} token
 * @returns {Buffer} the raw secret (16 or 32 bytes)
 * @throws {TypoError} wrong length, bad char, or checksum mismatch
 */
export function decodeInvite(token) {
  if (typeof token !== 'string') throw new TypoError('invite must be a string, got ' + typeof token)
  if (token.length !== 28 && token.length !== 54) {
    throw new TypoError('invite must be 28 or 54 chars, got ' + token.length)
  }
  const len = token.length === 28 ? 16 : 32
  const ckBits = ckBitsFor(len)
  let payload = 0n
  for (const ch of token) payload = (payload << 5n) | BigInt(charValue(ch))
  const stored = payload & ((1n << BigInt(ckBits)) - 1n)
  const secret = bigToBuf(payload >> BigInt(ckBits), len)
  if (checksumOf(secret, ckBits) !== stored) throw new TypoError('invite checksum mismatch')
  return secret
}

/**
 * The share string: identity + one-time secret as ONE copy-paste unit (§3.3).
 *   S "-" base32(K_inv)     e.g.  <26 chars> - <28 chars>
 * @param {string} s the 26-char contact string S (flag bit expected but not enforced here)
 * @param {Buffer} secret
 * @returns {string}
 */
export function formatShare(s, secret) {
  if (typeof s !== 'string' || s.length !== 26) throw new TypoError('S must be 26 chars')
  return s.toUpperCase() + '-' + encodeInvite(secret)
}

/**
 * Parse either form of a shared string. Bare S → reusable mode (today's behaviour, secret=null).
 * `S-INV` → invite mode. Both halves are checksum-validated (TypoError before any network work).
 * @param {string} str
 * @returns {{S:string, secret:Buffer|null, invite:boolean}}
 */
export function parseShare(str) {
  if (typeof str !== 'string') throw new TypoError('share must be a string, got ' + typeof str)
  const t = str.trim().toUpperCase()
  const dash = t.indexOf('-')
  if (dash === -1) return { S: t, secret: null, invite: false }
  const S = t.slice(0, dash)
  const secret = decodeInvite(t.slice(dash + 1))
  if (S.length !== 26) throw new TypoError('key must be 26 chars, got ' + S.length)
  return { S, secret, invite: true }
}

// ── HKDF derivations (§3.2) ───────────────────────────────────────────────────────────────────

const hk = (secret, salt, info, len) => Buffer.from(hkdfSync('sha256', secret, salt, info, len))

/** rid_inv for a channel+epoch. NOTE the `p2p-rvk-` namespace — never collides with S-derived rids. */
export function deriveInviteRid(secret, channel, epochStr, len) {
  if (typeof channel !== 'string' || !channel.length) throw new TypeError('channel must be a non-empty string')
  if (typeof epochStr !== 'string') throw new TypeError('epochStr must be a string')
  if (!Number.isInteger(len) || len < 1 || len > 8160) throw new RangeError('len must be 1..8160')
  return hk(secret, 'p2p-rvk-' + channel + '-v1', epochStr, len)
}

// ── the sealed candidate blob (§4.1) ──────────────────────────────────────────────────────────

/** length-prefixed, zero-padded to PAD_LEN (fixed-size ciphertext → no size leak, §6). */
function pad(plain) {
  if (plain.length > PAD_LEN - 2) throw new RangeError('blob too large to pad: ' + plain.length)
  const out = Buffer.alloc(PAD_LEN)
  out.writeUInt16BE(plain.length, 0)
  plain.copy(out, 2)
  return out
}
function unpad(padded) {
  if (padded.length !== PAD_LEN) return null
  const n = padded.readUInt16BE(0)
  if (n > PAD_LEN - 2) return null
  return padded.subarray(2, 2 + n)
}

/**
 * Seal a candidate blob under k_ip. Output is ALWAYS SEALED_LEN bytes: salt16 ‖ AEAD(pad(json)).
 * ad = rid binds the ciphertext to the exact rendezvous it was published at (anti-cross-context
 * replay). rid = HKDF(K_inv, "p2p-rvk-<ch>-v1", epoch) already carries the channel AND the epoch, so
 * binding to the rid transitively binds both — no separate epoch term is needed in the AD.
 * @param {Buffer} kIp 32-byte AEAD key
 * @param {object} blob { v, ts, candidates }
 * @param {Buffer} rid the rid it is published under
 * @returns {Buffer} SEALED_LEN bytes
 */
export function sealBlob(kIp, blob, rid) {
  const salt = randomBytes(16)
  const kSeal = hk(kIp, salt, 'p2p-ip-seal-v1', 32) // per-seal subkey → zero nonce is safe (see header)
  const ad = Buffer.from(rid)
  const plain = pad(Buffer.from(JSON.stringify(blob), 'utf8'))
  const c = createCipheriv('chacha20-poly1305', kSeal, ZERO_NONCE, { authTagLength: TAGLEN })
  c.setAAD(ad, { plaintextLength: plain.length })
  const body = Buffer.concat([c.update(plain), c.final()])
  return Buffer.concat([salt, body, c.getAuthTag()])
}

/**
 * Open a sealed blob. Returns null on ANY failure (wrong key, tamper, truncation, bad json) —
 * a rendezvous channel must never throw on hostile input; it just ignores the record.
 * @returns {object|null}
 */
export function openBlob(kIp, sealed, rid) {
  if (!Buffer.isBuffer(sealed) || sealed.length !== SEALED_LEN) return null
  const salt = sealed.subarray(0, 16)
  const body = sealed.subarray(16, sealed.length - TAGLEN)
  const tag = sealed.subarray(sealed.length - TAGLEN)
  const kSeal = hk(kIp, salt, 'p2p-ip-seal-v1', 32)
  const ad = Buffer.from(rid)
  try {
    const d = createDecipheriv('chacha20-poly1305', kSeal, ZERO_NONCE, { authTagLength: TAGLEN })
    d.setAAD(ad, { plaintextLength: body.length })
    d.setAuthTag(tag)
    const padded = Buffer.concat([d.update(body), d.final()]) // throws on tag failure
    const plain = unpad(padded)
    if (!plain) return null
    return JSON.parse(plain.toString('utf8'))
  } catch {
    return null
  }
}

// ── BEP44 (§4.2): both parties derive the SAME Ed25519 keypair from K_inv ─────────────────────

/**
 * Ed25519 keypair from a 32-byte seed. `pub` is the RAW 32 bytes BEP44 puts on the wire (`k`);
 * `pubKey` is the KeyObject node:crypto needs to verify with (raw bytes are not accepted).
 * @returns {{priv:import('node:crypto').KeyObject, pub:Buffer, pubKey:import('node:crypto').KeyObject}}
 */
export function ed25519FromSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) throw new TypeError('seed must be 32 bytes')
  const priv = createPrivateKey({ key: Buffer.concat([ED_PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' })
  const pubKey = createPublicKey(priv)
  const pub = Buffer.from(pubKey.export({ type: 'spki', format: 'der' }).subarray(-32))
  return { priv, pub, pubKey }
}

/** BEP44 mutable-item target = SHA1(pubkey ‖ salt) (spec: pubkey THEN salt). */
export function bep44Target(pub, salt) {
  return createHash('sha1').update(pub).update(salt).digest()
}

/** The exact bytes BEP44 signs: "4:salt<len>:<salt>3:seqi<seq>e1:v<len>:<v>" (BEP44 signing rule). */
export function bep44SignInput(salt, seq, v) {
  const parts = []
  if (salt && salt.length) parts.push(Buffer.from(`4:salt${salt.length}:`, 'ascii'), Buffer.from(salt))
  parts.push(Buffer.from(`3:seqi${seq}e1:v${v.length}:`, 'ascii'), Buffer.from(v))
  return Buffer.concat(parts)
}

// ── the invite context (everything a peer needs, derived once) ────────────────────────────────

/**
 * Derive every invite-mode key/helper from K_inv. Cheap; hold one per active invite.
 * @param {Buffer} secret K_inv (16 or 32 bytes)
 */
export function createInvite(secret) {
  if (!Buffer.isBuffer(secret) || (secret.length !== 16 && secret.length !== 32)) {
    throw new TypeError('K_inv must be a 16- or 32-byte Buffer')
  }
  const kIp = hk(secret, 'p2p-ip-v1', '', 32)
  const psk = hk(secret, 'p2p-psk-v1', '', 32)
  const bepSeed = hk(secret, 'p2p-bep44-v1', '', 32)
  const bepKeys = ed25519FromSeed(bepSeed)

  return {
    secret,
    kIp,
    psk,
    bepPub: bepKeys.pub,
    bepPriv: bepKeys.priv,
    /** rid_inv for a channel+epoch (§4.4) — only a K_inv holder can compute WHERE we published. */
    rid: (channel, epochStr, len) => deriveInviteRid(secret, channel, epochStr, len),
    /** Noise prologue binding the handshake to the exact rendezvous it arrived on (§5). */
    prologue: (rid) => Buffer.concat([Buffer.from('p2p-inv-v1', 'ascii'), Buffer.from(rid)]),
    // BEP44 salt = the rid itself (20 bytes; spec caps salt at 64). It is already
    // HKDF(K_inv, channel, epoch), so the target rotates per epoch and per invite for free, and both
    // parties derive it from the one thing they already agree on — no extra plumbing through race.js.
    bep44Salt: (rid) => Buffer.from(rid),
    bep44Target: (rid) => bep44Target(bepKeys.pub, Buffer.from(rid)),
    /** Sign a BEP44 mutable-item value with the K_inv-derived key. @returns {Buffer} 64-byte sig */
    bep44Sign: (rid, seq, v) => Buffer.from(edSign(null, bep44SignInput(Buffer.from(rid), seq, v), bepKeys.priv)),
    /** Verify a BEP44 mutable-item signature (belt-and-braces beside the AEAD tag). */
    bep44Verify: (rid, seq, v, sig) => {
      try { return edVerify(null, bep44SignInput(Buffer.from(rid), seq, v), bepKeys.pubKey, sig) } catch { return false }
    },
    /**
     * The blob codec handed to createTracker/createDht. `seal` returns bytes for the wire; `open`
     * returns the blob object or null. Rendezvous channels stay crypto-agnostic — they just carry
     * opaque bytes (which is exactly why the DEFAULT codec, plaintext JSON, is byte-identical to
     * today's reusable-S wire).
     */
    codec: {
      sealed: true,
      seal: (blob, rid) => sealBlob(kIp, blob, rid),
      open: (bytes, rid) => openBlob(kIp, bytes, rid),
    },
  }
}

/** Constant-time buffer equality (exported for tests / gate code). */
export function equal(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length && timingSafeEqual(a, b)
}

export default { createInvite, generateInviteSecret, encodeInvite, decodeInvite, formatShare, parseShare, INVITE_FLAG, hasInvite }
