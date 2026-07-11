// src/noise.js — Noise_IK_25519_ChaChaPoly_SHA256, in-house, zero-dep (node:crypto only).
//
// Contract: docs/INTERFACES.md §src/noise.js · semantics: DESIGN.md D4/D5 ·
// protocol: research/crypto-firstcontact.md §9 (message-by-message) · Noise spec rev34
// (noiseprotocol.org/noise.html). Composition-per-spec, NOT novel crypto.
//
// This is the P0 crypto gate. It is validated against the OFFICIAL rweather/noise-c KAT
// vector (test/vectors/) byte-exact — handshake msg1/msg2, transport messages, and the
// handshake hash — plus a fail-closed negative suite. AEAD tag verification is done ONLY
// by node:crypto (no manual byte compares anywhere).
//
// IK pattern:
//     <- s                         (responder static, pinned by the contact-string commitment)
//     ...
//     -> e, es, s, ss              (msg1: initiator)
//     <- e, ee, se                 (msg2: responder = THE ACK)
//
// Nonce note: the AEAD nonce is 4 zero bytes || little-endian u64 counter, per the Noise
// spec and the KAT (INTERFACES' "be64" wording is imprecise; the interop-truthful encoding
// is little-endian — flagged to main, non-blocking).

'use strict'

import {
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  createPrivateKey,
  diffieHellman,
  generateKeyPairSync,
  timingSafeEqual,
} from 'node:crypto'

const PROTOCOL_NAME = 'Noise_IK_25519_ChaChaPoly_SHA256'
const DHLEN = 32
const TAGLEN = 16
const HASHLEN = 32
// Highest legal nonce is 2^64-1 (reserved); refuse to use it (Noise §11.4 / §5.1).
const MAX_NONCE = (1n << 64n) - 1n

// X25519 raw<->KeyObject DER framing (RFC 8410 fixed prefixes; verified round-trip).
const X_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex') // 12 bytes + 32 raw pub
const X_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex') // 16 bytes + 32 raw priv

/** Thrown on any handshake/transport failure. Callers MUST treat as fatal — the protocol fails closed. */
export class HandshakeError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message)
    this.name = 'HandshakeError'
  }
}

// ── primitive helpers ─────────────────────────────────────────────────────────

function sha256(...parts) {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return h.digest()
}

function hmac(key, data) {
  return createHmac('sha256', key).update(data).digest()
}

/**
 * Noise HKDF: temp_key = HMAC(ck, ikm); out1 = HMAC(tk, 0x01); out2 = HMAC(tk, out1||0x02).
 * @param {Buffer} ck chaining key
 * @param {Buffer} ikm input key material
 * @returns {[Buffer, Buffer]}
 */
function hkdf2(ck, ikm) {
  const tk = hmac(ck, ikm)
  const o1 = hmac(tk, Buffer.from([1]))
  const o2 = hmac(tk, Buffer.concat([o1, Buffer.from([2])]))
  return [o1, o2]
}

function xPubFromRaw(raw) {
  return createPublicKey({ key: Buffer.concat([X_SPKI_PREFIX, raw]), format: 'der', type: 'spki' })
}
function xPrivFromRaw(raw) {
  return createPrivateKey({ key: Buffer.concat([X_PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' })
}
function rawXPub(keyObject) {
  return Buffer.from(keyObject.export({ type: 'spki', format: 'der' }).subarray(-32))
}

/**
 * X25519 Diffie-Hellman on raw 32-byte keys. Rejects a low-order/all-zero shared secret
 * (contributory-behaviour hardening — a substituted low-order point yields all-zero DH).
 * @param {Buffer} privRaw 32 raw private bytes
 * @param {Buffer} pubRaw 32 raw public bytes
 * @returns {Buffer} 32-byte shared secret
 */
function dh(privRaw, pubRaw) {
  let shared
  try {
    shared = diffieHellman({ privateKey: xPrivFromRaw(privRaw), publicKey: xPubFromRaw(pubRaw) })
  } catch (err) {
    throw new HandshakeError('X25519 DH failed: ' + err.message)
  }
  // all-zero shared secret => low-order point => reject (fail closed).
  if (timingSafeEqual(shared, Buffer.alloc(DHLEN))) {
    throw new HandshakeError('X25519 DH produced a zero shared secret (low-order point)')
  }
  return shared
}

/** Derive an ephemeral X25519 keypair, or wrap an injected raw private key (test/KAT only). */
function genEphemeral(rawPriv) {
  if (rawPriv) {
    const priv = xPrivFromRaw(rawPriv)
    return { priv: Buffer.from(rawPriv), pub: rawXPub(createPublicKey(priv)) }
  }
  const { publicKey, privateKey } = generateKeyPairSync('x25519')
  return {
    priv: Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32)),
    pub: rawXPub(publicKey),
  }
}

// ── CipherState (ChaCha20-Poly1305, Noise nonce discipline) ────────────────────

class CipherState {
  /** @param {Buffer|null} key 32-byte key, or null (no key set) */
  constructor(key = null) {
    this.k = key
    this.n = 0n
  }

  get hasKey() {
    return this.k !== null
  }

  _nonce() {
    if (this.n >= MAX_NONCE) throw new HandshakeError('nonce counter exhausted')
    const nonce = Buffer.alloc(12) // 4 zero bytes || u64 LE counter
    nonce.writeBigUInt64LE(this.n, 4)
    return nonce
  }

  /**
   * @param {Buffer} ad additional data
   * @param {Buffer} plaintext
   * @returns {Buffer} ciphertext || 16-byte tag (or plaintext unchanged if no key)
   */
  encryptWithAd(ad, plaintext) {
    if (!this.hasKey) return plaintext
    const nonce = this._nonce()
    const c = createCipheriv('chacha20-poly1305', this.k, nonce, { authTagLength: TAGLEN })
    if (ad && ad.length) c.setAAD(ad, { plaintextLength: plaintext.length })
    const body = Buffer.concat([c.update(plaintext), c.final()])
    const out = Buffer.concat([body, c.getAuthTag()])
    this.n++
    return out
  }

  /**
   * @param {Buffer} ad additional data
   * @param {Buffer} ciphertext ciphertext || 16-byte tag
   * @returns {Buffer} plaintext (throws HandshakeError on tag failure — fail closed)
   */
  decryptWithAd(ad, ciphertext) {
    if (!this.hasKey) return ciphertext
    if (ciphertext.length < TAGLEN) throw new HandshakeError('ciphertext shorter than auth tag')
    const nonce = this._nonce()
    const body = ciphertext.subarray(0, ciphertext.length - TAGLEN)
    const tag = ciphertext.subarray(ciphertext.length - TAGLEN)
    const d = createDecipheriv('chacha20-poly1305', this.k, nonce, { authTagLength: TAGLEN })
    if (ad && ad.length) d.setAAD(ad, { plaintextLength: body.length })
    d.setAuthTag(tag)
    let plaintext
    try {
      plaintext = Buffer.concat([d.update(body), d.final()]) // final() throws on bad tag
    } catch {
      throw new HandshakeError('AEAD authentication failed')
    }
    this.n++ // advance only on success (Noise increments after a valid op)
    return plaintext
  }
}

/** Public transport-cipher wrapper returned by split(). */
class TransportCipher {
  /** @param {CipherState} cs */
  constructor(cs) {
    this._cs = cs
  }
  /** @param {Buffer} plaintext @param {Buffer|null} [ad] @returns {Buffer} */
  encrypt(plaintext, ad = null) {
    return this._cs.encryptWithAd(ad || Buffer.alloc(0), plaintext)
  }
  /** @param {Buffer} ciphertext @param {Buffer|null} [ad] @returns {Buffer} */
  decrypt(ciphertext, ad = null) {
    return this._cs.decryptWithAd(ad || Buffer.alloc(0), ciphertext)
  }
}

// ── HandshakeState (IK) ────────────────────────────────────────────────────────

const PATTERNS = [
  ['e', 'es', 's', 'ss'], // msg1: initiator
  ['e', 'ee', 'se'], // msg2: responder (THE ACK)
]

class HandshakeState {
  constructor(role, opts) {
    this.initiator = role === 'initiator'
    if (!opts || !opts.localX || !Buffer.isBuffer(opts.localX.pub) || !Buffer.isBuffer(opts.localX.priv)) {
      throw new HandshakeError('localX {pub,priv} Buffers required')
    }
    if (opts.localX.pub.length !== DHLEN || opts.localX.priv.length !== DHLEN) {
      throw new HandshakeError('localX keys must be 32 raw bytes')
    }
    this.s = { pub: Buffer.from(opts.localX.pub), priv: Buffer.from(opts.localX.priv) }
    this.e = null
    this.re = null
    if (this.initiator) {
      if (!Buffer.isBuffer(opts.remoteXPub) || opts.remoteXPub.length !== DHLEN) {
        throw new HandshakeError('initiator requires 32-byte remoteXPub')
      }
      this.rs = Buffer.from(opts.remoteXPub)
    } else {
      this.rs = null
    }
    this._ephemeral = opts._ephemeral || null // raw priv, KAT/test injection only

    // InitializeSymmetric: protocol name is exactly HASHLEN bytes → h = name (no pad, no hash).
    const name = Buffer.from(PROTOCOL_NAME, 'ascii')
    if (name.length !== HASHLEN) throw new HandshakeError('protocol name length assumption broken')
    this.h = Buffer.from(name)
    this.ck = Buffer.from(name)
    this.cs = new CipherState(null)

    // MixHash(prologue) then the pre-message (<- s: responder static, in initiator's key order).
    this._mixHash(opts.prologue ? Buffer.from(opts.prologue) : Buffer.alloc(0))
    this._mixHash(this.initiator ? this.rs : this.s.pub)

    this.msgIndex = 0
    this.complete = false
  }

  // ── symmetric-state ops ──
  _mixKey(ikm) {
    const [ck, tempK] = hkdf2(this.ck, ikm)
    this.ck = ck
    this.cs = new CipherState(tempK) // InitializeKey → n=0
  }
  _mixHash(data) {
    this.h = sha256(this.h, data)
  }
  _encryptAndHash(plaintext) {
    const ct = this.cs.encryptWithAd(this.h, plaintext)
    this._mixHash(ct)
    return ct
  }
  _decryptAndHash(ciphertext) {
    const pt = this.cs.decryptWithAd(this.h, ciphertext)
    this._mixHash(ciphertext)
    return pt
  }

  // ── DH token resolution (first letter = initiator key, second = responder key) ──
  _dhToken(token) {
    switch (token) {
      case 'ee':
        return dh(this.e.priv, this.re)
      case 'es':
        return this.initiator ? dh(this.e.priv, this.rs) : dh(this.s.priv, this.re)
      case 'se':
        return this.initiator ? dh(this.s.priv, this.re) : dh(this.e.priv, this.rs)
      case 'ss':
        return dh(this.s.priv, this.rs)
      default:
        throw new HandshakeError('unknown DH token ' + token)
    }
  }

  _isWriteTurn() {
    // even message index = initiator writes; odd = responder writes.
    return this.msgIndex % 2 === 0 ? this.initiator : !this.initiator
  }

  /**
   * @param {Buffer} [payload]
   * @returns {Buffer} the handshake message to send on the wire
   */
  writeMessage(payload = Buffer.alloc(0)) {
    if (this.complete) throw new HandshakeError('handshake already complete')
    if (!this._isWriteTurn()) throw new HandshakeError('not this party’s turn to write')
    const out = []
    for (const token of PATTERNS[this.msgIndex]) {
      if (token === 'e') {
        this.e = genEphemeral(this._ephemeral)
        out.push(this.e.pub)
        this._mixHash(this.e.pub)
      } else if (token === 's') {
        out.push(this._encryptAndHash(this.s.pub))
      } else {
        this._mixKey(this._dhToken(token))
      }
    }
    out.push(this._encryptAndHash(Buffer.isBuffer(payload) ? payload : Buffer.from(payload)))
    this._advance()
    return Buffer.concat(out)
  }

  /**
   * @param {Buffer} message the received handshake message
   * @returns {Buffer} the decrypted payload (throws HandshakeError; fails closed)
   */
  readMessage(message) {
    if (this.complete) throw new HandshakeError('handshake already complete')
    if (this._isWriteTurn()) throw new HandshakeError('not this party’s turn to read')
    if (!Buffer.isBuffer(message)) throw new HandshakeError('message must be a Buffer')
    let off = 0
    const take = (n) => {
      if (off + n > message.length) throw new HandshakeError('handshake message truncated')
      const slice = message.subarray(off, off + n)
      off += n
      return slice
    }
    for (const token of PATTERNS[this.msgIndex]) {
      if (token === 'e') {
        this.re = Buffer.from(take(DHLEN))
        this._mixHash(this.re)
      } else if (token === 's') {
        const n = this.cs.hasKey ? DHLEN + TAGLEN : DHLEN
        this.rs = this._decryptAndHash(Buffer.from(take(n)))
      } else {
        this._mixKey(this._dhToken(token))
      }
    }
    const payload = this._decryptAndHash(message.subarray(off))
    this._advance()
    return payload
  }

  _advance() {
    this.msgIndex++
    if (this.msgIndex >= PATTERNS.length) this.complete = true
  }

  /**
   * @returns {{tx: TransportCipher, rx: TransportCipher, handshakeHash: Buffer}}
   */
  split() {
    if (!this.complete) throw new HandshakeError('cannot split before handshake completes')
    const [t1, t2] = hkdf2(this.ck, Buffer.alloc(0))
    const c1 = new CipherState(t1) // initiator -> responder
    const c2 = new CipherState(t2) // responder -> initiator
    return {
      tx: new TransportCipher(this.initiator ? c1 : c2),
      rx: new TransportCipher(this.initiator ? c2 : c1),
      handshakeHash: Buffer.from(this.h),
    }
  }
}

/**
 * Create an IK initiator handshake. The initiator knows (pins) the responder's static X25519 key.
 * @param {{localX:{pub:Buffer,priv:Buffer}, remoteXPub:Buffer, prologue?:Buffer, _ephemeral?:Buffer}} opts
 * @returns {HandshakeState}
 */
export function initiator(opts) {
  return new HandshakeState('initiator', opts)
}

/**
 * Create an IK responder handshake. Learns the initiator's static key during msg1 (TOFU pin).
 * @param {{localX:{pub:Buffer,priv:Buffer}, prologue?:Buffer, _ephemeral?:Buffer}} opts
 * @returns {HandshakeState}
 */
export function responder(opts) {
  return new HandshakeState('responder', opts)
}

export { HandshakeState, CipherState }
