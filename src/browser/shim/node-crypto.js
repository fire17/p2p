// src/browser/shim/node-crypto.js — `node:crypto`, reimplemented for the browser on vendored
// noble primitives, with EXACTLY the surface our protocol code imports:
//
//   src/key.js    createHash · generateKeyPairSync · hkdfSync · timingSafeEqual
//   src/noise.js  createHash · createHmac · createCipheriv · createDecipheriv ·
//                 createPublicKey · createPrivateKey · diffieHellman · generateKeyPairSync ·
//                 timingSafeEqual
//   src/wire.js   randomBytes
//   src/node.js   randomBytes
//   src/sign.js   sign · verify · createPrivateKey · createPublicKey   (Ed25519 group-op sigs)
//   src/rendezvous/tracker.js  (default import) crypto.randomBytes
//
// THE POINT: with this shim + the Buffer shim, a browser runs src/key.js, src/noise.js,
// src/wire.js, src/node.js and src/group.js **unchanged**. The browser and the TUI therefore
// execute the SAME Noise state machine, the SAME commitment gate and the SAME framing — so
// byte-identical interop is a property of the code, not a claim we have to keep re-testing.
// (We test it anyway: test/browser-shim.test.js asserts every function below is byte-for-byte
// equal to the real node:crypto, and test/browser-noise-parity.test.js runs the official Noise
// KAT vector through src/noise.js driven by THIS shim.)
//
// Wired in via an import map (see src/browser/index.html): "node:crypto" -> this file.
//
// WHY NOT WebCrypto: SubtleCrypto is async-only. src/noise.js and src/key.js are synchronous.
// Making them async would fork the protocol code for the browser — exactly the drift risk that
// would let the browser's security quietly diverge from the TUI's. A sync shim keeps one source
// of truth. Honest cost (documented in research/browser-client.md §3.4/§8.3): pure-JS crypto is
// not formally constant-time, and static keys can't be non-extractable CryptoKeys on this path.
//
// ponytail: no cipher/curve/hash we don't use. No streams, no KeyObject formats beyond the two
// DER shapes noise.js actually round-trips.

import { sha256 } from '../vendor/hashes/sha256.js'
import { hmac as nobleHmac } from '../vendor/hashes/hmac.js'
import { hkdf as nobleHkdf } from '../vendor/hashes/hkdf.js'
import { chacha20poly1305 } from '../vendor/ciphers/chacha.js'
import { ed25519, x25519 } from '../vendor/curves/ed25519.js'
import { Buffer } from './buffer.js'

// ── RFC 8410 DER framing. These four constants are the SAME BYTES as src/noise.js:44-45 —
// that is not a coincidence, it is the interop contract. ──
const X_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex') // + 32 raw X25519 pub
const X_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex') // + 32 raw X25519 priv
const ED_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex') // + 32 raw Ed25519 pub
const ED_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex') // + 32 raw Ed25519 priv

const CURVE = {
  x25519: { impl: x25519, spki: X_SPKI_PREFIX, pkcs8: X_PKCS8_PREFIX, crv: 'X25519' },
  ed25519: { impl: ed25519, spki: ED_SPKI_PREFIX, pkcs8: ED_PKCS8_PREFIX, crv: 'Ed25519' },
}

const b64url = (bytes) => Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

/** Which curve does this DER blob carry? (read the OID, don't guess from length) */
function algFromDer(der) {
  const hex = Buffer.from(der).toString('hex')
  if (hex.includes('2b656e')) return 'x25519' // OID 1.3.101.110
  if (hex.includes('2b6570')) return 'ed25519' // OID 1.3.101.112
  throw new TypeError('unsupported key OID (only X25519 / Ed25519)')
}

/**
 * Node's KeyObject, reduced to what our code round-trips: raw 32 bytes + the two DER exports
 * + the JWK export. Nothing else.
 */
class KeyObject {
  /** @param {'public'|'private'} type @param {'x25519'|'ed25519'} alg @param {Uint8Array} raw 32 bytes */
  constructor(type, alg, raw) {
    if (raw.length !== 32) throw new TypeError(`${alg} ${type} key must be 32 raw bytes`)
    this.type = type
    this.asymmetricKeyType = alg
    this._raw = Buffer.from(raw)
  }

  export(opts = {}) {
    const c = CURVE[this.asymmetricKeyType]
    if (opts.format === 'jwk') {
      const pub = this.type === 'public' ? this._raw : c.impl.getPublicKey(this._raw)
      const jwk = { kty: 'OKP', crv: c.crv, x: b64url(pub) }
      if (this.type === 'private') jwk.d = b64url(this._raw)
      return jwk
    }
    if (opts.format !== 'der') throw new TypeError('only der/jwk export is supported')
    if (opts.type === 'spki') {
      if (this.type !== 'public') throw new TypeError('spki export needs a public key')
      return Buffer.concat([c.spki, this._raw])
    }
    if (opts.type === 'pkcs8') {
      if (this.type !== 'private') throw new TypeError('pkcs8 export needs a private key')
      return Buffer.concat([c.pkcs8, this._raw])
    }
    throw new TypeError('unsupported der export type')
  }
}

/** @param {'x25519'|'ed25519'} alg */
export function generateKeyPairSync(alg) {
  const c = CURVE[alg]
  if (!c) throw new TypeError('unsupported key type: ' + alg)
  const priv = randomBytes(32)
  const pub = c.impl.getPublicKey(priv)
  return {
    publicKey: new KeyObject('public', alg, pub),
    privateKey: new KeyObject('private', alg, priv),
  }
}

/** Accepts a DER spki blob ({key,format,type}) or a private KeyObject (→ derives its public key). */
export function createPublicKey(input) {
  if (input instanceof KeyObject) {
    if (input.type === 'public') return input
    const c = CURVE[input.asymmetricKeyType]
    return new KeyObject('public', input.asymmetricKeyType, c.impl.getPublicKey(input._raw))
  }
  const der = Buffer.from(input.key)
  const alg = algFromDer(der)
  return new KeyObject('public', alg, der.subarray(-32)) // raw key is the DER tail
}

/** Accepts a DER pkcs8 blob ({key,format,type}) or a private KeyObject. */
export function createPrivateKey(input) {
  if (input instanceof KeyObject) return input
  const der = Buffer.from(input.key)
  const alg = algFromDer(der)
  return new KeyObject('private', alg, der.subarray(-32))
}

/**
 * X25519 ECDH. Node throws on a low-order/all-zero result; noble does too — src/noise.js
 * catches that and fails the handshake CLOSED, which is exactly the intended behaviour.
 * @returns {Buffer} 32-byte shared secret
 */
export function diffieHellman({ privateKey, publicKey }) {
  if (privateKey.asymmetricKeyType !== 'x25519' || publicKey.asymmetricKeyType !== 'x25519') {
    throw new TypeError('diffieHellman: X25519 keys required')
  }
  return Buffer.from(x25519.getSharedSecret(privateKey._raw, publicKey._raw))
}

/** @param {number} n @returns {Buffer} */
export function randomBytes(n) {
  const out = Buffer.alloc(n)
  globalThis.crypto.getRandomValues(out)
  return out
}

/**
 * Ed25519 detached sign, Node's shape: sign(null, msg, privKeyObject). `algorithm` is null for
 * Ed25519 (the algo is fixed by the key). Used by src/sign.js for group-op signatures.
 * @param {null} _algorithm must be null for Ed25519
 * @param {Buffer} msg @param {KeyObject} privKey an Ed25519 private KeyObject
 * @returns {Buffer} 64-byte detached signature
 */
export function sign(_algorithm, msg, privKey) {
  if (privKey.asymmetricKeyType !== 'ed25519') throw new TypeError('sign: Ed25519 key required')
  return Buffer.from(ed25519.sign(Buffer.from(msg), privKey._raw))
}

/**
 * Ed25519 detached verify, Node's shape: verify(null, msg, pubKeyObject, sig) -> boolean.
 * @param {null} _algorithm must be null for Ed25519
 * @param {Buffer} msg @param {KeyObject} pubKey an Ed25519 public KeyObject @param {Buffer} sig 64 bytes
 * @returns {boolean}
 */
export function verify(_algorithm, msg, pubKey, sig) {
  if (pubKey.asymmetricKeyType !== 'ed25519') throw new TypeError('verify: Ed25519 key required')
  return ed25519.verify(Buffer.from(sig), Buffer.from(msg), pubKey._raw)
}

/** Streaming SHA-256 (`createHash('sha256').update(a).update(b).digest()`). */
export function createHash(algorithm) {
  if (algorithm !== 'sha256') throw new TypeError('only sha256 is supported')
  const h = sha256.create()
  return {
    update(data) {
      h.update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data)
      return this
    },
    digest() {
      return Buffer.from(h.digest())
    },
  }
}

/** HMAC-SHA256 (`createHmac('sha256', key).update(data).digest()`). */
export function createHmac(algorithm, key) {
  if (algorithm !== 'sha256') throw new TypeError('only sha256 is supported')
  const h = nobleHmac.create(sha256, typeof key === 'string' ? Buffer.from(key, 'utf8') : key)
  return {
    update(data) {
      h.update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data)
      return this
    },
    digest() {
      return Buffer.from(h.digest())
    },
  }
}

/** HKDF-SHA256, Node's argument order. Salt/info may be strings (key.js passes strings). */
export function hkdfSync(digest, ikm, salt, info, keylen) {
  if (digest !== 'sha256') throw new TypeError('only sha256 is supported')
  const asBytes = (v) => (typeof v === 'string' ? Buffer.from(v, 'utf8') : Buffer.from(v))
  // Node returns an ArrayBuffer here; key.js wraps it in Buffer.from(). Bytes are what matter.
  return Buffer.from(nobleHkdf(sha256, asBytes(ikm), asBytes(salt), asBytes(info), keylen))
}

/** Node's RangeError-on-length-mismatch semantics, constant-time on equal lengths. */
export function timingSafeEqual(a, b) {
  if (a.length !== b.length) throw new RangeError('Input buffers must have the same byte length')
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

// ── ChaCha20-Poly1305, shaped like Node's Cipheriv/Decipheriv ──
// Node's API is incremental; noble's is one-shot. We buffer, then do the single call at final().
// src/noise.js only ever does: setAAD → update(whole) → final() → getAuthTag(), so this is exact.

const TAGLEN = 16
const assertChaCha = (algorithm) => {
  if (algorithm !== 'chacha20-poly1305') throw new TypeError('only chacha20-poly1305 is supported')
}

export function createCipheriv(algorithm, key, nonce) {
  assertChaCha(algorithm)
  let aad = null
  const chunks = []
  let tag = null
  return {
    setAAD(ad) {
      aad = Buffer.from(ad)
      return this
    },
    update(pt) {
      chunks.push(Buffer.from(pt))
      return Buffer.alloc(0) // everything is emitted by final() — Node allows this
    },
    final() {
      const pt = Buffer.concat(chunks)
      const sealed = Buffer.from(chacha20poly1305(Buffer.from(key), Buffer.from(nonce), aad || undefined).encrypt(pt))
      tag = sealed.subarray(sealed.length - TAGLEN)
      return sealed.subarray(0, sealed.length - TAGLEN) // ciphertext only; the tag goes via getAuthTag()
    },
    getAuthTag() {
      if (!tag) throw new Error('getAuthTag() called before final()')
      return tag
    },
  }
}

export function createDecipheriv(algorithm, key, nonce) {
  assertChaCha(algorithm)
  let aad = null
  let tag = null
  const chunks = []
  return {
    setAAD(ad) {
      aad = Buffer.from(ad)
      return this
    },
    setAuthTag(t) {
      tag = Buffer.from(t)
      return this
    },
    update(ct) {
      chunks.push(Buffer.from(ct))
      return Buffer.alloc(0)
    },
    final() {
      if (!tag) throw new Error('setAuthTag() must be called before final()')
      const sealed = Buffer.concat([Buffer.concat(chunks), tag])
      // noble THROWS on a bad tag — which is what src/noise.js wants (it fails the handshake closed).
      return Buffer.from(chacha20poly1305(Buffer.from(key), Buffer.from(nonce), aad || undefined).decrypt(sealed))
    },
  }
}

// tracker.js does `import crypto from 'node:crypto'` and calls crypto.randomBytes.
export default {
  createHash,
  createHmac,
  createCipheriv,
  createDecipheriv,
  createPublicKey,
  createPrivateKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  verify,
  timingSafeEqual,
}
