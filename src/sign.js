// src/sign.js — Ed25519 detached signatures over the RAW 32-byte keys key.js already produces.
//
// Why a file of its own: the pairwise Noise link authenticates the CHANNEL, but a group message
// fanned out to n members needs to authenticate its AUTHOR to every recipient — including one who
// received it RELAYED through a third member. A shared group key cannot do that (any member could
// forge any other member's messages); a per-sender signature can. See group.js §sender keys and
// research/browser-client.md §7.3(b).
//
// Same RFC 8410 DER framing trick as noise.js:44-45 — node:crypto wants DER, we hold raw scalars.
// Zero deps.
//
// BROWSER NOTE: this imports `sign`/`verify` from node:crypto, which the browser shim
// (src/browser/shim/node-crypto.js) does not export yet. Groups in the browser need two ~5-line
// additions there (noble's ed25519.sign / ed25519.verify). Flagged, not silently assumed.

import { sign as nodeSign, verify as nodeVerify, createPrivateKey, createPublicKey } from 'node:crypto'

const ED_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex') // + 32 raw priv
const ED_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex') // + 32 raw pub

const privKey = (raw32) => createPrivateKey({ key: Buffer.concat([ED_PKCS8_PREFIX, raw32]), format: 'der', type: 'pkcs8' })
const pubKey = (raw32) => createPublicKey({ key: Buffer.concat([ED_SPKI_PREFIX, raw32]), format: 'der', type: 'spki' })

/**
 * @param {Buffer} edPriv 32 raw bytes (identity.edPriv)
 * @param {Buffer} msg
 * @returns {Buffer} 64-byte detached signature
 */
export function signEd(edPriv, msg) {
  return nodeSign(null, msg, privKey(edPriv))
}

/**
 * Verify a detached signature. Returns false (never throws) on any malformed input — callers are
 * gates, and a gate must fail CLOSED, not explode.
 * @param {Buffer} edPub 32 raw bytes
 * @param {Buffer} msg
 * @param {Buffer} sig 64 bytes
 * @returns {boolean}
 */
export function verifyEd(edPub, msg, sig) {
  try {
    if (!Buffer.isBuffer(edPub) || edPub.length !== 32) return false
    if (!Buffer.isBuffer(sig) || sig.length !== 64) return false
    return nodeVerify(null, msg, pubKey(edPub), sig)
  } catch {
    return false
  }
}

export default { signEd, verifyEd }
