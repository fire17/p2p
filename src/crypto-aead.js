// Use the runtime's native ChaCha20-Poly1305 where available. Bun currently omits
// it, so reuse the browser's existing noble adapter for that cipher only. This
// changes neither the Noise state machine nor its keys, nonces, or wire bytes.
// The browser import map already supplies that same adapter as node:crypto.
import * as native from 'node:crypto'
import {
  createCipheriv as portableCipher,
  createDecipheriv as portableDecipher,
} from './browser/shim/node-crypto.js'

const hasChaCha = !native.getCiphers || native.getCiphers().includes('chacha20-poly1305')

export const createCipheriv = hasChaCha ? native.createCipheriv : portableCipher
export const createDecipheriv = hasChaCha ? native.createDecipheriv : portableDecipher
