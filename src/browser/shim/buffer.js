// src/browser/shim/buffer.js — the smallest Buffer that runs OUR code in a browser.
//
// WHY THIS EXISTS: the browser client must speak byte-identical Noise to the TUI. The safest
// way to guarantee that is not to re-implement the protocol for the browser — it is to run
// THE SAME SOURCE (src/key.js, src/noise.js, src/wire.js, src/node.js, src/group.js). Those
// files use Node's Buffer. Browsers don't have one. So: a shim, not a fork.
//
// Scope is deliberately tiny — exactly the surface those five modules touch, nothing more
// (5 statics + 7 instance methods, verified by grep before writing this). Buffer extends
// Uint8Array in Node, so we do the same: every Buffer we hand back IS a Uint8Array, which is
// what WebSocket.send / RTCDataChannel.send / WebCrypto all want anyway. Zero copies added.
//
// ponytail: not a Buffer polyfill. No base64, no readInt16LE, no Buffer.byteLength. If a
// future module needs more, add the one method it needs — resist growing this into feross/buffer.

const enc = new TextEncoder()
const dec = new TextDecoder()

const HEX = []
for (let i = 0; i < 256; i++) HEX[i] = i.toString(16).padStart(2, '0')

// Cross-instance brand. isBuffer() must NOT be `instanceof`: if this module is ever loaded via two
// URLs (e.g. the import-map specifier AND a relative path), instanceof gives FALSE for a valid
// buffer from the other instance — and src/noise.js / src/key.js gate their inputs on isBuffer, so
// the handshake would throw ("localX {pub,priv} Buffers required") on a perfectly good buffer.
// A Symbol.for brand lives in the GLOBAL symbol registry, so it is identical across instances —
// isBuffer then works no matter how many copies of this module exist. (Reported by browser-build,
// who hit it in group.js.) A plain Uint8Array has no brand, so it still returns false (matches Node).
const BRAND = Symbol.for('p2p.shim.buffer.v1')

/** Node's Buffer, minus everything we don't use. Instances are real Uint8Arrays. */
export class Buffer extends Uint8Array {
  /** brand read off the prototype — every instance (of any loaded copy) reports true */
  get [BRAND]() {
    return true
  }

  // ── statics (the 5 our code calls) ──

  /** @param {number} n @returns {Buffer} zero-filled */
  static alloc(n) {
    return new Buffer(n)
  }

  /** @param {number} n @returns {Buffer} (we zero-fill anyway — "unsafe" buys nothing here) */
  static allocUnsafe(n) {
    return new Buffer(n)
  }

  /**
   * @param {ArrayBuffer|ArrayBufferView|Array<number>|string} src
   * @param {string} [encoding] 'utf8' | 'ascii' | 'hex' | 'base64' (only what we use)
   */
  static from(src, encoding) {
    if (typeof src === 'string') {
      if (encoding === 'hex') {
        if (src.length % 2) throw new TypeError('hex string must have an even length')
        const out = new Buffer(src.length / 2)
        for (let i = 0; i < out.length; i++) {
          const byte = parseInt(src.substr(i * 2, 2), 16)
          if (Number.isNaN(byte)) throw new TypeError('invalid hex string')
          out[i] = byte
        }
        return out
      }
      if (encoding === 'base64' || encoding === 'base64url') {
        // base64url (key.js reads JWK x/d fields): restore the standard alphabet + padding
        let b64 = src.replace(/-/g, '+').replace(/_/g, '/')
        while (b64.length % 4) b64 += '='
        const bin = atob(b64)
        const out = new Buffer(bin.length)
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
        return out
      }
      // utf8 (default) and ascii — TextEncoder is utf8; ascii input is a subset, so this is exact
      const bytes = enc.encode(src)
      const out = new Buffer(bytes.length)
      out.set(bytes)
      return out
    }
    if (src instanceof ArrayBuffer) return new Buffer(src.slice(0))
    if (ArrayBuffer.isView(src)) {
      // COPY (Node's Buffer.from(view) copies too — aliasing here would be a real bug source)
      const view = new Uint8Array(src.buffer, src.byteOffset, src.byteLength)
      const out = new Buffer(view.length)
      out.set(view)
      return out
    }
    if (Array.isArray(src)) return new Buffer(Uint8Array.from(src))
    throw new TypeError('Buffer.from: unsupported source')
  }

  /** @param {ArrayBufferView[]} list @param {number} [total] */
  static concat(list, total) {
    let len = total
    if (len === undefined) {
      len = 0
      for (const b of list) len += b.length
    }
    const out = new Buffer(len)
    let off = 0
    for (const b of list) {
      if (off + b.length > len) {
        out.set(new Uint8Array(b.buffer, b.byteOffset, len - off), off)
        off = len
        break
      }
      out.set(b, off)
      off += b.length
    }
    return out
  }

  /**
   * @param {any} b — true only for OUR Buffer (matches Node: a bare Uint8Array is NOT a Buffer).
   * Brand-based, not instanceof, so it survives multiple module instances (see BRAND above).
   */
  static isBuffer(b) {
    return !!(b && b[BRAND] === true)
  }

  // ── instance methods (the 7 our code calls) ──

  /** subarray must keep returning a Buffer, not a plain Uint8Array (code calls .copy/.equals on it) */
  subarray(start, end) {
    const view = super.subarray(start, end)
    return new Buffer(view.buffer, view.byteOffset, view.length)
  }

  slice(start, end) {
    return this.subarray(start, end)
  }

  /** Node's copy(target, targetStart, sourceStart, sourceEnd) @returns {number} bytes copied */
  copy(target, targetStart = 0, sourceStart = 0, sourceEnd = this.length) {
    const src = super.subarray(sourceStart, sourceEnd)
    target.set(src, targetStart)
    return src.length
  }

  equals(other) {
    if (this.length !== other.length) return false
    for (let i = 0; i < this.length; i++) if (this[i] !== other[i]) return false
    return true
  }

  toString(encoding = 'utf8') {
    if (encoding === 'hex') {
      let s = ''
      for (let i = 0; i < this.length; i++) s += HEX[this[i]]
      return s
    }
    if (encoding === 'base64' || encoding === 'base64url') {
      let bin = ''
      for (let i = 0; i < this.length; i++) bin += String.fromCharCode(this[i])
      const b64 = btoa(bin)
      return encoding === 'base64url' ? b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : b64
    }
    return dec.decode(this)
  }

  readUInt32BE(off = 0) {
    return new DataView(this.buffer, this.byteOffset, this.byteLength).getUint32(off, false)
  }

  writeUInt32BE(value, off = 0) {
    new DataView(this.buffer, this.byteOffset, this.byteLength).setUint32(off, value >>> 0, false)
    return off + 4
  }

  writeBigUInt64LE(value, off = 0) {
    new DataView(this.buffer, this.byteOffset, this.byteLength).setBigUint64(off, BigInt(value), true)
    return off + 8
  }

  readBigUInt64LE(off = 0) {
    return new DataView(this.buffer, this.byteOffset, this.byteLength).getBigUint64(off, true)
  }
}

// The shared modules reference a bare global `Buffer` (and noise.js does so at MODULE TOP LEVEL,
// for its DER prefixes) — so this must be installed BEFORE they are imported. The browser entry
// point imports this file first, then dynamic-import()s everything else. See ../p2p.js.
if (typeof globalThis.Buffer === 'undefined') globalThis.Buffer = Buffer

export default Buffer
