// src/rendezvous/mdns.js — LAN fast-path rendezvous over multicast DNS (RFC 6762-shaped).
// Zero deps (node:dgram only). Contract: docs/INTERFACES.md §rendezvous. Role: store/lookup
// (DESIGN D6). Service `_p2p._tcp.local`; the derived rid + full candidate blob ride a TXT record.
//
// Uniform channel surface:  announce(rid, info, opts) / lookup(rid, opts) / close()
//   rid  : Buffer (32 bytes for mdns — deriveRid len=32)
//   info : full candidate blob { v, candidates:[{proto,ip,port,kind}], ts? } (DESIGN D6: mdns
//          carries the FULL blob, unlike dht which stores only a port)
//   lookup(rid) -> async iterable of { candidates[], channel:'mdns', ts }
//
// The socket is injectable (`opts.socketFactory`) so tests drive announce↔lookup over an
// in-memory bus with no real network.

import dgram from 'node:dgram'

const SERVICE = '_p2p._tcp.local'
const MCAST_ADDR = '224.0.0.251'
const MCAST_PORT = 5353
const TYPE_PTR = 12
const TYPE_TXT = 16
const CLASS_IN = 1

// ── minimal DNS wire codec ────────────────────────────────────────────────────

/** @param {string} name @returns {Buffer} */
function encodeName(name) {
  const parts = []
  for (const label of name.split('.')) {
    const b = Buffer.from(label, 'ascii')
    if (b.length > 63) throw new RangeError('DNS label too long')
    parts.push(Buffer.from([b.length]), b)
  }
  parts.push(Buffer.from([0]))
  return Buffer.concat(parts)
}

/**
 * Read a DNS name (handles compression pointers).
 * @param {Buffer} buf @param {number} off
 * @returns {{name:string, off:number}} off = position after the name in the ORIGINAL stream
 */
function readName(buf, off) {
  const labels = []
  let jumped = false
  let next = off
  let guard = 0
  while (true) {
    if (off >= buf.length || guard++ > 128) throw new RangeError('malformed DNS name')
    const len = buf[off]
    if (len === 0) {
      off += 1
      break
    }
    if ((len & 0xc0) === 0xc0) {
      const ptr = ((len & 0x3f) << 8) | buf[off + 1]
      if (!jumped) next = off + 2
      off = ptr
      jumped = true
      continue
    }
    labels.push(buf.toString('ascii', off + 1, off + 1 + len))
    off += 1 + len
  }
  return { name: labels.join('.'), off: jumped ? next : off }
}

/** @param {string} name @param {number} qtype @returns {Buffer} an mDNS query packet */
function encodeQuery(name, qtype) {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(1, 4) // qdcount
  const q = encodeName(name)
  const tail = Buffer.alloc(4)
  tail.writeUInt16BE(qtype, 0)
  tail.writeUInt16BE(CLASS_IN, 2)
  return Buffer.concat([header, q, tail])
}

/** @param {Array<{name:string,type:number,ttl:number,strings:string[]}>} answers @returns {Buffer} */
function encodeResponse(answers) {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(0x8400, 2) // QR=1, AA=1
  header.writeUInt16BE(answers.length, 6) // ancount
  const recs = answers.map((a) => {
    const name = encodeName(a.name)
    const meta = Buffer.alloc(8)
    meta.writeUInt16BE(a.type, 0)
    meta.writeUInt16BE(CLASS_IN, 2)
    meta.writeUInt32BE(a.ttl, 4)
    // rdata: for TXT, a sequence of length-prefixed strings
    const strs = a.strings.map((s) => {
      const b = Buffer.from(s, 'utf8')
      if (b.length > 255) throw new RangeError('TXT string too long')
      return Buffer.concat([Buffer.from([b.length]), b])
    })
    const rdata = Buffer.concat(strs)
    const rdlen = Buffer.alloc(2)
    rdlen.writeUInt16BE(rdata.length, 0)
    return Buffer.concat([name, meta, rdlen, rdata])
  })
  return Buffer.concat([header, ...recs])
}

/**
 * Decode a DNS packet into the pieces we need (questions + TXT answers).
 * @param {Buffer} buf
 * @returns {{questions:{name:string,qtype:number}[], txt:{name:string,strings:string[]}[]}}
 */
function decode(buf) {
  const questions = []
  const txt = []
  if (buf.length < 12) throw new RangeError('short DNS packet')
  const qd = buf.readUInt16BE(4)
  const an = buf.readUInt16BE(6)
  let off = 12
  for (let i = 0; i < qd; i++) {
    const r = readName(buf, off)
    off = r.off
    const qtype = buf.readUInt16BE(off)
    questions.push({ name: r.name, qtype })
    off += 4 // qtype + qclass
  }
  for (let i = 0; i < an; i++) {
    const r = readName(buf, off)
    off = r.off
    const type = buf.readUInt16BE(off)
    const rdlen = buf.readUInt16BE(off + 8)
    const rdStart = off + 10
    if (type === TYPE_TXT) {
      const strings = []
      let p = rdStart
      while (p < rdStart + rdlen) {
        const l = buf[p]
        strings.push(buf.toString('utf8', p + 1, p + 1 + l))
        p += 1 + l
      }
      txt.push({ name: r.name, strings })
    }
    off = rdStart + rdlen
  }
  return { questions, txt }
}

// ── blob codec seam (metadata-privacy §4.1/§4.3 — the SAME seam createTracker already has) ──────
// The TXT record carries OPAQUE BYTES. The default codec is plaintext JSON — byte-identical to
// v0.1.0 (reusable-S mode, where the candidates are public by construction anyway). INVITE mode
// passes src/invite.js's `inv.codec`, which AEAD-seals the candidate blob under k_ip=HKDF(K_inv,"ip")
// and pads it to a FIXED length, so a passive LAN listener sees only fixed-size ciphertext.
//
// MDNS-1 (wargame-findings): until this seam existed, invite-mode mDNS broadcast the FULL plaintext
// candidate blob — IP and port in the clear — to every device on the LAN, while the tracker and DHT
// surfaces for the same invite were already sealed. That is exactly the "IP never plaintext on any
// channel" rule, broken on the one channel nobody was watching.
//
// The rid is UNCHANGED (it is already rid_inv in invite mode — only a K_inv holder can compute it),
// so discovery reliability is untouched: the same peers find the same record on the same query. Only
// the PAYLOAD goes opaque.
const JSON_CODEC = {
  sealed: false,
  seal: (blob) => Buffer.from(JSON.stringify(blob), 'utf8'),
  open: (bytes) => { try { return JSON.parse(bytes.toString('utf8')) } catch { return null } },
}

// ── TXT payload: string[0]="rid=<hex>", remaining strings joined = base64(codec-sealed blob) ──

/** @param {Buffer} rid @param {object} blob @param {object} [codec] @returns {string[]} */
function encodeTxt(rid, blob, codec = JSON_CODEC) {
  const b64 = Buffer.from(codec.seal(blob, rid)).toString('base64')
  const chunks = []
  for (let i = 0; i < b64.length; i += 200) chunks.push(b64.slice(i, i + 200))
  return ['rid=' + rid.toString('hex'), ...chunks]
}

/**
 * @param {string[]} strings @param {object} [codec]
 * @returns {{ridHex:string, blob:object}|null} null on a foreign rid, a wrong key, tamper, or corrupt
 *   bytes — a record we cannot open is simply ignored (same rule as the tracker's codec seam).
 */
function decodeTxt(strings, codec = JSON_CODEC) {
  if (!strings.length || !strings[0].startsWith('rid=')) return null
  const ridHex = strings[0].slice(4)
  let bytes
  try { bytes = Buffer.from(strings.slice(1).join(''), 'base64') } catch { return null }
  // The rid is carried in the clear (it must be — it is the lookup key, and in invite mode it is
  // itself derived from K_inv), so it is available as the AEAD's associated data on both sides.
  const blob = codec.open(bytes, Buffer.from(ridHex, 'hex'))
  if (!blob) return null
  return { ridHex, blob }
}

// ── channel instance ──────────────────────────────────────────────────────────

/**
 * Create an mDNS rendezvous channel.
 * @param {object} [opts]
 * @param {() => number} [opts.now] clock (ms); injectable for tests
 * @param {(type:string, o:object)=>import('node:dgram').Socket} [opts.socketFactory] dgram.createSocket
 * @param {string} [opts.mcastAddr]
 * @param {number} [opts.port]
 * @param {number} [opts.ttl] TXT TTL seconds
 * @param {{sealed:boolean, seal:Function, open:Function}} [opts.codec] blob codec. Default = plaintext
 *   JSON (v0.1.0 wire, reusable-S mode — byte-identical). Pass an src/invite.js `inv.codec` for INVITE
 *   MODE: the candidate blob is AEAD-sealed under k_ip and padded to a fixed length, so a passive LAN
 *   listener reads neither the IP, nor the port, nor the size of the candidate set (MDNS-1).
 * @returns {{name:'mdns', ridLen:32, announce:Function, lookup:Function, close:Function}}
 */
export function createMdns(opts = {}) {
  const now = opts.now || (() => Date.now())
  const codec = opts.codec || JSON_CODEC        // invite mode passes src/invite.js's inv.codec (sealed)
  // NOTE: dgram.createSocket(type, cb) treats a 2nd arg as a callback — passing options there
  // silently DROPS them (reuseAddr lost → EADDRINUSE on the 2nd same-host bind). Options must go
  // in a single object with a `type` field. (Mock factories in tests ignore the args entirely.)
  const mkSocket = opts.socketFactory || ((type, o) => dgram.createSocket({ type, ...o }))
  const mcastAddr = opts.mcastAddr || MCAST_ADDR
  const port = opts.port || MCAST_PORT
  const ttl = opts.ttl || 120

  /** @type {Map<string,{rid:Buffer,blob:object}>} keyed by rid hex */
  const announcements = new Map()
  /** @type {Set<(msg:{ridHex:string,blob:object})=>void>} */
  const listeners = new Set()

  // reuseAddr lets multiple processes on ONE host bind 5353 and each receive the group's
  // traffic (the two-terminal-on-one-machine case). NOT reusePort — it's ENOTSUP for a
  // multicast bind on macOS and aborts the bind entirely.
  const sock = mkSocket('udp4', { reuseAddr: true })
  let ready = false
  const pending = []
  sock.on('error', () => {}) // ponytail: LAN best-effort; a dead socket just yields no peers

  sock.on('message', (buf) => {
    let pkt
    try {
      pkt = decode(buf)
    } catch {
      return
    }
    // answer queries for our service with every active announcement
    if (pkt.questions.some((q) => q.name === SERVICE) && announcements.size) {
      respond()
    }
    // feed TXT answers to active lookups. In invite mode this OPENS the sealed blob with our k_ip:
    // a record we cannot open (someone else's invite, a foreign p2p peer, tamper) yields null and is
    // simply dropped here — the same fail-closed rule the tracker's codec seam follows.
    for (const t of pkt.txt) {
      const dec = decodeTxt(t.strings, codec)
      if (dec) for (const cb of listeners) cb(dec)
    }
  })

  try {
    sock.bind(port, () => {
      try {
        sock.addMembership(mcastAddr)
        sock.setMulticastTTL(ttl)
        // CRITICAL for same-host discovery: IP_MULTICAST_LOOP governs whether our multicast
        // reaches OTHER sockets on this host (a second process, and ourselves). Without it,
        // a listener's answers never reach a dialer on the same machine → "no candidates".
        sock.setMulticastLoopback(true)
      } catch {
        /* mock / restricted env */
      }
      ready = true
      for (const fn of pending.splice(0)) fn()
    })
  } catch {
    ready = true // mock socket without real bind
  }

  const whenReady = (fn) => (ready ? fn() : pending.push(fn))
  const sendMcast = (buf) => whenReady(() => sock.send(buf, port, mcastAddr))

  function respond() {
    const answers = [...announcements.values()].map(({ rid, blob }) => ({
      name: SERVICE,
      type: TYPE_TXT,
      ttl,
      strings: encodeTxt(rid, blob, codec),
    }))
    if (answers.length) sendMcast(encodeResponse(answers))
  }

  /**
   * Announce a candidate blob under a rid. Idempotent per rid (re-announce updates the blob).
   * @param {Buffer} rid @param {object} info full candidate blob
   */
  function announce(rid, info) {
    if (!Buffer.isBuffer(rid)) throw new TypeError('rid must be a Buffer')
    const blob = { v: 1, ts: now(), ...info }
    announcements.set(rid.toString('hex'), { rid, blob })
    respond() // gratuitous announce so live lookups get us without re-querying
  }

  /**
   * Look up peers for a rid. Multicasts a query, then yields matching TXT answers as they arrive.
   * @param {Buffer} rid
   * @param {object} [lopts] @param {number} [lopts.timeout=1500] @param {AbortSignal} [lopts.signal]
   * @returns {AsyncIterable<{candidates:object[], channel:'mdns', ts:number}>}
   */
  async function* lookup(rid, lopts = {}) {
    if (!Buffer.isBuffer(rid)) throw new TypeError('rid must be a Buffer')
    const want = rid.toString('hex')
    const timeout = lopts.timeout ?? 1500
    const queue = []
    let wake
    const seen = new Set()
    const onMsg = ({ ridHex, blob }) => {
      if (ridHex !== want) return
      const key = JSON.stringify(blob.candidates || [])
      if (seen.has(key)) return
      seen.add(key)
      queue.push({ candidates: blob.candidates || [], channel: 'mdns', ts: blob.ts || now() })
      if (wake) wake()
    }
    listeners.add(onMsg)
    // First multicast can be missed (join races, buffer drops), so retransmit the query a few
    // times. Announcers answer every query for our service, so a late/dropped first query still
    // gets a reply on a retry.
    const query = encodeQuery(SERVICE, TYPE_PTR)
    sendMcast(query)
    const retries = [250, 750].map((d) => setTimeout(() => sendMcast(query), d))
    let done = false
    // NOT unref'd: this timer is the stream terminator; unref would let the loop exit before it fires
    const timer = setTimeout(() => {
      done = true
      if (wake) wake()
    }, timeout)
    const onAbort = () => {
      done = true
      if (wake) wake()
    }
    lopts.signal?.addEventListener('abort', onAbort, { once: true })
    try {
      while (!done || queue.length) {
        if (queue.length) {
          yield queue.shift()
          continue
        }
        if (done) break
        await new Promise((r) => (wake = r))
      }
    } finally {
      clearTimeout(timer)
      for (const r of retries) clearTimeout(r)
      listeners.delete(onMsg)
      lopts.signal?.removeEventListener('abort', onAbort)
    }
  }

  function close() {
    announcements.clear()
    listeners.clear()
    try {
      sock.close()
    } catch {
      /* already closed */
    }
  }

  return { name: 'mdns', ridLen: 32, announce, lookup, close }
}

// exported for unit tests
export const _internals = { encodeName, readName, encodeQuery, encodeResponse, decode, encodeTxt, decodeTxt, SERVICE }
