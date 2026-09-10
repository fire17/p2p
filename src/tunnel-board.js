// src/tunnel-board.js — AGENT TUNNEL T2: an offline, file-carried rendezvous board.
//
// WHAT THIS IS. A rendezvous CHANNEL (the `{name, ridLen, announce, lookup, close}` shape that
// src/rendezvous/race.js consumes) whose carrier is a DIRECTORY instead of a tracker/DHT/mDNS
// socket. Everything above the carrier is the REAL stack: the rids are the real
// HKDF(K_inv,…)/HKDF(S,…) rids, the record is sealed with the real `inv.codec` (ChaCha20-Poly1305,
// ad = rid), and the peers that meet over it run the real Noise IKpsk2 handshake over real UDP.
// So a test built on it proves the property chain the invite design claims — locate, open,
// handshake — with ZERO packets leaving the machine and zero public infrastructure touched.
//
// WHY IT EXISTS. `p2p tunnel`'s acceptance has to run on a laptop with no LAN, no tracker and no
// DHT, deterministically, in CI and offline. mDNS needs multicast (flaky/absent in sandboxes),
// the tracker and the DHT are public infrastructure. A directory is neither: two processes that
// can see the same folder can meet.
//
// HOW IT PLUGS IN (src/node.js:267 resolveDeps). `fileRendezvousDeps(dir)` returns exactly
// `{makeRace, resolve, publishAll}` — an INCOMPLETE dep set on purpose, so resolveDeps takes its
// REAL branch (real key/noise/transport-node) and only the three rendezvous seams are ours: the
// `...inj` spread is last, so our resolve/publishAll/makeRace win, and because `resolve` and
// `publishAll` are both present the mdns/dht/tracker factories are never CALLED — `node._channels`
// is `[]` after listen(), which is the observable proof that no real channel was constructed.
// `makeRace` is the seam invite-mode DIALING needs (src/node.js:764).
//
// LOOPBACK. src/transport.js:339 candidates() skips `internal` interfaces, so 127.0.0.1 is never
// announced and a box with no external interface announces NOTHING. `{loopback:true}` publishes a
// single synthetic udp4 candidate at 127.0.0.1:<the endpoint's real udp4 port> — same socket, same
// port, deterministic address — which is what makes the acceptance independent of the LAN.
//
// CROSS-PLATFORM: node built-ins only, path.join, atomic write = tmp + rename, no fs.watch
// (unreliable on all three OSes — this polls by existence), no process.platform branches.

import { mkdirSync, writeFileSync, renameSync, readFileSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { createRace } from './rendezvous/race.js'

const DEFAULT_LOOKUP_TIMEOUT_MS = 5000
const DEFAULT_POLL_MS = 25

/** Sleep that wakes early on abort. Short (<= pollMs) and deliberately NOT unref'd: it is the
 * clock that terminates a lookup stream, same rule as tracker.js's terminating timer. */
function sleep(ms, signal) {
  return new Promise((res) => {
    if (signal?.aborted) return res()
    const t = setTimeout(done, ms)
    function done() { clearTimeout(t); signal?.removeEventListener('abort', done); res() }
    signal?.addEventListener('abort', done, { once: true })
  })
}

/** `<dir>/<ridhex>.json` — the record's whole address. @param {string} dir @param {Buffer} rid */
export function recordPath(dir, rid) {
  return join(dir, rid.toString('hex') + '.json')
}

/**
 * One rendezvous channel carried by a directory.
 *
 * The record on disk is `{v:1, sealed:"<base64>"}` in invite mode (the bytes are exactly
 * `inv.codec.seal({v,ts,candidates}, rid)` — the same call tracker.js makes) and
 * `{v:1, blob:{v,ts,candidates}}` in reusable-S mode (plaintext, matching the v0.1.0 wire).
 *
 * @param {string} dir  the board directory (created on demand)
 * @param {{codec?:{seal:Function,open:Function}}|null} [inv] an src/invite.js invite context
 * @param {object} [opts] {name='tracker', ridLen=20, now, lookupTimeoutMs, pollMs}
 * @returns {{name:string, ridLen:number, announce:Function, lookup:Function, close:Function}}
 */
export function fileChannel(dir, inv = null, opts = {}) {
  const name = opts.name || 'tracker'          // 'tracker' => race.js weight 1 (an internet-class
  const ridLen = opts.ridLen ?? 20             // channel, not a LAN fast-path) — see CHANNEL_WEIGHT
  const now = opts.now || (() => Date.now())
  const codec = inv ? inv.codec : null
  const lookupTimeoutMs = opts.lookupTimeoutMs ?? DEFAULT_LOOKUP_TIMEOUT_MS
  const pollMs = opts.pollMs ?? DEFAULT_POLL_MS
  const mine = new Set()                       // rids WE announced — removed again on close()
  let closed = false

  /** Read + open one record. null on missing / corrupt / wrong key / tamper (never throws:
   * a rendezvous channel must ignore hostile input, exactly like tracker.js's ctx.unpack). */
  function read(rid) {
    let raw
    try { raw = readFileSync(recordPath(dir, rid), 'utf8') } catch { return null }
    let body
    try { body = JSON.parse(raw) } catch { return null }
    if (!body || typeof body !== 'object') return null
    if (typeof body.sealed === 'string') {
      if (!codec) return null                  // sealed record, no key: we cannot open it
      const bytes = Buffer.from(body.sealed, 'base64')
      return codec.open(bytes, rid) || null    // null on wrong k_ip / tampered byte / truncation
    }
    if (codec) return null                     // invite mode never accepts a plaintext record
    return body.blob || null
  }

  return {
    name,
    ridLen,
    _fileRendezvous: true,                     // marks a channel as ours in assertions/audits
    /** @param {Buffer} rid @param {{candidates?:object[]}} [info] */
    announce(rid, info) {
      if (!Buffer.isBuffer(rid)) throw new TypeError('rid must be a Buffer')
      if (closed) return { stop() { } }
      const blob = { v: 1, ts: now(), candidates: (info && info.candidates) || [] }
      const body = codec
        ? { v: 1, sealed: codec.seal(blob, rid).toString('base64') }
        : { v: 1, blob }
      const hex = rid.toString('hex')
      mkdirSync(dir, { recursive: true })
      // atomic: a reader either sees the previous record or the whole new one, never a half file.
      const tmp = join(dir, '.' + hex + '.' + process.pid + '.' + randomBytes(4).toString('hex') + '.tmp')
      writeFileSync(tmp, JSON.stringify(body))
      renameSync(tmp, recordPath(dir, rid))
      mine.add(hex)
      return { stop() { } }
    },
    /**
     * Poll for the record at `rid` until it appears or the deadline passes, then END. Ending is
     * load-bearing: src/node.js:418 punches as soon as the candidate stream is done, so a channel
     * that polled forever would make a failed dial HANG instead of failing with 'no candidates'.
     * @param {Buffer} rid @param {{timeout?:number, signal?:AbortSignal}} [lopts]
     */
    async *lookup(rid, lopts = {}) {
      if (!Buffer.isBuffer(rid)) throw new TypeError('rid must be a Buffer')
      const timeout = lopts.timeout ?? lookupTimeoutMs
      const deadline = Date.now() + timeout    // REAL clock: `now` may be a frozen test epoch
      for (;;) {
        if (closed || lopts.signal?.aborted) return
        const blob = read(rid)
        if (blob) {
          yield { candidates: blob.candidates || [], channel: name, ts: blob.ts ?? now() }
          return
        }
        const left = deadline - Date.now()
        if (left <= 0) return
        await sleep(Math.min(pollMs, left), lopts.signal)
      }
    },
    close() {
      closed = true
      for (const hex of mine) {                // stop advertising: withdraw our own records
        try { unlinkSync(join(dir, hex + '.json')) } catch { /* already gone — fine */ }
      }
      mine.clear()
    },
  }
}

/**
 * An endpoint FACADE that advertises one deterministic 127.0.0.1 candidate on the endpoint's real
 * udp4 port. Only `publishAll` sees it; the node keeps the real endpoint for punching/probeAuth.
 * Throws (loudly, never silently empty) when there is no udp4 port to advertise.
 */
function loopbackEndpoint(ep) {
  return {
    get port() { return ep.port },
    candidates() {
      const port = ep.port4 || ep.port
      if (!port) throw new TypeError('p2p: loopback rendezvous needs a udp4 port on the endpoint')
      return [{ proto: 'udp4', ip: '127.0.0.1', port, kind: 'host' }]
    },
    on(...a) { return typeof ep.on === 'function' ? ep.on(...a) : undefined },
    off(...a) { return typeof ep.off === 'function' ? ep.off(...a) : undefined },
    removeListener(...a) { return typeof ep.removeListener === 'function' ? ep.removeListener(...a) : undefined },
  }
}

/**
 * The rendezvous dep-set for src/node.js `listen(id, {deps})`.
 *
 * @param {string} dir board directory shared by both peers
 * @param {object} [opts]
 *   invite=null           explicit invite context for the listening-side publish
 *   loopback=false        publish 127.0.0.1:<udp4 port> instead of the LAN interfaces
 *   announce=true         false => publishAll is a no-op (a joiner that only seeks)
 *   now=Date.now          clock for rendezvous EPOCHS (freeze it for deterministic rid names)
 *   lookupTimeoutMs=5000  how long one rid is polled before its stream ends
 *   pollMs=25             poll interval
 * @returns {{makeRace:Function, resolve:Function, publishAll:Function, channels:object[]}}
 */
export function fileRendezvousDeps(dir, opts = {}) {
  const loopback = opts.loopback === true
  const doAnnounce = opts.announce !== false
  const now = opts.now || (() => Date.now())
  const channels = []                          // every channel this dep-set ever built (for close())

  /** Build one invite-scoped (or reusable-S) race over a single file channel. */
  const makeRace = (inv = null) => {
    const ch = fileChannel(dir, inv, {
      now, lookupTimeoutMs: opts.lookupTimeoutMs, pollMs: opts.pollMs,
    })
    channels.push(ch)
    // `invite: inv` is what moves the rid from HKDF(S,…) to HKDF(K_inv,…). Drop it and a
    // non-holder of K_inv can locate the record again — the whole property this carrier exists
    // to demonstrate. test/tunnel-board.test.js asserts both rids, so that regression is RED.
    const r = createRace({ channels: [ch], invite: inv, now })
    const publishAll = doAnnounce
      ? (s, endpoint) => r.publishAll(s, loopback ? loopbackEndpoint(endpoint) : endpoint)
      : () => ({ stop() { } })
    return { resolve: r.resolve, publishAll, channels: [ch] }
  }

  const base = makeRace(opts.invite || null)                  // reusable-S mode: listen()'s own presence
  return {
    makeRace,
    resolve: base.resolve,
    publishAll: base.publishAll,
    channels,
    /** close every channel this dep-set built (the base one is NOT owned by the node). */
    close() { for (const c of channels) { try { c.close() } catch { /* */ } } },
  }
}

export default { fileRendezvousDeps, fileChannel, recordPath }
