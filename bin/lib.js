// Shared helpers for the p2p CLI + TUI. Zero deps (Node built-ins only).
// Reuses the real framework: ../src/node.js (network) + ../src/key.js (identity/gate).

import { homedir } from 'node:os'
import { join } from 'node:path'
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs'
import { generateIdentity, decodeKey, verifyCommitment, encodeKey, TypoError } from '../src/key.js'
import { generateInviteSecret, formatShare, parseShare, INVITE_FLAG } from '../src/invite.js'

export { generateIdentity, decodeKey, verifyCommitment, encodeKey, TypoError }
export { generateInviteSecret, formatShare, parseShare, INVITE_FLAG }

/**
 * Mint a fresh ONE-TIME invite for this identity (metadata privacy v1). Same keypair, but the
 * contact string carries the INVITE flag and a per-invite secret tail: only the holder of the tail
 * can locate (rid_inv), decrypt (k_ip) or handshake with (psk) this node's rendezvous record.
 * The secret is NOT persisted — it lives for the life of the process that published it.
 * @param {{edPub:Buffer,xPub:Buffer}} id
 * @returns {{secret:Buffer, share:string}}
 */
export function mintInvite(id) {
  const secret = generateInviteSecret()
  return { secret, share: formatShare(encodeKey(id.edPub, id.xPub, INVITE_FLAG), secret) }
}

/** true if a CLI argument looks like a contact string (bare S or an S-<tail> invite share). */
export function looksLikeShare(s) {
  if (typeof s !== 'string') return false
  try { const { S } = parseShare(s); return S.length === 26 } catch { return false }
}

// ── own-key guard: the #1 footgun ────────────────────────────────────────────
// Two `p2p` sessions on the same profile share ONE identity, so `p2p connect <own-key>`
// (or bare `p2p <own-key>`) silently tries to talk to yourself and never connects. Resolve
// the dial target's 26-char S (bare key OR the S half of an S-<tail> invite share) and compare
// it to THIS session's own key on the KEYPAIR COMMITMENT — not the raw string. decodeKey is
// case-insensitive (Crockford ambiguity mapped) AND flag-independent: a one-time invite of your
// OWN key encodes to a different S (the INVITE_FLAG bit is set) but the same 14-byte commitment,
// so the string compare misses it while the commitment compare catches it. A malformed target
// returns false (its bad-key error is handled by the normal dial path). Mirrors the browser
// client's own-key guard (commit 2054f5d).
export function isOwnKey(target, ownKey) {
  if (!ownKey) return false
  try {
    const a = decodeKey(parseShare(String(target).trim()).S).commitment
    const b = decodeKey(String(ownKey).trim()).commitment
    return a.equals(b)
  } catch { return false }
}

/** The actionable refuse message printed at every dial entry point when you dial your OWN key. */
export const OWN_KEY_MSG =
  "that's your OWN key — you can't chat with yourself. Run the other peer with a " +
  'different identity:  p2p --profile <name>   (or --ephemeral).'

// ── teardown safety: never await a promise that may never settle ─────────────
// peer.send() resolves ONLY on its ACK (src/node.js: pending Map appSeq -> {resolve,reject};
// it rejects only on a PERMANENT send error). Send to a dead/hung peer and that promise NEVER
// settles. Any shutdown path that does `await inflight` therefore hangs FOREVER — and with a
// `closing`/`quitting` re-entrancy guard in front of it, every subsequent Ctrl-C is swallowed:
// an unkillable process. Every teardown drain MUST be bounded by this.
/** Await `p`, but never longer than `ms`. Resolves (never rejects) — a drain must not throw. */
export function drainBounded(p, ms = 300) {
  let t
  // NB: the timer is deliberately NOT unref'd — an unref'd timer lets the event loop drain out
  // from under a never-settling `p`, which is precisely the case this exists to survive.
  // clearTimeout in the tail means it never holds the process open either.
  return Promise.race([
    Promise.resolve(p).catch(() => {}),
    new Promise((r) => { t = setTimeout(r, ms) }),
  ]).then(() => { clearTimeout(t) }, () => { clearTimeout(t) })
}

// ── TUI input helpers (pure — the TUI itself needs a real TTY, these do not) ──
/**
 * Map a raw stdin chunk (raw mode: no line discipline, so Ctrl-C arrives as the BYTE 0x03 and
 * arrows as ESC sequences) to a TUI action. Returns null for ordinary printable text.
 */
export function keyAction(seq) {
  switch (seq) {
    case '\x03': return 'quit-force'                              // Ctrl-C  — always exits
    case '\x04': return 'quit-force'                              // Ctrl-D  — always exits
    case '\x1b[A': return 'hist-prev'                             // ↑  older sent line
    case '\x1b[B': return 'hist-next'                             // ↓  newer sent line
    case '\x1b[5~': return 'page-up'                              // PgUp    scroll back
    case '\x1b[6~': return 'page-down'                            // PgDn    scroll forward
    case '\x1b[1;2A': return 'line-up'                            // Shift+↑ scroll 1 line
    case '\x1b[1;2B': return 'line-down'                          // Shift+↓ scroll 1 line
    case '\x1b[H': case '\x1bOH': case '\x1b[1~': return 'scroll-top'   // Home
    case '\x1b[F': case '\x1bOF': case '\x1b[4~': return 'scroll-live'  // End -> live
    default: return null
  }
}

/**
 * Shell-style history ring for the input line: ↑ walks back through what YOU sent, ↓ walks
 * forward and lands back on the half-typed draft you left behind. In memory only.
 */
export function createHistory(max = 500) {
  const items = []
  let idx = 0      // items.length == "on the live draft, not browsing"
  let draft = ''
  return {
    items,
    get size() { return items.length },
    /** Record a submitted line (skips blanks + consecutive dupes) and return to the live draft. */
    remember(text) {
      if (!text || !text.trim()) return
      if (items[items.length - 1] !== text) items.push(text)
      if (items.length > max) items.shift()
      idx = items.length
      draft = ''
    },
    /** ↑ — returns the line to put in the input (stashing `current` as the draft on first step). */
    prev(current = '') {
      if (!items.length) return current
      if (idx === items.length) draft = current
      idx = Math.max(0, idx - 1)
      return items[idx]
    },
    /** ↓ — returns the next-newer line, or the stashed draft once you walk off the end. */
    next(current = '') {
      if (idx >= items.length) return current
      idx++
      return idx === items.length ? draft : items[idx]
    },
  }
}

/** Clamp a scroll offset (lines ABOVE the live bottom; 0 = live) to what actually exists. */
export const clampScroll = (scroll, totalLines, viewH) =>
  Math.max(0, Math.min(Math.max(0, totalLines - Math.max(1, viewH)), scroll))

// ── ANSI (no-op when stdout is not a TTY) ────────────────────────────────────
export const TTY = process.stdout.isTTY
export const c = (code, s) => (TTY ? `\x1b[${code}m${s}\x1b[0m` : String(s))
export const bold = (s) => c('1', s)
export const dim = (s) => c('2', s)
export const red = (s) => c('31', s)
export const green = (s) => c('32', s)
export const yellow = (s) => c('33', s)
export const blue = (s) => c('34', s)
export const magenta = (s) => c('35', s)
export const cyan = (s) => c('36', s)

// ── peer identity display ────────────────────────────────────────────────────
export const shortId = (S) => String(S).slice(0, 6)
// Dialer's peer carries .S (the dialed key); a listener's accepted peer has S=null but
// .remoteStatic (32B X25519). Label from whichever is present, stable per peer.
export const peerLabel = (peer) =>
  peer && peer.S
    ? shortId(peer.S)
    : peer && peer.remoteStatic
      ? Buffer.from(peer.remoteStatic).toString('hex').slice(0, 6).toUpperCase()
      : '??????'
export const asBuf = (d) => (Buffer.isBuffer(d) ? d : Buffer.from(String(d)))

// ── identity store: a STABLE key across runs (else your key changes every launch) ──
// Stored at ~/.p2p/<profile>.json, 0600. Keys are raw 32B buffers (see key.js). This
// holds your PRIVATE keys unencrypted — same trust model as ~/.ssh/id_*; dir/file are
// 0700/0600. --ephemeral skips the store for a throwaway identity.
const P2P_DIR = process.env.P2P_HOME || join(homedir(), '.p2p')
const idFile = (profile = 'default') => join(P2P_DIR, `${profile}.json`)

export function loadOrCreateIdentity({ ephemeral = false, profile = 'default' } = {}) {
  if (ephemeral) return generateIdentity()
  const file = idFile(profile)
  if (existsSync(file)) {
    const j = JSON.parse(readFileSync(file, 'utf8'))
    const id = {
      S: j.S,
      edPub: Buffer.from(j.edPub, 'hex'),
      edPriv: Buffer.from(j.edPriv, 'hex'),
      xPub: Buffer.from(j.xPub, 'hex'),
      xPriv: Buffer.from(j.xPriv, 'hex'),
    }
    // integrity: the stored key string must match its committed pubkeys, else refuse it
    if (!verifyCommitment(decodeKey(id.S).commitment, id.edPub, id.xPub)) {
      throw new Error(`identity file ${file} is corrupt (key does not match its pubkeys)`)
    }
    return id
  }
  const id = generateIdentity()
  saveIdentity(id, profile)
  return id
}

export function saveIdentity(id, profile = 'default') {
  mkdirSync(P2P_DIR, { recursive: true, mode: 0o700 })
  const j = {
    S: id.S,
    edPub: id.edPub.toString('hex'),
    edPriv: id.edPriv.toString('hex'),
    xPub: id.xPub.toString('hex'),
    xPriv: id.xPriv.toString('hex'),
  }
  const file = idFile(profile)
  writeFileSync(file, JSON.stringify(j), { mode: 0o600 })
  try { chmodSync(file, 0o600) } catch { /* best-effort on platforms without chmod */ }
  return file
}

export const idFilePath = idFile

// ── friends: everyone you've connected with, so you can reconnect later ───────
// Stored at ~/.p2p/<profile>.friends.json — a small list keyed by the friend's 26-char
// key (their public contact string). Populated automatically on every connection; never
// clobbered on update (it lives beside the identity in ~/.p2p). No private data — just
// public keys + a nickname + timestamps.
const friendsFile = (profile = 'default') => join(P2P_DIR, `${profile}.friends.json`)

export function loadFriends(profile = 'default') {
  const file = friendsFile(profile)
  if (!existsSync(file)) return []
  try {
    const list = JSON.parse(readFileSync(file, 'utf8'))
    return Array.isArray(list) ? list : []
  } catch { return [] }
}

// Record (or refresh) a friend by their key. Returns { friend, isNew }. Ignores our own key.
export function addFriend(key, { nick, profile = 'default', selfKey } = {}) {
  key = String(key || '').trim().toUpperCase()
  if (key.length !== 26 || key === String(selfKey || '').toUpperCase()) return { friend: null, isNew: false }
  const list = loadFriends(profile)
  const now = Date.now()
  let f = list.find((x) => x.key === key)
  let isNew = false
  if (f) { f.lastSeen = now; if (nick) f.nick = nick }
  else { f = { key, nick: nick || shortId(key), firstSeen: now, lastSeen: now }; list.push(f); isNew = true }
  try {
    mkdirSync(P2P_DIR, { recursive: true, mode: 0o700 })
    writeFileSync(friendsFile(profile), JSON.stringify(list, null, 2), { mode: 0o600 })
  } catch { /* best-effort; a failed friends-write must never break a chat */ }
  return { friend: f, isNew }
}

// Resolve a name-or-key to a friend's key: exact key, nick match, or short-id prefix.
export function resolveFriend(nameOrKey, profile = 'default') {
  const q = String(nameOrKey || '').trim()
  if (q.length === 26) return q.toUpperCase()
  const list = loadFriends(profile)
  const byNick = list.find((f) => f.nick && f.nick.toLowerCase() === q.toLowerCase())
  if (byNick) return byNick.key
  const byShort = list.find((f) => f.key.toLowerCase().startsWith(q.toLowerCase()))
  return byShort ? byShort.key : null
}

// The public key of a connected peer, for saving as a friend: peer.key (both sides, once
// node.js exposes it) or peer.S (the dialer always has the key it dialed).
export const peerKey = (peer) => (peer && (peer.key || peer.S)) || null

// ── the real network backend ─────────────────────────────────────────────────
export async function loadNode() {
  const mod = await import(new URL('../src/node.js', import.meta.url))
  if (typeof mod.listen !== 'function' || typeof mod.identity !== 'function') {
    throw new Error('src/node.js is missing the expected exports (listen/identity)')
  }
  return mod
}

// ── doctor: probe free-infra rendezvous reachability (no peer needed) ─────────
export async function doctor() {
  const out = []
  try {
    const { createEndpoint } = await import(new URL('../src/transport.js', import.meta.url))
    const ep = await createEndpoint({})
    try {
      const srflx = await ep.stun()
      out.push(['STUN (public reflexive address)', !!srflx, srflx ? `${srflx.ip}:${srflx.port}` : 'no response'])
    } catch (e) { out.push(['STUN', false, e.message]) }
    ep.close?.()
  } catch (e) { out.push(['STUN', false, e.message]) }

  try {
    const { DHT, BOOTSTRAP } = await import(new URL('../src/rendezvous/dht.js', import.meta.url))
    const d = new DHT(); await d.ready()
    let up = 0
    for (const b of BOOTSTRAP) { try { await d.ping(b); up++ } catch { /* dead node */ } }
    d.close()
    out.push([`DHT bootstrap nodes`, up > 0, `${up}/${BOOTSTRAP.length} reachable`])
  } catch (e) { out.push(['DHT', false, e.message]) }

  try {
    const { TRACKERS, trackerProbe, randId20 } = await import(new URL('../src/rendezvous/tracker.js', import.meta.url))
    let up = 0
    for (const t of TRACKERS) { try { await trackerProbe(t, randId20(), { timeout: 6000 }); up++ } catch { /* down */ } }
    out.push([`WSS trackers`, up > 0, `${up}/${TRACKERS.length} reachable`])
  } catch (e) { out.push(['trackers', false, e.message]) }

  return out
}
