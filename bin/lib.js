// Shared helpers for the p2p CLI + TUI. Zero deps (Node built-ins only).
// Reuses the real framework: ../src/node.js (network) + ../src/key.js (identity/gate).

import { homedir } from 'node:os'
import { join } from 'node:path'
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs'
import { generateIdentity, decodeKey, verifyCommitment, TypoError } from '../src/key.js'

export { generateIdentity, decodeKey, verifyCommitment, TypoError }

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
