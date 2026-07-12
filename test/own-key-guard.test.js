// test/own-key-guard.test.js — the CLI own-key guard: the #1 footgun is dialing your OWN key.
// Two `p2p` sessions on the same default profile share one identity, so `p2p connect <own-key>`
// silently tries to talk to yourself and never connects. Guard added to every bin/ dial entry
// point (p2p.js lineMode → connect/chat, p2p-tui.js dial → bare `p2p <key>` + /connect,
// p2p-chat.js runConnect). Mirror of the browser client's own-key guard (commit 2054f5d).
//
// Part A unit-tests the shared isOwnKey() predicate; Part B spawns the REAL `p2p` CLI and proves
// `p2p connect <own-key>` REFUSES + never dials (exits 2, no network), and that the normal dial
// plumbing is untouched (--selftest still PASS). Zero deps; no live rendezvous / mDNS used.

import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateIdentity, mintInvite, isOwnKey, OWN_KEY_MSG } from '../bin/lib.js'

const P2P = fileURLToPath(new URL('../bin/p2p.js', import.meta.url))
// a bare 26-char Crockford-base32 key (alphabet excludes I L O U)
const KEY_RE = /\b[0-9A-HJKMNP-TV-Z]{26}\b/

function runCli(args, home) {
  return spawnSync(process.execPath, [P2P, ...args], {
    env: { ...process.env, P2P_HOME: home }, encoding: 'utf8', timeout: 20000,
  })
}

// ── Part A: the predicate ──────────────────────────────────────────────────────
test('isOwnKey: refuses your OWN bare key (case-insensitive)', () => {
  const id = generateIdentity()
  assert.equal(isOwnKey(id.S, id.S), true)
  assert.equal(isOwnKey(id.S.toLowerCase(), id.S), true)
  assert.equal(isOwnKey('  ' + id.S + '  ', id.S), true) // trimmed
})

test('isOwnKey: refuses your OWN one-time invite share (S-<tail>)', () => {
  const id = generateIdentity()
  const { share } = mintInvite(id) // "<26-char S>-<28-char secret>"
  assert.match(share, /-/)
  assert.equal(isOwnKey(share, id.S), true)
})

test('isOwnKey: ALLOWS a different peer key (guard must not false-positive)', () => {
  const me = generateIdentity(), other = generateIdentity()
  assert.notEqual(me.S, other.S)
  assert.equal(isOwnKey(other.S, me.S), false)
})

test('isOwnKey: malformed/empty target does not trip the guard', () => {
  const id = generateIdentity()
  assert.equal(isOwnKey('not-a-key', id.S), false)
  assert.equal(isOwnKey('', id.S), false)
  assert.equal(isOwnKey(id.S, ''), false) // no own key resolved yet -> never blocks
})

test('OWN_KEY_MSG is actionable (names the fix)', () => {
  assert.match(OWN_KEY_MSG, /OWN key/)
  assert.match(OWN_KEY_MSG, /--profile/)
  assert.match(OWN_KEY_MSG, /--ephemeral/)
})

// ── Part B: the real CLI ────────────────────────────────────────────────────────
test('CLI: `p2p connect <own-key>` REFUSES and never dials', () => {
  const home = mkdtempSync(join(tmpdir(), 'p2p-ownkey-'))
  const mint = runCli(['key'], home) // mints the default identity in this temp P2P_HOME
  const S = (mint.stdout.match(KEY_RE) || [])[0]
  assert.ok(S, 'minted my own default key: ' + JSON.stringify(mint.stdout))

  const r = runCli(['connect', S], home)
  assert.equal(r.status, 2, 'exits 2 (refused)')
  const out = r.stdout + r.stderr
  assert.match(out, /OWN key/, 'prints the actionable refuse message')
  assert.doesNotMatch(out, /connecting to/i, 'never reached the dial')
  assert.doesNotMatch(out, /secure channel/i, 'no channel established')
})

test('CLI: bare `p2p <own-key>` (TUI launch) refuses without a TTY-less dial', () => {
  // The bare-key path routes into the TUI, which needs a real terminal; without one it exits
  // before any dial. The interactive /connect + bare-launch dial share ONE guard in p2p-tui.js
  // dial() (unit-covered by isOwnKey above); here we only assert the CLI never self-dials on stdout.
  const home = mkdtempSync(join(tmpdir(), 'p2p-ownkey-'))
  const S = (runCli(['key'], home).stdout.match(KEY_RE) || [])[0]
  assert.ok(S)
  const r = runCli([S], home)
  assert.doesNotMatch(r.stdout + r.stderr, /secure channel/i, 'no self-channel established')
})

test('CLI: --selftest still PASSES (normal two-node dial plumbing intact)', () => {
  const r = spawnSync(process.execPath, [P2P, '--selftest'], { encoding: 'utf8', timeout: 30000 })
  assert.equal(r.status, 0, r.stdout + r.stderr)
  assert.match(r.stdout, /SELFTEST PASS/)
})
