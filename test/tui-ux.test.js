// test/tui-ux.test.js — the TUI UX contract: Ctrl-C ALWAYS exits, ↑/↓ recalls what you sent,
// PgUp/PgDn scrolls the log.
//
// THE BUG THIS LOCKS DOWN (owner: "sometimes NOTHING quits it — not /quit, not Ctrl-C"):
// peer.send() resolves only on its ACK (src/node.js: pending Map appSeq -> {resolve,reject};
// rejects ONLY on a permanent send error). Send to a dead/hung peer and that promise NEVER settles.
// The old teardown did `await inflight` behind a `quitting` re-entrancy guard, so the first Ctrl-C
// hung in the await and every later Ctrl-C was swallowed by the guard — an unkillable process. And
// raw mode delivers Ctrl-C as the BYTE 0x03, not SIGINT, so nothing else could kill it either.
//
// The TUI needs a real TTY, so it cannot be driven headlessly (and a live TUI = live network, which
// the owner is using right now). Instead the pure pieces live in bin/lib.js and are tested here:
// drainBounded (the anti-hang property), keyAction (raw-mode key decoding, incl. 0x03), the history
// ring, and the scroll clamp. Live-TTY behaviour is owner-verified. Zero deps, zero network.

import test from 'node:test'
import assert from 'node:assert/strict'
import { drainBounded, keyAction, createHistory, clampScroll } from '../bin/lib.js'

// ── #1 CRITICAL: the exit path can never be trapped by a send that never settles ──────────────
test('drainBounded: a NEVER-settling send cannot trap the exit path', async () => {
  const never = new Promise(() => {}) // exactly what peer.send() gives you against a dead peer
  const t0 = Date.now()
  await drainBounded(never, 50) // must resolve anyway — this is the whole anti-hang property
  const dt = Date.now() - t0
  assert.ok(dt < 2000, 'returned in ' + dt + 'ms instead of hanging forever')
})

test('drainBounded: a rejecting send does not throw out of the teardown', async () => {
  await drainBounded(Promise.reject(new Error('permanent send error')), 50) // must not reject
})

test('drainBounded: a send that DOES land is awaited (not needlessly delayed)', async () => {
  let landed = false
  const t0 = Date.now()
  await drainBounded(Promise.resolve().then(() => { landed = true }), 5000)
  assert.equal(landed, true, 'the ack landed before we tore down')
  assert.ok(Date.now() - t0 < 1000, 'did not sit out the full bound')
})

// ── #1 CRITICAL: raw mode hands us Ctrl-C as a byte — it must decode to a forced quit ──────────
test('keyAction: Ctrl-C (0x03) and Ctrl-D (0x04) are a forced quit', () => {
  assert.equal(keyAction('\x03'), 'quit-force')
  assert.equal(keyAction('\x04'), 'quit-force')
})

test('keyAction: ordinary text is NOT an action (it types)', () => {
  assert.equal(keyAction('a'), null)
  assert.equal(keyAction('hello'), null)
  assert.equal(keyAction('\r'), null)
})

// ── #2 history ────────────────────────────────────────────────────────────────────────────────
test('keyAction: ↑/↓ are history recall', () => {
  assert.equal(keyAction('\x1b[A'), 'hist-prev')
  assert.equal(keyAction('\x1b[B'), 'hist-next')
})

test('history: ↑ walks back through what YOU sent, ↓ walks forward', () => {
  const h = createHistory()
  h.remember('hello')
  h.remember('/connect 0S1QS10TPRP5BK00225RT975PT')
  h.remember('bye')
  assert.equal(h.prev(''), 'bye')
  assert.equal(h.prev(''), '/connect 0S1QS10TPRP5BK00225RT975PT')
  assert.equal(h.prev(''), 'hello')
  assert.equal(h.prev(''), 'hello', 'stops at the oldest')
  assert.equal(h.next(''), '/connect 0S1QS10TPRP5BK00225RT975PT')
  assert.equal(h.next(''), 'bye')
})

test('history: ↓ off the end restores the half-typed draft you left', () => {
  const h = createHistory()
  h.remember('sent one')
  assert.equal(h.prev('half-typed'), 'sent one') // stashes the draft
  assert.equal(h.next(''), 'half-typed') // and hands it back
})

test('history: empty history, blanks and consecutive dupes are no-ops', () => {
  const h = createHistory()
  assert.equal(h.prev('draft'), 'draft', 'nothing to recall -> input untouched')
  assert.equal(h.next('draft'), 'draft')
  h.remember('   ')
  h.remember('')
  assert.equal(h.size, 0)
  h.remember('x'); h.remember('x'); h.remember('x')
  assert.equal(h.size, 1, 'consecutive dupes collapse')
})

test('history: ring is bounded (no unbounded memory growth)', () => {
  const h = createHistory(3)
  for (const t of ['a', 'b', 'c', 'd']) h.remember(t)
  assert.deepEqual(h.items, ['b', 'c', 'd'])
})

// ── #3 scroll ─────────────────────────────────────────────────────────────────────────────────
test('keyAction: PgUp/PgDn/Home/End/Shift+arrows scroll the log', () => {
  assert.equal(keyAction('\x1b[5~'), 'page-up')
  assert.equal(keyAction('\x1b[6~'), 'page-down')
  assert.equal(keyAction('\x1b[1;2A'), 'line-up')
  assert.equal(keyAction('\x1b[1;2B'), 'line-down')
  assert.equal(keyAction('\x1b[F'), 'scroll-live')
  assert.equal(keyAction('\x1bOF'), 'scroll-live')
  assert.equal(keyAction('\x1b[H'), 'scroll-top')
})

test('clampScroll: never past the oldest line, never below live', () => {
  // 100 lines of log in a 20-line viewport -> at most 80 lines of scrollback
  assert.equal(clampScroll(500, 100, 20), 80, 'clamped to the oldest line')
  assert.equal(clampScroll(-5, 100, 20), 0, 'never below live')
  assert.equal(clampScroll(30, 100, 20), 30, 'a valid offset is kept')
  assert.equal(clampScroll(10, 5, 20), 0, 'nothing to scroll when it all fits')
})
