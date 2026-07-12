// test/quit-always.test.js — "a process you can't kill is the worst bug."
//
// THE BUG (owner, live test): "sometimes when p2p fails, NOTHING quits it — not /quit, not Ctrl+C."
// peer.send() resolves ONLY on its ACK (src/node.js: pending Map appSeq -> {resolve,reject}; it
// rejects only on a PERMANENT send error). Send to a dead/hung peer and that promise NEVER settles.
// Every chat front-end tore down with an unbounded `await inflight` sitting behind a
// `if (closing) return` / `if (quitting) return` re-entrancy guard, so the FIRST Ctrl-C hung in the
// await and the guard then swallowed every retry. Unkillable.
//
// Fixed in bin/p2p.js lineMode() (`p2p connect` / `p2p chat` — the command the owner actually runs),
// bin/p2p-tui.js and bin/p2p-chat.js: the drain is BOUNDED (drainBounded) and a second Ctrl-C exits
// immediately, awaiting nothing.
//
// These front-ends all open a real network node on startup, so they cannot be driven in the default
// (offline) suite — see test/live-gate.test.js. So we assert the two things that actually make the
// bug impossible: (1) the bounded-drain primitive really does survive a never-settling send, and
// (2) a source tripwire that no shutdown path has regressed back to an unbounded `await inflight`.
// Live-TTY behaviour is covered by a dependency-free pty run (macOS `script`) — see the lane report.

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { drainBounded } from '../bin/lib.js'

const src = (f) => readFileSync(fileURLToPath(new URL('../bin/' + f, import.meta.url)), 'utf8')

/** Source lines with comment-only lines stripped, so a comment ABOUT the bug isn't mistaken for it. */
const codeLines = (text) =>
  text.split('\n').filter((l) => {
    const t = l.trim()
    return t && !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*')
  })

// The chat front-ends whose teardown this lane fixed. (bin/p2p-group.js is another lane's file and
// still carries the unbounded drain at :226 — reported, not silently adopted here.)
const FRONTENDS = ['p2p.js', 'p2p-tui.js', 'p2p-chat.js']

// ── the property that makes the hang impossible ───────────────────────────────────────────────
test('drainBounded: a never-settling send (dead peer) cannot trap the exit path', async () => {
  const never = new Promise(() => {}) // exactly what peer.send() gives you against a dead peer
  const t0 = Date.now()
  await drainBounded(never, 50) // resolves anyway, or this test hangs and the suite times out
  assert.ok(Date.now() - t0 < 2000, 'teardown drain returned instead of hanging forever')
})

// ── the tripwire: never regress to an unbounded drain ─────────────────────────────────────────
for (const f of FRONTENDS) {
  test(`${f}: teardown never awaits the send queue unbounded`, () => {
    const bad = codeLines(src(f)).filter((l) => /await\s+inflight/.test(l))
    assert.deepEqual(bad, [], `unbounded \`await inflight\` is back in ${f} — a dead peer will hang Ctrl-C`)
  })

  test(`${f}: teardown drains through drainBounded()`, () => {
    assert.match(src(f), /drainBounded\(inflight/, `${f} must bound its shutdown drain`)
  })
}

// ── the guard that used to swallow Ctrl-C must no longer be able to ───────────────────────────
test('p2p.js: a second Ctrl-C force-exits instead of being swallowed', () => {
  // The old code was `if (closing) return` — the retry went nowhere. It must now exit.
  const s = src('p2p.js')
  assert.doesNotMatch(s, /if \(closing\) return;\s*closing = true/, 'the swallowing guard is back')
  assert.match(s, /if \(closing\) return finish\(130\)/, 'a 2nd Ctrl-C must force-exit')
})

test('p2p.js: teardown is re-entrancy safe (rl.close() fires "close" -> shutdown again)', () => {
  // finish() calls rl.close(), which synchronously emits 'close', whose handler calls shutdown()
  // again. Without an `exiting` latch that re-entry would hijack the graceful exit code.
  assert.match(src('p2p.js'), /if \(exiting\) return/, 'the first exit must win')
})
