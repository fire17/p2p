// test/live-gate.test.js — the gate that keeps `node --test` off the real network, tested.
//
// THE HAZARD (this happened): `node --test` executes EVERY .js/.mjs under test/, and several of them
// bound real sockets by DEFAULT — a LIVE mDNS test multicasting on the LAN, real public STUN, the
// Mainline-DHT and WSS-tracker gates, and werift-tui-e2e.mjs, whose default mode dials two peers
// over the REAL public trackers. The owner feel-tests a live tui↔tui session on this same machine,
// so a stray announce from a test run pollutes his discovery. One of them bit us mid-session.
//
// This asserts the invariant that prevents a repeat: WITHOUT P2P_LIVE, nothing on the real network
// runs; WITH it, the same tests run. The flip is proven against a NO-OP probe fixture rather than by
// firing the real mDNS/STUN/DHT/tracker tests — proving the flag by emitting real traffic would be
// committing the exact sin the gate exists to prevent.

import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { liveOnly, LIVE, skipLiveScript } from './live-gate.mjs'

const HERE = fileURLToPath(new URL('.', import.meta.url))
const probe = fileURLToPath(new URL('./fixtures/live-gate-probe.mjs', import.meta.url))

/**
 * Run `node --test <file>` with an env, return its output (never throws on a nonzero exit).
 * NODE_TEST_CONTEXT must be STRIPPED: we are ourselves running under the test runner, and a child
 * that inherits it switches to node's v8-serialized reporter protocol and prints nothing to stdout.
 */
function runNodeTest(file, env) {
  const childEnv = { ...process.env, P2P_LIVE: '', ...env }
  delete childEnv.NODE_TEST_CONTEXT
  try {
    return execFileSync(process.execPath, ['--test', file], { env: childEnv, encoding: 'utf8', stdio: 'pipe' })
  } catch (e) {
    return String(e.stdout || '') + String(e.stderr || '')
  }
}

test('the gate flips: a live-gated test is SKIPPED without P2P_LIVE and RUNS with it', () => {
  const off = runNodeTest(probe, { P2P_LIVE: '' })
  assert.match(off, /skipped 1/, 'without the flag the gated test must be SKIPPED')
  assert.match(off, /pass 0/, 'and must not run')

  const on = runNodeTest(probe, { P2P_LIVE: '1' })
  assert.match(on, /pass 1/, 'with P2P_LIVE=1 the same test must RUN')
  assert.match(on, /skipped 0/, 'and must not be skipped')
})

test('liveOnly / skipLiveScript reflect the flag in THIS process', () => {
  // This suite runs without P2P_LIVE in the default `node --test`, which is the state we care about.
  if (!LIVE) {
    assert.equal(typeof liveOnly.skip, 'string', 'liveOnly must carry a skip reason when opted out')
    assert.match(liveOnly.skip, /P2P_LIVE/, 'the skip reason must tell you how to run it')
  } else {
    assert.deepEqual(liveOnly, {}, 'with the flag set, liveOnly must not skip anything')
  }
  // A harness launched BY HAND is never gated — the owner's manual workflow must keep working.
  const saved = process.env.NODE_TEST_CONTEXT
  delete process.env.NODE_TEST_CONTEXT
  assert.equal(skipLiveScript('x.mjs'), false, 'a hand-run harness is never skipped')
  if (saved !== undefined) process.env.NODE_TEST_CONTEXT = saved
})

// ── the standing audit: no test may reach the real network without the gate ──────────────────────
//
// A source tripwire, because the failure mode is someone ADDING a live test later (or an existing
// one losing its gate) and nobody noticing until it multicasts across the owner's LAN again. Every
// file below reaches real infrastructure; each must carry the gate.

test('AUDIT: every real-network test/harness still carries the live gate', () => {
  const gated = [
    ['mdns.test.js', /test\('LIVE: two real-socket instances[^']*', liveOnly/, 'real LAN multicast'],
    ['stun.test.js', /test\('LIVE: real public STUN[^']*', liveOnly/, 'real public STUN servers'],
    ['gate/dht.test.js', /test\('bootstrap nodes are live \(ping\)', \{ \.\.\.liveOnly/, 'real Mainline DHT bootstrap'],
    ['gate/dht.test.js', /test\('GATE: live announce[^']*', \{ \.\.\.liveOnly/, 'real Mainline DHT announce'],
    ['gate/tracker.test.js', /test\('WSS tracker reachability[^']*', \{ \.\.\.liveOnly/, 'real public WSS trackers'],
    ['gate/tracker.test.js', /test\('two-peer offer relay[^']*', \{ \.\.\.liveOnly/, 'real public WSS trackers'],
    ['werift-tui-e2e.mjs', /if \(skipLiveScript\('werift-tui-e2e\.mjs'\)\) process\.exit\(0\)/, 'real trackers + real ICE'],
  ]
  for (const [file, re, why] of gated) {
    const src = readFileSync(HERE + file, 'utf8')
    assert.match(src, re, `${file} reaches ${why} — it MUST keep its live gate (see test/live-gate.mjs)`)
  }
})
