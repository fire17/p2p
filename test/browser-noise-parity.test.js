// test/browser-noise-parity.test.js — G1: the BROWSER runs the same Noise as the TUI.
//
// The browser client does not re-implement the protocol. It runs src/noise.js and src/key.js —
// the exact files the TUI runs — with node:crypto and Buffer swapped for the browser shims.
// This test drives that stack (in a child process, so replacing the global Buffer can't disturb
// the runner) and asserts:
//
//   1. the official Noise KAT vector is reproduced BYTE-EXACT on the browser stack, against BOTH
//      independent sources (cacophony + snow) — same assertion the TUI's noise.test.js makes;
//   2. key.js works there: identity, 26-char contact string, commitment gate;
//   3. the rid the browser derives for a contact string is IDENTICAL to the one the TUI derives
//      — this is what makes browser and TUI meet at the same rendezvous point.
//
// (1)+(3) together are the interop proof: same handshake bytes, same meeting place.
// Primitive-level equality (shim vs node:crypto, function by function) is browser-shim.test.js.

import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'
import { deriveRid } from '../src/key.js' // the REAL, node-native key.js

const HERE = dirname(fileURLToPath(import.meta.url))

test('G1: browser stack reproduces the official Noise KAT byte-exact, and agrees with the TUI on rids', () => {
  const out = execFileSync(process.execPath, [join(HERE, 'fixtures', 'browser-stack.mjs')], {
    encoding: 'utf8',
    timeout: 60_000,
  })

  assert.match(out, /BROWSER-STACK OK/, 'browser stack must complete cleanly')
  assert.match(out, /KAT byte-exact on the browser stack vs cacophony/, 'KAT vs cacophony')
  assert.match(out, /KAT byte-exact on the browser stack vs snow/, 'KAT vs snow')
  assert.match(out, /key\.js: identity \+ 26-char string \+ commitment gate/, 'key.js on the browser stack')

  // The rendezvous handshake: the browser derived a rid for a fresh identity. The TUI's OWN
  // key.js, given the same contact string, must derive the same 20 bytes — or a browser and a
  // TUI would announce/look up at different places and never find each other.
  const m = /^RID (\S+) ([0-9a-f]{40})$/m.exec(out)
  assert.ok(m, 'browser stack must print its derived rid')
  const [, S, browserRid] = m
  const tuiRid = deriveRid(S, 'tracker', '2026-07-12', 20).toString('hex')
  assert.equal(browserRid, tuiRid, 'browser and TUI MUST derive the same rendezvous id for the same key')
})
