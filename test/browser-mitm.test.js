// test/browser-mitm.test.js — the security claim, adversarially. The browser client is ONLY as
// secure as the TUI if it fails closed against an attacker who owns the signaling path (a
// malicious tracker + the WebRTC/DTLS layer). This runs the browser stack (shim crypto + the
// SHARED src/key.js + src/noise.js) and proves a MITM cannot succeed.
//
// If any assertion here inverts, the "security >= TUI" claim is false — so these are the tests
// that earn the claim, not the happy-path E2E.

import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))

test('browser stack fails closed against a signaling-layer MITM', () => {
  const out = execFileSync(process.execPath, [join(HERE, 'fixtures', 'browser-mitm.mjs')], {
    encoding: 'utf8',
    timeout: 60_000,
  })
  assert.match(out, /gate REJECTS substituted keys/, 'commitment gate must reject an attacker\'s keys')
  assert.match(out, /MITM handshake FAILED CLOSED/, 'Noise IK must reject an impostor responder')
  assert.match(out, /real handshake completes with matching handshake hash/, 'the honest path still works')
  assert.match(out, /MITM-RESISTANT OK/, 'overall')
})
