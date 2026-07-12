// scratch/leak-red-proof.mjs — proves the standing leak-monitor's assertions actually BITE.
//
// NOT part of the default suite. Run:  node scratch/leak-red-proof.mjs
//
// It deliberately RE-INTRODUCES each leak and shows the monitor's own assertion goes RED (throws).
// A detector that fails to fire here is the real bug — so this exits non-zero if any RED is missing.
// Covers the two the brief calls out: no-plaintext-IP and wire-header-auth.

import assert from 'node:assert/strict'
import { Observer, CAND_SETS, assertNoLeak } from '../test/observer.js'
import { encodeFrame, decodeFrame, TYPE } from '../src/wire.js'

let missing = 0
const red = (label, fn) => {
  try { fn(); console.log(`\n❌ NO RED for ${label} — the detector FAILED to fire (this is a real problem)`); missing++ }
  catch (e) { console.log(`\n✅ RED fired for ${label}:\n   ${e.message}`) }
}

// ── RED 1: no-plaintext-IP — inject a plaintext IP into a "sealed" surface view ────────────────────
red('no-plaintext-IP (injected leak into a sealed blob)', () => {
  const cands = CAND_SETS.ipv4
  const obs = new Observer('broken-seal')
  // simulate a regressed seal that left the candidate IP in the clear inside the 544-B value
  const leaky = Buffer.alloc(544)
  leaky.write(`{"candidates":[{"ip":"${cands[0].ip}","port":${cands[0].port}}]}`, 0, 'utf8')
  obs.bytes(leaky)
  assertNoLeak(obs, cands)          // <-- must THROW: A (IP) / B (port) / C (marker) all violated
})

// ── RED 2: wire-header-auth — the pre-fix (unauthenticated) control plane accepts a forged frame ───
red('wire-header-auth (forged ack accepted by the pre-fix unauthenticated decode)', () => {
  const connId = Buffer.alloc(8, 0xab)
  const attacker = Buffer.alloc(16, 0x99)                     // a forger's key (not the real peer's)
  const forged = encodeFrame(TYPE.PING, connId, 0, 0xfffffff0, null, attacker)
  // The PRE-FIX code decoded the header with NO key and fed f.ack straight to onAck → window drain.
  // Assert the SECURE property against that path: it must be rejected (null). It is NOT → RED.
  const f = decodeFrame(forged)                               // no MAC key == the WIRE-1/2/3 vuln path
  assert.equal(f, null, `unauthenticated decode ACCEPTED a forged frame carrying ack=${f?.ack} — this drains the send window (WIRE-1)`)
})

// sanity: the FIX side is green (the same forged bytes are rejected under a receive key)
{
  const connId = Buffer.alloc(8, 0xab)
  const macRx = Buffer.alloc(16, 0x22)
  const attacker = Buffer.alloc(16, 0x99)
  const forged = encodeFrame(TYPE.PING, connId, 0, 0xfffffff0, null, attacker)
  assert.equal(decodeFrame(forged, macRx), null, 'FIX: authenticated decode rejects the forgery')
  console.log('\n🟢 GREEN (contrast): under the real receive key the same forged frame decodes to null (rejected).')
}

console.log(missing === 0 ? '\nAll detectors fired. ✅' : `\n${missing} detector(s) did NOT fire. ❌`)
process.exit(missing === 0 ? 0 : 1)
