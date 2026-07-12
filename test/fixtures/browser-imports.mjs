// test/fixtures/browser-imports.mjs — shim-coverage smoke check (browser-research lane).
//
// Confirms the browser stack (shim crypto + Buffer) can IMPORT every shared protocol module —
// including src/sign.js and BOTH group constructors (pairwise createGroup + sender-keys
// createSecureGroup) — with no missing `node:crypto` export. This is purely a completeness check
// on the shim I own; it does NOT test group logic (that's browser-build's lane). If a shared
// module starts importing a node:crypto function the shim lacks, this fails loudly here instead of
// as a runtime "does not provide an export named X" in a real browser.

import { register } from 'node:module'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'
import assert from 'node:assert/strict'

const HERE = dirname(fileURLToPath(import.meta.url))
register(pathToFileURL(join(HERE, 'shim-hooks.mjs')))
const { Buffer: ShimBuffer } = await import('../../src/browser/shim/buffer.js')
globalThis.Buffer = ShimBuffer
globalThis.process ??= { env: {} }

// every shared module the browser loads (transitively) must import cleanly on the shim
const key = await import('../../src/key.js')
const noise = await import('../../src/noise.js')
await import('../../src/wire.js')
await import('../../src/node.js')
const group = await import('../../src/group.js')

assert.equal(typeof key.generateIdentity, 'function')
assert.equal(typeof noise.initiator, 'function')
assert.equal(typeof group.createGroup, 'function', 'pairwise createGroup must load')

// sign.js + createSecureGroup are browser-build's incoming lane — they must at least IMPORT on the
// shim (i.e. the shim exports everything they pull from node:crypto). Logic is not exercised here.
if (typeof group.createSecureGroup === 'function') {
  const sign = await import('../../src/sign.js')
  assert.equal(typeof sign.signEd, 'function', 'src/sign.js must load on the shim (needs sign/verify)')
  // exercise sign/verify once through the real sign.js API to prove the shim path end-to-end
  const id = key.generateIdentity()
  const msg = ShimBuffer.from('group op')
  const sig = sign.signEd(id.edPriv, msg)
  assert.equal(sign.verifyEd(id.edPub, msg, sig), true, 'sign.js round-trips on the browser shim')
  assert.equal(sign.verifyEd(id.edPub, ShimBuffer.from('tampered'), sig), false, 'wrong msg -> false')
  console.log('  ✔ src/sign.js + createSecureGroup import + sign/verify round-trip on the browser shim')
} else {
  console.log('  ⏭ createSecureGroup not present yet (browser-build lane) — pairwise group only')
}

console.log('BROWSER-IMPORTS OK')
