// test/browser-imports.test.js — the browser shim COVERS every shared protocol module.
//
// A regression guard on shim completeness (my lane, src/browser/shim/*): if any shared module —
// key/noise/wire/node/group/sign — starts importing a `node:crypto` function the shim doesn't
// export, the browser page would throw "does not provide an export named X" at load. This catches
// that in CI, in a child process (so overriding the global Buffer can't disturb the runner),
// against the browser stack. It deliberately does NOT test group/sign LOGIC — only that the
// modules import and that sign.js round-trips on the shim (its one node:crypto-heavy path).

import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))

test('every shared protocol module imports on the browser shim (shim-coverage regression guard)', () => {
  const out = execFileSync(process.execPath, [join(HERE, 'fixtures', 'browser-imports.mjs')], {
    encoding: 'utf8',
    timeout: 60_000,
  })
  assert.match(out, /BROWSER-IMPORTS OK/, 'a shared module imports a node:crypto export the shim lacks')
})
