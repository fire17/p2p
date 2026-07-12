// test/fixtures/shim-hooks.mjs — module-resolution hooks that make Node load our protocol
// source the way a BROWSER would: `node:crypto` inside src/ resolves to the browser shim.
//
// Scoped deliberately: only imports coming FROM src/ (and not from src/browser/ itself, which
// legitimately has no node:crypto imports) get redirected. The test runner, node internals and
// the test files themselves keep the real node:crypto — that's what we compare against.

import { pathToFileURL } from 'node:url'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const SHIM = pathToFileURL(join(HERE, '..', '..', 'src', 'browser', 'shim', 'node-crypto.js')).href

export async function resolve(specifier, context, nextResolve) {
  if ((specifier === 'node:crypto' || specifier === 'crypto') && context.parentURL) {
    const parent = context.parentURL
    if (parent.includes('/src/') && !parent.includes('/src/browser/')) {
      return { url: SHIM, shortCircuit: true }
    }
  }
  return nextResolve(specifier, context)
}
