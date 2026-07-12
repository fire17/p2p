// test/browser-idb-guard.test.js — a browser that will not open IndexedDB must FAIL LOUDLY, not hang.
//
// The identity lives in IndexedDB, so identity() is the first thing the browser awaits at boot. On a
// phone that is the most fragile step in the whole chain: private browsing (and "block all cookies")
// can make `indexedDB.open` throw, or settle NEITHER onsuccess NOR onerror, and `onblocked` fires
// whenever another tab is still holding an older version of the database. Any of those used to hang
// the boot forever behind a page that just said "booting…" — nothing on screen, nothing in the console.
//
// So each of those four cases gets a test: they must REJECT, with a message a human can act on.
// (test/browser-deploy.test.js covers the other silent killer — a module the server never serves.)

import test from 'node:test'
import assert from 'node:assert/strict'
import { identity } from '../src/browser/p2p.js'

/** Swap in a fake IndexedDB for one test, always putting the real global back. */
async function withIndexedDB(fake, fn) {
  const had = Object.prototype.hasOwnProperty.call(globalThis, 'indexedDB')
  const prev = globalThis.indexedDB
  globalThis.indexedDB = fake
  try { await fn() } finally {
    if (had) globalThis.indexedDB = prev
    else delete globalThis.indexedDB
  }
}

/** An open() request that fires `event` on the next tick — or, with 'never', not at all. */
const opener = (event) => ({
  open() {
    const req = { result: null, error: new Error('nope') }
    if (event !== 'never') {
      setTimeout(() => {
        if (event === 'error') req.onerror && req.onerror()
        if (event === 'blocked') req.onblocked && req.onblocked()
      }, 0)
    }
    return req
  },
})

test('no IndexedDB at all (storage disabled) → rejects with an actionable message', async () => {
  await withIndexedDB(undefined, async () => {
    await assert.rejects(identity({ slot: 'idb-none' }), /blocking storage/i)
  })
})

test('indexedDB.open() THROWS (Safari private mode SecurityError) → rejects, does not hang', async () => {
  const throwing = { open() { throw Object.assign(new Error('The operation is insecure.'), { name: 'SecurityError' }) } }
  await withIndexedDB(throwing, async () => {
    await assert.rejects(identity({ slot: 'idb-throw' }), /blocking storage.*insecure/is)
  })
})

test('onblocked (another tab holds an older DB version) → rejects, naming the other tabs', async () => {
  await withIndexedDB(opener('blocked'), async () => {
    await assert.rejects(identity({ slot: 'idb-blocked' }), /another tab/i)
  })
})

test('open() that NEVER settles (the real mobile hang) → times out and rejects', async (t) => {
  // THE bug this guard exists for: no success, no error, no block — just silence. Before the guard,
  // identity() awaited that forever and the page said "booting…" until the user gave up.
  t.mock.timers.enable({ apis: ['setTimeout'] })
  await withIndexedDB(opener('never'), async () => {
    const pending = identity({ slot: 'idb-silent' })
    t.mock.timers.tick(5000) // the guard's timeout
    await assert.rejects(pending, /never responded/i)
  })
})
