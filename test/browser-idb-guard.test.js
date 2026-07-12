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
//
// And the mirror image, which matters just as much: identity() is now FATAL on a storage failure
// (it used to swallow the read error and mint a keypair on top of broken storage — a key that could
// not survive a reload). The risk in that change is over-reach: an EMPTY store is not a failure, it
// is every user's first run. So the last two tests hold that line — a healthy, empty IndexedDB must
// still MINT, and the next call must REUSE what it minted. If someone ever makes an empty read fatal,
// every new user is locked out, and these fail.

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

/**
 * A HEALTHY IndexedDB, in memory: the happy path every first-run user takes. Async like the real one
 * (requests settle on a later tick), so the code under test is exercised through its real callbacks.
 * @param {Map} records the backing store — inspect it after, to see what was actually persisted
 */
function healthyIndexedDB(records = new Map()) {
  const later = (fn) => setTimeout(fn, 0)
  const db = {
    transaction() {
      const tx = { error: null, oncomplete: null, onerror: null }
      const req = (compute) => {
        const r = { transaction: tx, result: undefined, onsuccess: null, onerror: null }
        later(() => { r.result = compute(); r.onsuccess && r.onsuccess(); tx.oncomplete && tx.oncomplete() })
        return r
      }
      tx.objectStore = () => ({
        get: (k) => req(() => records.get(k)),
        put: (v, k) => req(() => records.set(k, v)),
        getAllKeys: () => req(() => [...records.keys()]),
        getAll: () => req(() => [...records.values()]),
      })
      return tx
    },
  }
  return { records, open() { const r = { result: db, onsuccess: null }; later(() => r.onsuccess && r.onsuccess()); return r } }
}

test('healthy but EMPTY store (every user\'s first run) → MINTS a key and persists it', async () => {
  const fake = healthyIndexedDB()
  await withIndexedDB(fake, async () => {
    const id = await identity({ slot: 'first-run' })
    assert.equal(typeof id.S, 'string')
    assert.equal(id.S.length, 26, 'a fresh first run must produce a real 26-char contact key')
    assert.equal(id.xPriv.length, 32)
    assert.equal(id.edPriv.length, 32)
    // …and it must be SAVED, or the user loses the key they are about to share.
    const saved = fake.records.get('id:first-run')
    assert.ok(saved, 'the minted identity was not written to storage')
    assert.equal(saved.S, id.S)
    assert.equal(saved.slot, 'first-run')
  })
})

test('a second call REUSES the stored identity — it does not mint a new one', async () => {
  const fake = healthyIndexedDB()
  await withIndexedDB(fake, async () => {
    const first = await identity({ slot: 'returning' })
    const second = await identity({ slot: 'returning' })
    assert.equal(second.S, first.S, 'the key changed under the user between two loads')
    assert.equal(fake.records.size, 1, 'a second record was written — the identity was re-minted')
    // The reload path goes through hydrate(), which re-verifies the commitment. Same keys, or the
    // stored record did not really round-trip.
    assert.equal(Buffer.from(second.edPub).toString('hex'), Buffer.from(first.edPub).toString('hex'))
    assert.equal(Buffer.from(second.xPriv).toString('hex'), Buffer.from(first.xPriv).toString('hex'))
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
