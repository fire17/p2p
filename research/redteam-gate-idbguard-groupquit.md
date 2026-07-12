# Redteam CAG Gate — a00538d (IndexedDB boot guard) + fb95ee3 (p2p group Ctrl+C, #17)

> **Lane:** redteam / CAG-gate (opus @ xhigh). In-process only. The v0.3.2 batch (with d47a878 + ef3b414).

## Verdicts

| Commit | Item | Verdict |
|---|---|---|
| a00538d | guard IndexedDB + carry the failure reason on screen | **CONFIRMED-SHIP** (test-coverage gap noted) |
| fb95ee3 | p2p group Ctrl+C — the 4th/last unbounded-drain front-end | **CONFIRMED-SHIP** |

---

## a00538d — IndexedDB boot guard (worktree @ a00538d, parent 5756ad7)

**Angle (b) — the KEY RISK: does making storage-failure FATAL ever reject a LEGIT first-run? NO —
empirically confirmed.** The change removed the old `idbGet(k).catch(() => null)` (which minted a fresh
key on broken storage → the BRW-2-class "key that can't survive a reload" bug). The concern: an empty
store (a fresh user) must still mint, not be treated as a failure. It does, by IndexedDB semantics —
`objectStore.get(missingKey)` fires `onsuccess` with `result === undefined` (NOT `onerror`), so
`idbGet` RESOLVES `undefined`, `identity()`'s `if (saved)` is false, and it falls through to `create()`
→ mint. **My probe (a healthy fake IndexedDB, empty store):**
```
empty-store first-run → MINTED ✓ (a fresh user gets a key)
second call           → reuses the SAME persisted identity ✓
```
Only a genuine storage FAILURE (idb() rejects on: no indexedDB / open() throws (Safari private) /
onerror / onblocked / 5 s timeout) propagates as fatal, surfaced by app.js's boot catch. ✓

**Angle (a) — 5 s under 8 s ordering:** `IDB_TIMEOUT_MS = 5000` (src/browser/p2p.js:52) vs
boot-guard's `BOOT_MS = 8000`. On the real hang (`indexedDB.open` settling neither success nor error),
idb() rejects at 5 s → identity() throws → app.js writes the SPECIFIC reason to `#statusText` → at 8 s
boot-guard's `booted()` sees `statusText !== 'booting…'` and no-ops. The specific reason wins. ✓

**Angle (c) — `__p2pBooted` placement:** set once at `app.js:213` (the `going online…` point inside
main(), after identity() + listen()), NOT at module top — so it never silences the guard for a failure
that happens BEFORE the app is actually online. ✓

**My test output:** `browser-idb-guard.test.js` → **4/4** (no-IDB / open-throws / onblocked /
never-settles-timeout, each rejects with an actionable message, none hang).

**Test-coverage GAP (noted, not a blocker):** the suite covers only the 4 FAILURE modes; there is NO
automated "healthy empty store → mints" regression guard for angle (b) — the highest-risk change. It is
verified here by my probe + the lane's real-browser check (healthy boot silent). **Recommend** adding a
healthy-fake-IDB test asserting `identity()` mints on an empty store, so a future regression that turns
an empty read fatal would be caught.

---

## fb95ee3 — p2p group Ctrl+C (#17, the 4th front-end) (worktree @ fb95ee3, parent ef3b414)

Same class I gated 3× (ac9f36e, 7678417): teardown now `drainBounded(inflight, 300)` + `if (closing)
return finish(130)` + an `exiting` re-entry latch + raw-mode release + SIGTERM→143/SIGHUP→129.

**Gate angle — the fan-out: does the bounded drain cover group.send()'s fan-out (not just one dead
peer)?** Yes. `inflight` chains `inflight.then(() => send(text))`, and `send()` awaits `group.send(text)`
which fans out to EVERY member. If one member is dead its send never settles → `inflight` never settles
— but `drainBounded(inflight, 300)` races the WHOLE chain against 300 ms, so it resolves regardless of
member count or which/how-many members hang. drainBounded bounds `inflight` opaquely — a single
never-settling fan-out leg is bounded exactly like a single dead peer. The commit comment states it:
"a group makes it likelier still — group.send() fans out to every member, so ONE dead member is [enough]".
✓

**My verification:**
- `FRONTENDS = ['p2p.js', 'p2p-tui.js', 'p2p-chat.js', 'p2p-group.js']` — all four now under the tripwire.
- `grep "await inflight" bin/` → **comments only** (5 hits, every one an explanatory comment; no code).
- `quit-always.test.js` → **13/13**, incl. the three p2p-group.js asserts (drainBounded, 2nd-Ctrl-C
  force, re-entrancy + terminal release).
- **Mutation:** I reintroduced a real `await inflight` in p2p-group.js → the tripwire went **RED** on
  *"unbounded `await inflight` is back in p2p-group.js — a dead peer will hang Ctrl-C"* + *"must bound
  its shutdown drain"*. Restored → green. The 4th front-end is genuinely guarded now. ✓

---

## Standing-resident
Both CONFIRMED-SHIP. With d47a878 + ef3b414 this is the full v0.3.2 set. The unkillable-CLI class is now
closed across all 4 front-ends. One test-only follow-up recommended (a00538d healthy-empty-store mint
test). Resident.
