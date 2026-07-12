# Redteam CAG Gate — b5d8d88 (single-live identity + auto-adopt — kill the zombie tab)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Analysis + verification only.
> **Date:** 2026-07-12. **Isolation:** clean detached worktree @ b5d8d88 (parent abe112b).
> **Constraint honored:** in-process (real key/noise/wire + mock MQTT relay) only — no mDNS/LAN/live
> browser. Files: `src/browser/p2p.js`, `src/browser/app.js`, `test/browser-duplicate-identity.test.js`
> (no node.js/transport). This is the web↔web "50%" root cause; gates the dev.6 bump.

## Verdict: **CONFIRMED-SHIP.** The critical FAILS-OPEN requirement holds (verified by my own probe).

Root cause (reproduced in-test): two no-`#id` tabs both boot the `default` slot → same static keypair →
both subscribe HKDF(S) → both complete a REAL Noise IK on one dial → dialer binds the first responder,
the other tab is a CONNECTED-but-silent zombie; messages land in the wrong tab ⇒ ~50% loss. The protocol
can't refuse it (both are cryptographically legitimate), so the browser must.

## Gate angle 1 — FAILS OPEN (critical) · VERIFIED by my own probe

The guard catches a footgun; it must NEVER be why a legit user can't come online. `claimIdentity(S,
locks)` returns a `{held:true}` sentinel on EVERY LockManager failure path; only a genuine
`ifAvailable` `lock===null` (the identity is live in another tab) returns `{held:false}`. My probe with
injected LockManagers:
```
absent navigator.locks    → held=true  (ONLINE) ✓
request not a function     → held=true  (ONLINE) ✓
request throws sync        → held=true  (ONLINE) ✓   (the `catch { resolve(free) }`)
request rejects async      → held=true  (ONLINE) ✓   (the `.catch(() => resolve(free))`)
lock held by other tab     → held=false (refused)     ← the ONLY refuse — a real duplicate
lock granted               → held=true  (ONLINE) ✓
```
A fail-CLOSED here would be worse than the zombie; it does not exist. `ifAvailable:true` also means the
request never QUEUES/blocks — a duplicate resolves instantly to `null`, not a hang. ✓

## Gate angle 4 — per-S, not a global mutex · VERIFIED by probe

The lock name is `'p2p-live-' + S`. My probe: two DIFFERENT identities (A, B) under a granting
LockManager both get `held=true` — different S ⇒ different lock ⇒ both online. Not serialized. ✓

## Gate angle 2 — lock lifecycle (no permanent brick)

The lock is held by the `ifAvailable` callback's returned `parked` promise; `lease.release()` resolves
it. `node.close` is wrapped to call `t.close()` + `lease.release()` — so `node.close()` frees the
identity (test: "closing the holding tab frees the identity for the next one" ✓). On a tab crash/refresh
the page context is destroyed and the Web Locks spec auto-releases any lock the page held — so a stale
lock cannot brick the same user's next session. (Real-crash auto-release is the browser's guarantee, not
exercisable in node — see the honest GAP; the in-process test covers the explicit-release path.)

## Gate angle 3 — auto-adopt races (self-healing, no zombie recurrence)

On `listen()` throwing `reason:'identity-live'` AND the slot was NOT named in the URL, app.js
auto-adopts: `nextFreeSlot()` → `location.hash='id='+next` → reload. Two tabs racing CAN compute the
same `nextFreeSlot` (the pick is not atomic), BUT after reload each runs `claimIdentity(S_slot)` on the
adopted slot — the atomic gate — so exactly one wins and the loser is refused again and re-adopts the
NEXT free slot. `nextFreeSlot` is monotonic (the winner persists its slot, so the loser's next pick is
higher), so the loop terminates; the zombie CANNOT recur because the lock refuses the duplicate BEFORE
any socket opens. A named-slot tab (`slotWasAskedFor`) gets the error text instead — it meant that slot.
Self-healing, as designed. ✓

## Gate angle 5 — own-key guard untouched + sound

The diff does not touch the own-key guard (`git diff` for it is empty). At b5d8d88 it is intact at
`app.js:281` — `if (myKey && S === myKey) { say(...); return }` — a string compare to this tab's key
that refuses a self-dial before any network, as gated in 90e5bfd. ✓

## My test output
```
browser-duplicate-identity.test.js  — claimIdentity first-holds/second-refused · closing-holder-frees ·
  FAILS OPEN (no/throwing Web Locks) · UNGUARDED duplicate = both connect, one receives (the zombie, RED)
+ browser-imports/shim/mitm/noise-parity/raced-transport/webrtc-hardening (deterministic subset)
  → 31/31 pass, 0 fail
node --check src/browser/app.js + p2p.js → syntax OK
```
The "UNGUARDED duplicate identity" test is the RED (reproduces the zombie at the protocol layer — both
tabs complete a real Noise IK, exactly one receives); the `claimIdentity` tests are the GREEN guard.

## CAG §6
1. **Residual-closed:** the web↔web "50%" zombie (a same-identity second tab silently eating half the
   messages) — an identity is now ONLINE in exactly one tab. Quantified: two→one live responder per S.
2. **Attack-surface:** new parts = the Web Lock + auto-adopt loop. Neither is remotely triggerable (both
   are same-origin, same-user tab lifecycle); no network surface. Enumerated.
3. **Weakest-link:** unchanged — Noise IK/commitment is still the boundary; this is a local dedup.
4. **Reliability:** fails open on every LockManager fault (proven) — reliability is strictly preserved;
   the only refusal is a genuine duplicate, which auto-adopts into a second peer (better UX, not worse).
5. **Degenerate-safe:** no Web Locks ⇒ old behavior (online), exactly v0.1.0-equivalent for a single tab.
6. **Monitor:** browser-duplicate-identity.test.js (RED + guard) is the standing assertion.
7. **Reversible:** browser-only; node/transport untouched; no wire change.
8. **Simplicity:** one Web Lock + a shared `nextFreeSlot` (de-duped with ＋New). Minimal.

## Honest GAP (lane-flagged, I concur — UNVERIFIED, not run)
app.js's Web-Locks path is unit-tested with an INJECTED LockManager, not a real browser. A real two-tab
Chrome run (two tabs, same origin/storage, real `navigator.locks`) is NOT exercised here — and per the
owner-live-testing constraint I did NOT run the Playwright/browser paths. `browser-identity.test.js`
(Playwright, two isolated CONTEXTS ⇒ distinct lock managers) is stated unaffected but not re-run.
Recommended post-bump confirmation: two real tabs on the default identity → the second becomes a distinct
second peer, no zombie. The in-process protocol-layer RED + the injected-LockManager fails-open matrix
are strong evidence; the real-browser pass is the last mile.

## Standing-resident
b5d8d88 clear to ship (the web↔web zombie root cause). Resident.
