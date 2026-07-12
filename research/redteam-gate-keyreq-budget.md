# Redteam CAG Gate — 0124a16 (unify KEYREQ budget + refresh on reconnect)

> **Lane:** redteam / CAG-gate (opus @ xhigh). In-process only. Worktree @ 0124a16 (parent d1ccf66).
> Task #18 turned out NOT test-only: strengthening the KEYREQ-storm test (per my own d2d6c0c
> weak-guard finding) EXPOSED a real leak in the shipped group.js. Queues for the next reship;
> prod (d2d6c0c) is bounded-but-imperfect (worst case 9 not 8, no crash) — LOW severity, no hotfix.

## Verdict: **CONFIRMED-SHIP.** The 1+MAX leak is closed; the refresh is exhausted-gated and its
reconnect-amplification is bounded (handshake-rate-limited, self-directed) — not a new DOS.

## The closed loop (my d2d6c0c finding → here)
In the d2d6c0c gate I flagged that its BOUND-1 assertion did NOT reproduce the storm (the test allowed
A's KEYREQ send, so `pulling` dedup kept `keyreqs≈1`). Strengthening it (#18) — forcing A's KEYREQ to
`reject` (D unreachable) so `pulling` clears and every dropped message re-asks — made the storm real AND
uncovered a genuine leak: `pullKeys()` fired its OWN KEYREQ OUTSIDE the `MAX_KEYREQ` budget, so the true
worst case was `1 + MAX_KEYREQ` — two separately-"bounded" paths whose SUM wasn't bounded.

## Angle 2 — is the SUM now bounded at MAX_KEYREQ across BOTH paths? (not a strawman)
`pullKeys()` now routes every request through `requestKey(S)` (`for (const S of …) requestKey(S)`), so
both the ingest-triggered and the pull-triggered paths share the ONE `keyReqs` budget. The test drives
it for real (its send interceptor now returns `'reject'` for KEYREQ — a genuine unreachable-peer
failure, the send-failure path the old test never created). **My RED→GREEN:**
```
RED  @parent d1ccf66 (shipped): "a missing key must cost ≤8 KEYREQs … attempted 9 for 60 messages"
GREEN @0124a16                 : ≤8 (the pull is routed through the shared budget)
```
So the strengthened guard genuinely bites, and the fix bounds the sum. ✓

## Angle 1 (PRIORITY) — can refresh-on-reconnect be exploited to RE-STORM? No.
`refreshBudget(peer)` on `'peer'`/`'reconnect'`:
```
S = peer.key || peer.S
if (!S || recvChains.has(S)) return                 // we already have their key — nothing to refresh
if ((keyReqs.get(S) || 0) < MAX_KEYREQ) return      // still mid-budget — NOT a new chance
keyReqs.delete(S); pulling.delete(S)                // only an EXHAUSTED budget is refreshed
```
- **Exhausted-only gate** prevents the mid-episode double-budget: our own `connect()` fires `'peer'`
  mid-episode, and an UNCONDITIONAL reset would have handed a 2nd budget while the 1st was still spending
  (that is the 1+8=9 the strengthened test caught) — the `< MAX_KEYREQ` guard blocks it.
- **Reconnect amplification is bounded, not a DOS:** a flapping member earns a fresh 8-budget only when
  it reconnects AND we still lack its key. Each reconnect is a FULL Noise handshake (we initiate or
  accept), so the rate is handshake-limited, not free. The 8 KEYREQs are SELF-DIRECTED — sent to the
  reconnecting member, asking for THEIR key — so there is no third-party reflection/amplification, and a
  member that simply delivers its key (`recvChains.has(S)` true) ends it immediately. Cost is linear in
  reconnects (8×N) and each N costs the attacker a handshake. Acceptable — a reliability win (a genuinely
  reconnected member is re-pulled instead of permanently given up) with bounded, self-directed cost.

## Angle 3 — no regression
`group-keydist.test.js + group-secure.test.js` → **17/17** (GRP-1..5 forged-authorship / blind-relay /
cryptographic-removal intact + the cannot-dial-back / self-heal / 10-run suite). (Lane's broader run: 52/52.)

## CAG §6
1. Closes the 1+MAX KEYREQ sum + the permanent-give-up-after-reconnect gap. 2. New part: one
   exhausted-gated refresh listener — enumerated; amplification bounded (above). 3. Not weaker (the sum
   is now genuinely one budget). 4. Reliability: a reconnected member is re-pulled. 5. Degenerate-safe.
   6. The strengthened storm test IS the monitor — and it bites (RED@parent "attempted 9"). 7. Reversible.
   8. Reuses requestKey — removes a duplicate path (simpler + correct).

## Standing-resident
0124a16 CONFIRMED-SHIP; queues for the next reship (prod is low-severity bounded meanwhile). This closes
the KEYREQ-budget thread my d2d6c0c gate opened. Resident.
