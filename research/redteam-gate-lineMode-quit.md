# Redteam CAG Gate — 7678417 (p2p connect/chat lineMode Ctrl+C-always-exit)

> **Lane:** redteam / CAG-gate (opus @ xhigh). In-process only. Worktree @ 7678417 (parent 35132da).
> Completes the ac9f36e Ctrl+C-always-exit fix on `bin/p2p.js lineMode` — the `p2p connect <key>` /
> `p2p chat <key>` path the owner runs most. CLI-only. Files: bin/p2p.js (:124-150), quit-always.test.js.

## Verdict: **CONFIRMED-SHIP.** All four angles verified, tripwire bites (my own mutation).

Same bug class as ac9f36e: `peer.send()` resolves only on ACK, so a dead-peer send never settles; the
old `if (closing) return; closing = true; await inflight` hung the 1st Ctrl+C and swallowed retries.

## Angle 1 — a never-settling send cannot trap the exit
`shutdown()` awaits `drainBounded(inflight, 300)` (bounded — verified in the ac9f36e gate: timer NOT
unref'd, clearTimeout both tails) then `finish(0)`; a SECOND Ctrl+C hits `if (closing) return
finish(130)` and waits on NOTHING. quit-always.test.js: *"a never-settling send (dead peer) cannot trap
the exit path"* runs `drainBounded(new Promise(()=>{}), 50)` — resolves or the suite times out. ✓

## Angle 2 — the re-entrancy latch cannot hijack the exit code or wedge
Traced: 1st Ctrl+C → `shutdown` → `drainBounded` → `finish(0)` sets `exiting = true`, then `node.close()`,
then `rl.close()` which SYNCHRONOUSLY re-emits `'close'` → the `rl.on('close')` handler → `shutdown()` →
`if (closing) return finish(130)` → `finish(130)` hits `if (exiting) return` → **no-op**. Control unwinds
to the original `finish(0)` → `setRawMode(false)` → `process.exit(0)`. The graceful code 0 stands; the
re-entrant 130 is discarded. The latch cannot wedge: `finish()` is fully SYNCHRONOUS (no `await` between
`exiting = true` and `process.exit`), so there is nothing to hang on. quit-always asserts the latch
present (`/if \(exiting\) return/`). ✓

## Angle 3 — the 2nd-Ctrl+C force path is defensively correct (not live-triggerable)
The commit is HONEST that the force path did not fire in the live PTY run — because the 1st Ctrl+C now
exits within the 300 ms bounded drain, so a user never needs the 2nd press. The force path only engages
against a genuinely never-settling send that outlives the drain — which `drainBounded` makes impossible
in normal operation. It is a belt-and-braces path, covered by the unit (`new Promise(()=>{})`) + the
tripwire, not by a live run. The reasoning is sound: you cannot live-trigger a path that the bounded
drain has already made unreachable. ✓

## Angle 4 — the source tripwire bites (my own mutation)
`quit-always.test.js` scans each front-end (p2p.js, p2p-tui.js, p2p-chat.js) via `codeLines` (strips
comment lines, so the explanatory "`await inflight`" comment in the fixed p2p.js does NOT false-trigger —
confirmed: the intact suite is 9/9) for: (a) NO unbounded `await inflight`; (b) presence of
`drainBounded(inflight`; and for p2p.js specifically the swallowing guard `if (closing) return; closing =
true` is ABSENT and `if (closing) return finish(130)` + `if (exiting) return` are PRESENT.
**My mutation:** replaced `drainBounded(inflight, 300)` with a real `await inflight` in p2p.js → the
tripwire went **RED** on two assertions (*"unbounded `await inflight` is back … a dead peer will hang
Ctrl-C"* + *"must bound its shutdown drain"*). Restored → green. The guard genuinely bites on a
regression. ✓

## My test output
`quit-always.test.js` → **9/9 pass** (bounded-drain property + per-file anti-pattern/require tripwires +
the p2p.js 2nd-Ctrl+C + re-entrancy assertions). node --check bin/p2p.js OK.

## Honest residual (commit-flagged, I concur)
`bin/p2p-group.js:226` STILL carries the same unbounded `await inflight` (the 4th front-end) — the
`p2p group` command remains unkillable-prone. It belongs to the tui-group lane (task #17), reported not
touched here; the tripwire deliberately does NOT scan p2p-group.js yet (so it stays green while #17 is
open — a documented gap). Recommend adding p2p-group.js to the tripwire list once #17 lands.

## CAG §6
1. Closes the unkillable `p2p connect`/`p2p chat` (the owner's most-used command). 2. New parts: bounded
drain + `finish` latch — enumerated, both synchronous-exit. 3. Not weaker. 4. Reliability: a landing ack
still gets 300 ms; a dead peer no longer hangs. 5. Degenerate-safe (2nd Ctrl+C = immediate). 6. Monitor =
quit-always.test.js (bites, proven). 7. Reversible, CLI-only. 8. Reuses drainBounded — minimal.

## Standing-resident
7678417 CONFIRMED-SHIP. 3 of 4 front-ends now safe; p2p-group.js (#17) is the last, correctly scoped
out. Resident.
