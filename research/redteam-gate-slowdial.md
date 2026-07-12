# Redteam CAG Gate — ef3b414 (slow-dial: punch as soon as the relay is reachable)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Worktree @ ef3b414 (parent d47a878). In-process/mock-relay.
> Kills the ~13s TUI→browser dial (task #8 part 1). Files: node.js, compose.js, transport-node.js,
> interop-tui-web.test.js.

## Verdict: **CONFIRMED-SHIP.** No WAN tui↔tui regression; the pending-handover is load-bearing (proven
by mutation-hang); the trade-off is honest and bounded (one low-pri ticket recommended).

Root: `collectCandidates` blocked on the first rendezvous candidate with NO deadline; a browser publishes
none a TUI can punch, so the dial sat until the whole stream drained (~13s). Fix: a relay-capable
endpoint bounds the first-candidate wait (`RELAY_GRACE_MS=3000`); the stream is NOT abandoned at the
deadline — late UDP joins the same race via `compose.addLeg`.

## Angle 1 — WAN tui↔tui NOT regressed
The grace is opt-in BY CAPABILITY, not a global timeout: `graceMs = inv ? Infinity : (node._ep &&
node._ep.relayGraceMs) || Infinity`. Only a relay-capable composed endpoint sets `relayGraceMs=3000`; a
plain-UDP endpoint or invite mode ⇒ `Infinity` (the old blocking behaviour). A WAN tui↔tui pair publishes
UDP candidates that arrive well within 3 s, so the grace never fires and the relay is never dialled. The
test asserts it directly: *"tui↔tui: still connects over LOOPBACK UDP — and never touches the relay"* →
`assert.equal(relay.published, 0)` (interop line 142). The relay-floor case still holds (*"UDP dead ⇒ the
relay leg carries the dial"* asserts `relay.published > 0`). ✓

## Angle 2 — the pending-promise handover is load-bearing (mutation-proof)
Async generators QUEUE `next()`: if the deadline races `it.next()` and the code then RE-CALLS `it.next()`
in the drain, the in-flight (first, direct-UDP) candidate is swallowed — the naive-timeout footgun that
would silently drop the direct route. The fix HANDS the in-flight promise over:
`drainRest(it, cap, graceMs, pending)` awaits `firstLate = await (pending || it.next())`. **My mutation:**
I replaced `(pending || it.next())` with `it.next()` (drop the handover) → the test *"slow-dial: a LATE
udp candidate still races"* **HUNG → "test timed out after 8000ms"** (the direct UDP never joins, the
awaited message never arrives). Restored → green. So the handover genuinely carries the direct-UDP route. ✓

## Angle 3 — the trade-off (honest, bounded) — 3 s is sane; one ticket
The commit is explicit (node.js comment): discovery keeps running PAST the deadline and its late
candidates `addLeg` into the SAME race, so a slow-UDP peer is NOT condemned to relay-only. The residual
it flags: if the first UDP arrives >3 s AND the relay delivers the first real frame before UDP validates,
the composite commits to the relay (fast + correct, but a worse route; no relay→UDP migration is
attempted). Judgment: **3 s is sane** — a WAN UDP srflx candidate normally lands <1 s, so 3 s is generous
headroom; the only losers are genuinely slow/degraded paths, and even they still race (not abandoned).
The no-migration residual is a minor perf item, not a correctness bug — **recommend a LOW-PRIORITY ticket
for relay→UDP migration** (or a longer grace on WAN), not a blocker.

## My test output
`interop-tui-web.test.js` → **7/7 pass** incl. *"slow-dial: a peer that publishes NO candidates is dialed
WITHOUT waiting for the stream to drain"* and *"slow-dial: a LATE udp candidate still races — bounding the
wait does NOT cost the direct route"* (the one that hangs without the handover), plus the tui↔tui
`relay.published===0` and the GLARE 10/10.

## CAG §6
1. Closes the ~13s tui→browser dial. 2. New parts: bounded first-wait + drainRest + addLeg — enumerated,
   each `unref`'d/cleared. 3. Not weaker (UDP still preferred; relay is the floor). 4. Reliability:
   tui↔tui unchanged (relay.published===0), tui↔browser now fast. 5. Degenerate-safe: Infinity default =
   old behaviour. 6. interop tests are the monitor (late-races bites — proven). 7. Reversible. 8. Reuses
   compose/addLeg — minimal.

## Standing-resident
ef3b414 CONFIRMED-SHIP. Recommend a low-pri relay→UDP-migration ticket for the honest no-migration
residual. Resident.
