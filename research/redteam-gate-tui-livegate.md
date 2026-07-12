# Redteam CAG Gate — ac9f36e (TUI exit UX) + 170bc0b/3c45a0a (live-test gating)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Analysis + verification only.
> **Date:** 2026-07-12. **Isolation:** clean worktree @ ac9f36e. In-process only; **no live test run.**
> Batches into dev.7.

## Verdicts

| Commit | Item | Verdict |
|---|---|---|
| ac9f36e | TUI Ctrl+C-always-exit + ↑↓ history + scroll | **CONFIRMED-SHIP** |
| 170bc0b | gate every real-network test behind P2P_LIVE | **CONFIRMED-SHIP** (audit-scope limitation flagged) |
| 3c45a0a | doc: `npm run test:live` | **CONFIRMED-SHIP** (chore) |

---

## ac9f36e — TUI exit UX

**Angle 1 — can forceExit EVER be trapped by a never-settling promise? NO.** `forceExit()` is fully
synchronous: `restoreTerminal()` (all try/catch, no await), `state.node?.close?.()` (best-effort,
try/catch), `process.exit(code)`. It **awaits nothing**, so a `peer.send()` promise that never settles
(resolves only on ACK vs a dead peer — src/node.js) cannot trap it. The old bug was `quit()` doing
`await inflight` behind an `if (quitting) return` guard that swallowed retries — gone. tui-ux.test.js
proves it: *"drainBounded: a NEVER-settling send cannot trap the exit path"* reproduces the hang with a
`new Promise(()=>{})` and confirms teardown still completes. ✓
**Angle 2 — drainBounded correctness.** `Promise.race([p.catch(()=>{}), setTimeout(r, ms)])` with the
timer **deliberately NOT unref'd** (an unref'd timer would let the loop drain out from under a
never-settling `p` — the exact case it exists to survive) and `clearTimeout(t)` in BOTH race tails (so
it never holds the process open once resolved). The lane's self-caught unref bug is fixed. Tests:
never-settling bounded to ~300 ms; a rejecting send doesn't throw out of teardown; a landing send is
awaited, not delayed. ✓
**Angle 3 — data-loss split is sane.** Ctrl+C / Ctrl+D (raw byte `0x03`/`0x04`, caught AHEAD of every
other path at :178/:182 — no reliance on SIGINT, which raw mode suppresses) → immediate `forceExit`
(abort, no drain) — what a user hitting Ctrl+C expects. `/quit` → `drainBounded(inflight, 300)` (a
bounded best-effort flush) then exit. Abort-now vs bounded-drain is the right division. ✓
**Angle 4 — crash handler is correct, not masking.** `uncaughtException` + `unhandledRejection` both
`restoreTerminal()` → `console.error('p2p-tui crashed: '+msg)` → `process.exit(1)`. For a raw-mode/alt-
screen TUI this is the RIGHT behavior: without it a crash leaves the shell wrecked. It SURFACES the
error (not swallowed) and exits nonzero. (Minor: prints `e.message`, not the full stack — a small
debuggability tradeoff, not dangerous.) ✓ SIGINT→130/SIGTERM→143/SIGHUP→129 all route to forceExit.

**My test output:** `tui-ux.test.js` → **12/12 pass** (forceExit never-trapped, drainBounded ×3, 0x03/
0x04 forced-quit, + history/scroll). **CONFIRMED-SHIP.**

---

## 170bc0b + 3c45a0a — live-test gating (+ two leaks it closed)

`test/live-gate.mjs`: `liveOnly` (a node:test skip-options object unless `P2P_LIVE=1`) and
`skipLiveScript(name)` (standalone harnesses exit early ONLY under the auto-runner, keyed on
`NODE_TEST_CONTEXT`, so hand-runs still work). Two real leaks it found+closed:
- **werift-tui-e2e.mjs** auto-dialled REAL public trackers on every `npm test` (node --test runs every
  .mjs; its default mode is `selftest`). Now `if (skipLiveScript('werift-tui-e2e.mjs')) process.exit(0)`
  at line 25 — verified present. (My own earlier hand-runs of this harness still work: no
  NODE_TEST_CONTEXT ⇒ not skipped — consistent.)
- **transport.test.js:206** punched TEST-NET-3 `203.0.113.1` and a real SYN left the box (the
  "unroutable on the internet ≠ no packet leaves" trap). Now `{proto:'udp4', ip:'127.0.0.1', port:1}` —
  a closed LOOPBACK port. Coverage is IDENTICAL (nothing validates → UDP times out → TCP fallback
  refused → `punch` rejects) with **zero external bytes**. Verified the candidate line + the reject. ✓

**My verification (no live test run):**
- `live-gate.test.js` → **3/3**: the flip is proven against a NO-OP probe fixture
  (`fixtures/live-gate-probe.mjs`, an empty `liveOnly` test — confirmed it touches no socket), so the
  flag is proven WITHOUT emitting real traffic (P2P_LIVE off ⇒ `skipped 1/pass 0`; on ⇒ `pass 1`).
- **AUDIT tripwire — does it bite? Partly, and here is the honest scope (angle 1):**
  - **Gate REMOVED from a KNOWN file → YES, it bites.** I stripped `liveOnly` from mdns.test.js's LIVE
    test and ran only the AUDIT (a static source scan — no live test executed): it went **RED**
    (*"mdns.test.js reaches real LAN multicast — it MUST keep its live gate"*). Proven.
  - **A brand-NEW ungated real-network FILE → NO, it escapes.** The audit is a **hardcoded whitelist**
    (`const gated = [7 entries]`; the loop reads only those files — no `readdirSync`/glob/pattern-scan
    of `test/`). A new `test/whatever.test.js` that binds real multicast or dials a public host without
    the gate would NOT be caught until someone manually adds it to the list. So the audit is a strong
    REGRESSION guard for today's known live tests, not a DISCOVERY guard for future ones.

**Judgment: CONFIRMED-SHIP with the audit-scope limitation flagged (not FIX-FIRST).** The mechanism is
sound and proven; the two real leaks are closed; the audit covers every real-network test that exists
today and bites on the most likely failure (an existing gate being dropped). The residual — a NEW
ungated file escaping — is a real but bounded gap. **Recommend (follow-up):** replace the whitelist with
a `readdirSync('test')` sweep that flags any file matching real-network signatures (`224.0.0.251`,
`stun:`/`stun.`, known tracker/relay hosts, `dht`, a non-loopback `dgram` bind) and lacks a
`live-gate.mjs` reference — so a new ungated test fails the audit automatically. Loopback-only binds
staying ungated is the correct call (binding ≠ traffic).

**CAG §6 (live-gate):** (1) closes real off-box traffic from `node --test` (werift dial + the TEST-NET-3
SYN) — the exact pollution that bit the owner's live session; (2) surface = two tiny gate helpers +
env flag; (3) not weaker; (5) `P2P_LIVE=1` restores full coverage (degenerate-safe for CI); (6) the
AUDIT + flip tests are the monitor — with the whitelist caveat above; (7) reversible; (8) minimal.

---

## Standing-resident
ac9f36e + 170bc0b + 3c45a0a clear for dev.7. The live-gate audit-scope limitation is flagged for a
follow-up (directory-sweep audit); it does not block — the mechanism works and today's leaks are closed.
A 4th commit (bin/p2p.js lineMode Ctrl+C, task #12) is inbound; I'll gate it fresh. Resident.
