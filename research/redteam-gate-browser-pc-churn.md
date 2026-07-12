# Redteam CAG Gate — c43d647 (BRW-4b: real-browser RTCPeerConnection churn)

> **Lane:** redteam / CAG-gate (opus @ xhigh). This closes the exact axis my werift-only BRW-4 gate
> structurally could not see (see `redteam-gate-brw-dos-wss.md` §werift blind spot). Analysis + verify only.
> **Date:** 2026-07-12. **Commit:** `c43d647` — `src/browser/webrtc.js` + browser tests only. Parent `b9b6819`.
> **Isolation:** clean detached worktree @ c43d647.

## Verdict: **CONFIRMED-SHIP.** No DEVIATION, no open GAP.

The fix is proven on a REAL browser (Chromium 141 via Playwright): RED reproduces the owner's crash,
GREEN eliminates it, connectivity intact. With b9b6819, this is v0.3.0-dev.2.

## The hard gate — a REAL Chromium soak (my own runs)

`test/browser-pc-soak.mjs` is genuinely a browser, not werift: it wraps the page's REAL
`window.RTCPeerConnection` with a `CountingPC extends Real` and the cap error is a real Blink throw.
Phase A accelerates the clocks 200× (90 s ≈ 5 h of real listening), fake in-page tracker bus, no network.

**GREEN @ c43d647:**
```
construction curve : 6 → 12 over ~5.0 h modeled   (FLAT — reuse working)
cumulative built   : 12   (≈ 0.0/min real)        peak live 12 (cap 24)   live after close: 0
dialer             : CONNECTED in 27ms  (to an ICE-restarted, aged parked offer — real ICE + DataChannel)
listener accepted  : 3      PC-cap errors: none
✔ PHASE A PASSED — bounded PCs, no cap error, dialer still connects
```

**RED @ parent b9b6819 (revert only `webrtc.js`, same soak):**
```
t=1s created=240 live=88 parked=64      t=3s created=500 live=0 parked=0
PC-cap errors: Failed to construct 'RTCPeerConnection': Cannot create so many PeerConnections   (×3)
rate 155.9/s accelerated (≈46.8/min real)   peak live 100   dialer: not run   accepted: 0
✖ BROWSER PC-SOAK FAILED
```
The old per-announce code slams Chromium's ~500-CONSTRUCTION wall in ~3 s accelerated (≈10 min real) —
**exactly the owner's `Cannot create so many PeerConnections` / stuck-at-booting bug, reproduced.** The
fix flips it to 12 flat constructions with the dialer still connecting. My werift BRW-4 gate could never
have surfaced this (werift has no per-page PC cap); a real browser does. **Blind spot closed.**

## iceRestart re-offer correctness

The soak's mid-soak dial (after the pool has cycled for a modeled hour) **connected in 27 ms to an
aged offer** — proving `reoffer()`'s `createOffer({iceRestart:true})` on the SAME pc still produces a
completable offer with real ICE + a real DataChannel. Independently, `werift-tui-e2e selftest` → **PASS**
(iceRestart re-offer works with the werift PC too; node↔node over real trackers, Noise IK, bidirectional).

## Regressions (my own runs, standalone to avoid the parallel-load werift flake)

```
werift-tui-e2e selftest    ✔ PASS  (real DataChannel, Noise IK, both established, peer.key===S)
browser-e2e (Playwright)   ✔ PASS  (G2 tracker rendezvous + G3 WebRTC + Noise IK; DATA+ACK both ways)
browser-group-ui (Playwright) ✔ PASS  (create + add + join + chat via the shipped /app/ buttons —
                                       the group flow the churn was ALSO breaking)
browser deterministic *.test.js  33/33  (incl. the rewritten BRW-4b reuse-invariant test + BRW-5)
```
The rewritten `browser-webrtc-hardening.test.js` BRW-4b test asserts the **reuse invariant**:
`created1 === created2` and `created2 ≤ 12` while `announces > 60` — constructions track the pool, NOT
the announce cycles (the deterministic, werift-fake mirror of the real soak). BRW-5 unchanged.
(Full deterministic glob was finalizing at write time; the browser subset above is the changed surface —
`webrtc.js` is the only source touched, node/wire/group/transport untouched.)

## Escalation — MAX_OFFERS_PER_PUNCH=3: **BLESSED**

A dial answers at most 3 parked offers in parallel. Right balance: ≥2 spares so a dead/stale parked pc
doesn't strand the dial (real ICE, one offer usually suffices), yet bounded so a hostile/duplicating
tracker can neither flood the dialer with answerer PCs nor make one dialer open a burst of connections.
Every racing-but-lost answerer is freed on connect (`dialPcs` minus winner → `freePc`), so even 3 is
transient — no per-dial leak. Accept 3.

## CAG §6

1. **Residual-closed (quantified):** the real-browser cumulative RTCPeerConnection wall (~500/page,
   `close()` does NOT decrement — only an Oilpan GC a page can't trigger does). Old listener minted 4
   PCs × 3 trackers / 10 s ≈ 72/min → wall in ~7 min (the owner's live crash). New: idle steady-state
   **0/hour**; constructions track real CONNECTIONS (a pc is built only to refill a CONSUMED slot).
   Phase B (shipped `/app/` on the real trackers) measured ~4/min vs the old ~72/min.
2. **Attack-surface enumeration:** new parts = reused pool/slot, `reoffer(iceRestart)`, construction
   token bucket (burst 12, 6/min), hard caps `MAX_LIVE_PCS=32` / `MAX_TOTAL_PCS=480`, `MAX_OFFERS_PER_PUNCH=3`,
   `freePc` handler-nulling. Adversaries: (a) answer-spam forcing refills → rated token bucket + caps;
   (b) hostile tracker raining offers at a dialer → `MAX_OFFERS_PER_PUNCH`; (c) construction past the
   wall → `MAX_TOTAL_PCS=480` returns null (degrade, never throw). Enumerated.
3. **Weakest-link:** pre-fix weakest link = unbounded cumulative construction (0 bound against a hard
   500-wall ⇒ guaranteed crash on a long-lived tab). Post-fix = `MAX_TOTAL_PCS=480` hard stop BELOW the
   wall ⇒ degrade, never crash. Strictly stronger.
4. **Reliability proof:** the honest dialer still connects — soak 27 ms to an aged offer, browser-e2e
   3.8 s, group-ui full flow. The dial path is UNRATED (`newPc()` without `rated`) so a user dial always
   builds its answerer; a consumed slot refills (rated). `P(connect)` preserved.
5. **Degenerate-safe:** at a cap `newPc` returns null → the listener simply stops refilling (existing
   parked offers keep serving) instead of throwing. Never below baseline (baseline = the crash). The
   node/werift path (no per-page cap) is unaffected — werift-tui PASS.
6. **Monitoring hook:** `test/browser-pc-soak.mjs` (real Chromium) IS the standing CAG-6 assertion —
   RED on old / GREEN on new, both verified here — plus the deterministic reuse-invariant test.
7. **Reversible / no wire change:** pure browser-transport change; all bounds are constructor opts;
   node/wire/group/transport untouched. The DataChannel wire is unchanged (browser-e2e + werift-tui both
   green, symmetric module on both runtimes). NOT part of the v0.3.0 protocol break.
8. **Simplicity dominance:** reuse-pool + iceRestart is the minimal construction that makes constructions
   track connections; a single-persistent-pc alternative loses multi-dialer resilience. Not dominated.

## Residual (honestly stated in the commit; I concur — not a gate blocker)

Not run across two real distinct NATs; a >5 h wall-clock real tab not soaked (the 200× accelerated soak
models 5 h and Phase B measures the real `/app/` churn). Recommend a real multi-hour `/app/` tab left
open as the final feel-test. The accelerated real-Chromium RED/GREEN + Phase B are strong enough to ship.

## Standing-resident

c43d647 clear to ship. With b9b6819 → **v0.3.0-dev.2**. All routed lanes now gated
(browser/wss · wire-auth · GRP · GRP-5 closure · tracker · dos-meta · browser-pc-churn). Resident for
anything further.
