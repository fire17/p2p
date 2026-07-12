# Redteam CAG Gate — a84345e (BRW-4/5/1) + 6cd0c3c (DOS-1-WSS)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Analysis + verification only — no `src/` edits.
> **Date:** 2026-07-12. **Gated commits:** `a84345e`, `6cd0c3c` (both landed before this lane's gate ran; crash-recovered).
> **Method:** read diff → run committed tests → independent real-PC soak → werift wire gate → full CAG §6.
> Reproduce the soak: `node scratch/redteam-brw4-soak.mjs [fixed|prefix] [seconds]`.

## ⚠️ Method limitation — this gate has a WERIFT BLIND SPOT (added 2026-07-12, post-owner-feeltest)

The owner hit a LIVE BRW-4 RESIDUAL feel-testing on real Chrome: `Cannot create so many
PeerConnections` — which also breaks group connections. My BRW-4 soak bounded the wrong axis.

- What my soak proved: the **parked/live** RTCPeerConnection count stays bounded (`LIVE=8` at the cap).
  True, and it is what the committed test asserts.
- What it did NOT prove: that the **creation CHURN** is survivable on a real browser. My own soak run
  **created 320 PCs** (closing 312) in 20 s — werift accepts that churn happily because it enforces NO
  browser-style ceiling on concurrent/rapidly-created RTCPeerConnections. A real Chromium does: closed
  PCs are not freed synchronously, so the announce cadence (still `OFFERS_PER_ANNOUNCE` PCs minted per
  interval — the fix caps how many are *parked*, NOT the creation *rate*) accumulates un-GC'd PC objects
  and eventually throws `Cannot create so many PeerConnections`.
- Root cause of the blind spot: **werift is not a browser.** A werift-injected `RTCPeerConnection` has no
  creation-rate/concurrency limit, so a soak on it is structurally incapable of reproducing a browser
  exhaustion that is about creation churn rather than live count. My "real-PC soak" was real werift, not
  real browser — a category I conflated.
- Correct instrument: a **REAL-CHROMIUM** soak (Playwright/headed Chrome) that drives the same announce
  churn and asserts the browser does not throw. That is the `browser-pc-churn` lane. When it lands I will
  gate it by confirming (a) the soak is genuinely a browser (not werift), (b) it reproduces RED on the
  pre-fix code (`Cannot create so many PeerConnections`), and (c) the count/churn stays bounded with the
  fix. Standing method fix: **any browser-resource claim must be gated on a real browser, never werift.**

## Verdicts

| Commit | Item | Verdict |
|---|---|---|
| a84345e | BRW-4 parked-offer reap/cap (RTCPeerConnection leak) | **CONFIRMED-SHIP** |
| a84345e | BRW-5 bounded chunk reassembly | **CONFIRMED-SHIP** |
| a84345e | BRW-1 outbound lock only on well-formed frame | **CONFIRMED-SHIP** |
| 6cd0c3c | DOS-1-WSS accept-path cap/rate/idle-evict + dials cleanup | **CONFIRMED-SHIP** |

No DEVIATION. One documentation-level **GAP** (below) — the committed BRW-4 soak uses a fake PC; the
real-RTCPeerConnection proof this lane locked as a hard gate lives in `scratch/redteam-brw4-soak.mjs`
and is recorded here, not in the deterministic suite. Not ship-blocking (module bookkeeping is what
leaks; the fake-PC test asserts it), but the harness should be promoted or referenced.

## Evidence (own runs)

**Deterministic suite (full):** `node --test` → **197 pass / 0 fail** (177s). The two gate files:
`browser-webrtc-hardening.test.js` 3/3, `transport-wss-dos.test.js` 4/4. Re-run at clean HEAD in an
isolated worktree (pinned 6cd0c3c, sharing node_modules) → 18/18 across the two gate files + `wire.test.js`.

**BRW-4 SOAK — the hard gate, with REAL werift RTCPeerConnections (not fake, not code-reasoned):**
`scratch/redteam-brw4-soak.mjs` drives a long-lived listener whose parked offers are NEVER answered
(the exact BRW-4 scenario), injecting werift's real `RTCPeerConnection` (real ICE agent, host
candidates, `iceServers: []` → zero network), counting live PCs as `created − closed`.

- **FIXED (HEAD):** 20 s soak → `created=320, closed=312, LIVE pinned at 8` (== cap) every 2 s sample,
  `peak LIVE = 8`, RSS flat (~100–127 MB, no upward trend), `LIVE after close() = 0`. **BOUNDED ✅**
- **PRE-FIX (git 27de4b0, same harness):** 12 s → `created=192, LIVE == created`, linear +32/2 s,
  RSS climbing. **UNBOUNDED ❌** — reproduces the exact leak the commit fixes.

So the parked/unanswered PC count stays bounded under a sustained real-PC soak (created ≫ bound,
312 of 320 reclaimed mid-soak), and the answered-offer path still promotes to a live connection
(committed test 2/3). The hard gate is **satisfied by an independent real-PC harness**, above the
committed fake-PC test.

**Werift wire gate (DataChannel wire changed in a84345e → re-run required):**
`node test/werift-tui-e2e.mjs selftest` — CONFIRMED it actually RAN (did not self-skip; werift present).
Run at clean HEAD 6cd0c3c in the isolated worktree → **PASS**: two Node peers over the REAL public WSS
trackers, real ICE, real DataChannel, Noise IK on top; both peers established, `peer.key === S` on both
sides (MITM-free), bidirectional app messages delivered. The chunking/reassembly changes did not break
the real wire.

> ⚠️ **The FIRST werift selftest run CRASHED** (`createChannel: opts.mac {tx,rx} required`, node.js
> attach → wire.js:161). Root cause is NOT these commits: the **wire-auth lane was editing
> `src/node.js` + `src/wire.js` + `test/wire.test.js` LIVE and uncommitted** (mtimes 17:00–17:01) —
> half-threaded WIRE-1/2/3 `mac` plumbing. `git show --stat a84345e 6cd0c3c -- src/wire.js src/node.js`
> is empty: neither gated commit touches those files. Re-running against a clean-HEAD worktree removed
> the contamination and the gate passed. (Rule 7 collision — flagged to team-lead.)

## CAG §6 — a84345e (BRW-4 the load-bearing item)

1. **Residual-closed (quantified):** closes a LIVE v0.2.0 leak — a listener parked 1 RTCPeerConnection
   per announced offer (4/announce, 10 s cadence ⇒ ~24 PCs/min ≈ 1440/hr; commit says ~4300/hr under
   its measured rate), freed only on `dc.onopen`/`node.close`. Adversary: any dialer that receives
   offers and never answers (or just silence). Now: `OFFER_TTL` reap (120 s == tracker offer-expiry, so
   nothing still-serveable is dropped), `CONNECT_TTL` (30 s) reap on answer-but-ICE-never-opens,
   `MAX_PENDING_OFFERS=64` oldest-evicted. Does NOT close: an attacker who completes DTLS+Noise and
   holds *live* connections — that is node-layer peer accounting, out of scope.
2. **Attack-surface enumeration:** new parts = TTL timers, the pending-cap eviction loop, `freePc`,
   the answer→connect-TTL swap. Adversary tries: (a) flood offers to exhaust timers — bounded by the
   cap (≤64 parked ⇒ ≤64 timers); (b) answer to hold a slot — connect-TTL reclaims if the channel
   never opens; (c) race teardown — `if (closed) freePc(pc); return null` guards a pc built mid-close;
   `stop()` evicts every parked offer. Timers `unref()` so a parked offer never keeps a Node process
   alive. No unenumerated part.
3. **Weakest-link map:** post-change the weakest link is the same cap constant (64 parked). It is not
   weaker than baseline — baseline had NO bound (∞). Strictly stronger.
4. **Reliability proof:** the accept path is untouched for answered offers — `dc.onopen` still promotes
   (committed test 2/3 + the werift wire gate both green). TTL == tracker offer-expiry, so a reaped
   offer was already un-serveable. `P(connect)` unchanged for any real dialer. ✅
5. **Degenerate-safe:** with no dialers it degrades to "park up to 64, reap after 120 s" — bounded,
   never below baseline reachability (still parking + refreshing offers every cycle).
6. **Monitoring hook:** `_debug.liveCount()` + `handle.pendingCount()` are the standing leak-monitor
   assertions; the committed soak asserts both stay bounded; this lane's real-PC soak re-asserts with
   werift.
7. **Flag-gated/reversible:** all bounds are constructor opts (`offerTtlMs/connectTtlMs/maxPendingOffers/
   announceIntervalMs`) with the prior behavior recoverable by widening them; wire bytes unchanged
   (offer/answer JSON shape identical). Byte-identical on the wire.
8. **Simplicity dominance:** TTL + LRU cap is the minimal bound for a park-map; no simpler correct
   option (an unbounded map WAS the bug). Not dominated.

**BRW-5:** residual = unbounded reassembly keyed by sender-chosen msgId (memory exhaustion post-DTLS,
pre-Noise). Caps `MAX_REASM_BYTES=8 MiB` + `MAX_REASM_ENTRIES=256`, evict-oldest, drop the current if
it alone blows the byte cap. Real traffic never touches it (node frames ≤ mtu ⇒ single-chunk fast
path). Committed test floods 5000×15 KB distinct partials → delivered=0, `reasmCount ≤256`,
`reasmBytes ≤8 MiB`, then a fresh complete message still delivers (cap did not wedge). Degenerate-safe,
monitored via `_debug.reasmCount/reasmBytes`. **PASS.**

**BRW-1:** residual = `composePunch` locked outbound on ANY first frame; a hostile relay runt could win
the lock and misroute the handshake outbound. Now locks only when `decodeFrame(buf)` validates (a real
HELLO/wire frame). Inbound still forwarded up (node's own decodeFrame drops junk). Committed test:
"a bogus runt does NOT win the lock; the real HELLO does" — green. No wire change (validation only).
**PASS.**

## CAG §6 — 6cd0c3c (DOS-1-WSS)

1. **Residual-closed:** the WSS relay is a GUARANTEED on-path attacker — it can inject unlimited
   PUBLISHes with fresh attacker-chosen 16-byte senderIds, each pre-fix minting a `socketLike` +
   firing `onConnection` (→ a node peer-record) with no cap/rate/eviction. Now: `MAX_ACCEPTED=1024`
   cap, token-bucket (`ACCEPT_RATE=20/s`, `ACCEPT_BURST=40`), `ACCEPT_IDLE_MS=60 s` idle-evict,
   dials-map cleanup on close. Does NOT close: a *slow-and-low* attacker under the rate that keeps
   accepts warm — but that is bounded by `MAX_ACCEPTED` + idle-evict (silent ⇒ swept).
2. **Attack-surface enumeration:** new parts = token bucket, `evictMostIdle` (stalest `lastSeen`),
   the idle `sweep` interval, `socketLike(onClose)` deferred cleanup. Adversary: (a) burst → only
   `burst` admitted (test 1: 1000 senders → exactly 40); (b) sustained flood → `accepted ≤ maxAccepted`
   (test 2: 1000 → ≤50); (c) go silent to squat slots → idle-evict sweeps (test 3: 5 → 0 after window);
   (d) dial-map self-leak → close removes from `dials` (test 4). `sweep.unref()`. Enumerated.
3. **Weakest-link map:** weakest link = `MAX_ACCEPTED` (1024). Baseline was ∞. Strictly stronger.
4. **Reliability proof:** legitimate first-contact is admitted while `tokens ≥ 1` and `accepted <
   maxAccepted` (or a staler peer is evicted). A real correspondent sends frames ⇒ `lastSeen` refreshes
   ⇒ never idle-evicted while active. Dedup/dial path untouched. No drop of a live conversant under
   any non-flood condition. ✅
5. **Degenerate-safe:** under flood it degrades to "admit ≤ burst then ≤ rate, hold ≤ cap, shed
   stalest" — bounded, never below baseline (baseline accepted everything unboundedly; the fix only
   ever admits a subset, and a real peer that keeps talking is never the stalest).
6. **Monitoring hook:** `_debug.acceptedCount()` + `_debug.dialsCount()` — the committed test asserts
   all four bounds fire. CAG check-6 satisfied.
7. **Flag-gated/reversible:** every bound is a constructor opt (`maxAccepted/acceptIdleMs/acceptRate/
   acceptBurst/idleSweepMs`); set wide → prior behavior. No wire/byte change (envelope format
   identical).
8. **Simplicity dominance:** token-bucket + LRU-by-lastSeen + idle sweep is the minimal standard
   bound for an accept map. Not dominated.

## Standing-resident note

Gate is GREEN for both commits. This lane now stands resident as the CAG gate for the incoming
lanes — **wire-auth (WIRE-1/2/3, currently editing `wire.js`+`node.js` uncommitted)** and
**grp-harden (GRP-1/2/3/4, `group.js`)** — to be gated per landed commit, same CAG §6 discipline.
