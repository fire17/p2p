# Redteam CAG Gate — fe413e2 (tracker-pool: drop dead openwebtorrent, add ftorrent)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Analysis + verification only.
> **Date:** 2026-07-12. **Commit:** `fe413e2` (data-only change to `TRACKERS` in `src/rendezvous/tracker.js`).

## Verdict: **CONFIRMED-SHIP.**

Data-only, byte-identical protocol, one-line reversible. Both halves independently verified by me with
the createTracker cross-instance method (NOT `trackerRelayProbe`, which the research explicitly marks
unreliable).

## My own test output

**Per-tracker isolation** — a `createTracker({trackers:[url]})` announcer + a second-instance lookup on
the same rid; success = the lookup receives the announcer's candidate blob (that host relayed the offer):
```
RELAYS ✓  wss://open.ftorrent.com            (896ms)     ← the ADD is live (matches doc's ~890ms)
DEAD   ✗  wss://tracker.openwebtorrent.com   (no relay/12s)  ← the REMOVAL is justified (dead matchmaker)
RELAYS ✓  wss://tracker.webtorrent.dev       (631ms)     ← anchor still healthy
```
**New-pool end-to-end smoke** (default `TRACKERS` = webtorrent.dev + btorrent.xyz + ftorrent): a cross-
instance announce→lookup **relayed in 634ms → PASS**. The pool matchmakes with OWT gone and ftorrent in.

These independently reproduce `research/tracker-pool.md`'s core claims (OWT answers announce but relays
0 offers; ftorrent 5/5). I did NOT re-run the Tor cross-IP confound-killer (the doc already did — OWT
0/2 ×2 via a real Tor exit), but a same-IP createTracker relay is sufficient to confirm OWT is dead:
webtorrent.dev and ftorrent both relayed same-IP in the same harness where OWT relayed nothing in 12s.

## Reliability CAG (the load-bearing checks)

- **Removal can't lower P(success)** — OWT matchmade nothing (my probe: no relay in 12s; doc: 0/5
  same-IP, cross-IP relay NO). Removing a host that contributed 0 peers to the result set is neutral for
  discovery and **net-positive on metadata**: a dead matchmaker still learns `(your IP, infohash)` on
  every announce while relaying nothing — a pure on-path liability (tracker-pool.md §"remove on metadata
  grounds alone").
- **Adding a live tracker is monotone** — verified in code, not just asserted: `announce()` and
  `lookup()` both `trackers.map(url => openConn(...))` — an independent parallel connection per tracker
  (one failing/​slow does not block the others), and `lookup` dedupes peer blobs via a `seen` Set keyed
  on `JSON.stringify(blob.candidates)`. So the yielded peer set is a monotone union over the pool: adding
  ftorrent can only surface more distinct peers (or deduped duplicates), never fewer.
- **Degenerate-safe** — if ftorrent later dies (single-source, no longevity record — the honest caveat
  from the research), the pool degrades to the two proven-working members (webtorrent.dev + btorrent),
  i.e. back to the current *effective*-2 baseline, never below it. Graceful.

## CAG §6 (condensed)

1. **Residual:** removes a dead matchmaker (0 discovery value, 1 on-path observer of `IP+infohash`); adds
   a live 5/5 matchmaker with an independent ASN. Effective working pool 2→3; on-path observer count flat
   (1-for-1 swap) but **operator/ASN diversity up** — the old pool had OWT+btorrent both behind Cloudflare
   (AS13335); the new pool is three distinct ASNs (Hetzner DE / Cloudflare US / Pulse US).
2. **Attack surface:** no new code (data only). ftorrent is a new on-path party (can log `IP, infohash,
   who-you-met`) — same class as any relay, and it *replaces* OWT, so observer count doesn't grow. Trust
   residual (documented): ftorrent is single-source with no reputation/longevity record — a trust concern,
   not a liveness one.
3. **Weakest-link:** the pre-change weakest link was OWT — a dead matchmaker that silently passed every
   liveness-only check. Removing it + adding a cross-instance-verified relay is strictly not weaker.
   btorrent remains the least-reliable survivor (Cloudflare-hostage to client-IP reputation) but is kept
   as best-effort, not the anchor.
4. **Reliability proof:** P(discovery) monotone non-decreasing under the fan-out+dedupe design (above),
   empirically confirmed (new pool relays end-to-end; ftorrent + webtorrent.dev each relay in isolation).
5. **Degenerate-safe:** see above — floor is the effective-2 baseline.
6. **Monitor:** `research/tracker-pool.md` live-probe (createTracker cross-instance + Tor confound-killer)
   is the standing evidence. `trackerRelayProbe` is explicitly marked unreliable — do not use as a
   capability signal (it returned 0/2 for trackers that matchmake 5/5).
7. **Reversible:** one-line data revert; no wire/byte change (only which hosts are dialed).
8. **Simplicity:** minimal data change, no logic. Dominant.

## Notes

- No stale references to `openwebtorrent` anywhere in `src/`, `bin/`, `app.js` (only the explanatory
  comment in `tracker.js`).
- Cycling (#27) being dropped is consistent: only 3 working matchmakers exist in the wild — no supply for
  N=8–10 — which empirically confirms the `surface-hardening.md` §3.6 deferral. No build, correctly.

## GRP-cluster follow-up (closing an earlier loose end)

The GRP full-deterministic glob that reported "exit 1" was a **grep-pattern artifact** — the runner
grepped `# tests` but node:test emits `ℹ tests`, so grep matched nothing and exited 1. Re-run with the
correct capture: **199 tests / 199 pass / 0 fail**. GRP cluster is fully coherent at HEAD; no regression.
