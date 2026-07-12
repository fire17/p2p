# p2p — WSS Tracker Pool: Discovery, Live-Probe & Vetting Study

> **Research Lane: Tracker Pool (task #29).** Owner: fire17. Status: **DECISION-GRADE — LIVE-PROBED VERDICT** (research only — NO `src/` changes this pass; the `TRACKERS` edit is a later build).
> **Date:** 2026-07-12. **Author:** tracker-pool lane (opus @ high) + 1 sonnet enumeration subagent.
> **Reads on top of:** `src/rendezvous/tracker.js` (the shipped `TRACKERS` pool + `trackerProbe`/`createTracker`), `research/surface-hardening.md` §3.4/§3.6 (surface cycling; benefit ∝ pool size N; N=3 ⇒ 33% floor; CAG check-3 tension), `research/wargame-findings.md` §6.2 (public relays are best-effort by ToS; a relay is an on-path attacker — the WSS relay is the FLOOR under WebRTC).
>
> **Reading contract:** a senior engineer reading ONLY this file can decide the exact `TRACKERS` list to ship, holds the live measurements behind each verdict, understands why the "grow to 8–10" goal is blocked by ecosystem supply, and can re-run every probe from `scratch/` (gitignored). Every liveness claim is a real measurement taken 2026-07-12; anything not directly measured is flagged **UNVERIFIED**.

---

## 0. The mission and its one-line result

**Task #29:** discover, live-probe, and vet additional public WebTorrent/WSS trackers to grow the reliable pool toward **8–10** without ever risking discovery reliability.

**Result (honest, blunt):** the goal of 8–10 is **not achievable — the public WSS-matchmaker ecosystem does not contain 8–10 working independent operators.** After sweeping the whole WebTorrent ecosystem (ngosang lists + history/blacklist, create-torrent, trystero, P2P-Media-Loader, go2rtc, PeerTube source, GitHub code search) and **live-probing every reachable candidate**, exactly **three** hosts work as general-purpose WebRTC matchmakers today — and **one of the three currently shipped (`tracker.openwebtorrent.com`) is a DEAD matchmaker**: it accepts announces but no longer relays offers (confirmed cross-IP over Tor, 0/10).

So the real deliverable is not a bigger pool — it is: **(a) repair the shipped pool** (swap the dead member for a live one, netting 3 all-working, all-independent-operator trackers), and **(b)** record that surface cycling's premise (a pool big enough for the benefit to matter) has **no supply** in the wild, which keeps cycling deferred exactly as `surface-hardening.md` §3.6 already concluded — now with the empirical reason, not just the analytic one.

---

## 1. Method — capability, not liveness (and the confound that had to die)

Three probe tiers, each stronger than the last. All run from the repo's own code (`src/rendezvous/tracker.js`) or hand-rolled zero-dep clients in `scratch/` (gitignored — the commit-lock holds the doc only; probing happened outside it).

1. **Announce probe** (`trackerProbe`, `scratch/probe-trackers.js`) — connect over WSS, send one announce under a **random** infohash, await the response. Proves reachability + protocol only. **This tier LIES** for our purpose: a tracker can pass announce 3/3 and still never relay a peer (see OWT, §3).
2. **Matchmake probe** (`createTracker`, `scratch/probe-matchmake.js`) — the capability that matters: one `createTracker` listener announces a rid + candidate blob; a separate `createTracker` dialer looks the same rid up. **Success = the dialer receives the listener's blob through that tracker alone.** This exercises our exact production code path.
3. **Cross-IP relay probe** (`scratch/crossip-driver.js` + `scratch/socks-ws-peer.js`) — the confound-killer. Tiers 1–2 both run from **one source IP**. A tracker that suppresses relay between same-IP peers (an anti-abuse measure) would look dead under tier 2 while working fine for real, differently-located peers. So peer A dials from this machine (`62.56.174.16`); peer B dials **through a local Tor SOCKS5 proxy** (exit `185.220.101.35`) — a genuinely different source IP. Success = A receives B's offer.

> The `trackerRelayProbe` in `tracker.js` returned 0/2 even for trackers that matchmake 5/5 — it is **unreliable and must not be used as a capability signal**; tier 2 (`createTracker`) is the ground truth. Noted so no future lane trusts it.

**Fresh-candidate note:** the crashed original run of this lane left its probe scripts + round-1/2 outputs in `scratch/`; they were independently re-run this pass, not trusted as-is.

---

## 2. Candidate enumeration (the full sweep)

Sources: ngosang/trackerslist (`trackers_all_ws.txt` + `blacklist.txt` + commit history sampled 2020→2026), `webtorrent/create-torrent` defaults, `dmotz/trystero` `torrent` strategy `defaultRelayUrls`, Novage `p2p-media-loader` `core.ts` default announce list, `webtorrent/instant.io`, OpenWebTorrent repos, GitHub code search `wss://tracker`, PeerTube source (per-instance tracker), and issue threads (webtorrent #1653/#1674/#743, p2pt #34, ngosang #257).

**The signal that frames everything:** ngosang/trackerslist — the canonical daily-updated community list — currently ships **exactly one** WS tracker in `trackers_all_ws.txt` (`wss://tracker.btorrent.xyz:443`). The WS-tracker population is tiny and shrinking; this is not a list that can be grown to 8–10.

Candidate hosts that were enumerated and probed (full list + provenance preserved in the appendix). The ones that resolve and merited a live capability probe:

| Host | Provenance | DNS |
|---|---|---|
| `tracker.openwebtorrent.com` | create-torrent / trystero / P2P-ML / go2rtc default (most-defaulted in the ecosystem) | Cloudflare |
| `tracker.webtorrent.dev` | create-torrent / trystero default | Hetzner DE |
| `tracker.btorrent.xyz` | ngosang (sole WS entry) + create-torrent + trystero | Cloudflare |
| `open.ftorrent.com` | trystero `defaultRelayUrls` (current main) — single-source | Pulse US |
| `tracker.novage.com.ua` | Novage p2p-media-loader default; README says "public trackers available" | Oracle IE |
| `tracker.files.fm:7073` | trystero default; 5yr in ngosang, dropped 2026-03 | files.fm (Tet LV) |
| `tracker.magnetoo.io` | community lists only (DeSireFire/adysec) | 5.79.75.200 |
| `qot.abiir.top` | community lists only | 34.8.196.142 |

Enumerated but **not live** (NXDOMAIN / dead / scoped — no probe possible or pointless): `tracker.ghostchu-services.top`, `tracker.dnlab.net`, `track.file.pizza`, `hub.bugout.link` (all NXDOMAIN); `tracker.fastcast.nz`, `ws.peer.ooo`, `tracker.btsync.cf`, `spacetradersapi-chatbox.herokuapp.com`, `tracker.sloppyta.co`, `tracker.webtorrent.io`, `tracker.lab.vvc.niif.hu` (dead/retired, documented in appendix); and the **PeerTube instance trackers** (`peertube.cpy.re`, `video.blender.org`, `open.tube`, `tube.privacytools.io`) which are **instance-scoped** — confirmed via PeerTube source (`controllers/tracker.ts`) and observed live: they reject arbitrary infohashes (`"failure reason":"Unknown infoHash … requested by ip"`), so they can **never** serve as a general rid-keyed matchmaker.

---

## 3. Live-probe results (real measurements, 2026-07-12)

### 3.1 The capability verdict

| Tracker | announce | matchmake (same-IP) | **cross-IP relay (Tor)** | latency (median) | verdict |
|---|---|---|---|---|---|
| `wss://tracker.webtorrent.dev` | 3/3 | **5/5** | **YES** | ~560 ms | ✅ WORKING |
| `wss://tracker.btorrent.xyz` | 2–3/3 | **4/5** | **YES** (1 retry — see §3.3) | ~1100–1400 ms | ✅ WORKING (flaky) |
| `wss://open.ftorrent.com` | 3/3 | **5/5** | **YES** | ~890 ms | ✅ WORKING |
| `wss://tracker.openwebtorrent.com` | **3/3** | **0/5** (0/5 deep) | **NO** (0/2 ×2) | ~270 ms (announce) | ❌ **DEAD MATCHMAKER** |
| `wss://tracker.novage.com.ua` | 0/3 (timeout) | 0/3 | — | — | ❌ unreachable |
| `wss://tracker.magnetoo.io/announce` | 0/3 (non-101) | 0/3 | — | — | ❌ no WS upgrade |
| `wss://qot.abiir.top:443/announce` | 0/3 (non-101) | 0/3 | — | — | ❌ no WS upgrade |
| `wss://tracker.files.fm:7073/announce` | 0/3 | — | — | — | ❌ **403 Forbidden** on WS upgrade (Origin-gated) |

### 3.2 The critical finding — a dead matchmaker is shipping right now

`tracker.openwebtorrent.com` is in the **current shipped `TRACKERS`** (`src/rendezvous/tracker.js:11`) and is the **most-defaulted WSS tracker in the entire WebTorrent ecosystem** (create-torrent, trystero, P2P-Media-Loader, go2rtc all default to it). It is also the **fastest to answer** (announce ~270 ms) — so every liveness-only check passes it. **But it no longer relays WebRTC offers.**

Raw two-peer trace (`scratch/owt-raw.js`): both peers register (the tracker's `complete` count climbs 1→2 under the shared infohash) but **A never receives B's offer**. Contrast the identical trace against `tracker.webtorrent.dev`, where A receives B's offer frame every time.

The confound-killer settles it: with peer B dialing through a **Tor exit** (a truly different source IP), OWT relayed **0/2 twice** while the `webtorrent.dev` control relayed **YES** in the same harness. So OWT's failure is **not** same-IP suppression — it genuinely does not forward offers. **This means the effective shipped pool is 2, not 3.** (Whether OWT is permanently dead or intermittently down is UNVERIFIED — it may recover; but as of 2026-07-12 it is a non-functional matchmaker.)

### 3.3 The btorrent flakiness caveat (honest)

`tracker.btorrent.xyz` matchmakes 4/5 (one same-IP miss) and its cross-IP probe returned **NO on the first attempt, YES on retry**. It is **Cloudflare-fronted** (origin hidden behind AS13335), and Cloudflare challenges/blocks low-reputation client IPs (Tor exits especially) — the first cross-IP NO is almost certainly a Cloudflare edge challenge on that particular exit, not a btorrent relay failure. **Net: btorrent works, but it is the least reliable of the three and its reachability is hostage to Cloudflare's client-IP reputation.** Keep it, but do not treat it as the anchor.

---

## 4. Operator / jurisdiction diversity vet

The point of a pool (and of any future cycling) is that surfaces are **independent parties**, not one operator's fleet. The three working trackers:

| Tracker | ASN / host | Jurisdiction | Registrar / NS | Operator | Independent? |
|---|---|---|---|---|---|
| `tracker.webtorrent.dev` | AS24940 **Hetzner** | **DE** | — | WebTorrent LLC (Feross ecosystem) | ✅ distinct |
| `tracker.btorrent.xyz` | AS13335 **Cloudflare** (origin hidden) | US edge / origin unknown | Cloudflare registrar + NS | btorrent.xyz (community) | ✅ distinct operator, but Cloudflare-fronted |
| `open.ftorrent.com` | AS394838 **Pulse** | **US** | deSEC NS (`ns1.desec.io`), **Caddy** server | unknown/newer, trystero-listed | ✅ distinct — different ASN, different stack |

**Diversity read:** three different ASNs (Hetzner DE, Cloudflare US, Pulse US), three different operators, two jurisdictions (DE + US). That is **genuinely diverse for N=3** — not one fleet. The weakness: two of the three surface through **US-adjacent infrastructure**, and one (`open.ftorrent.com`) is a **single-source, undocumented operator** — live and independent, but with **no reputation/longevity record** (trust concern, not a liveness concern). By contrast, the now-removed OWT and the kept btorrent both front through **Cloudflare (AS13335)** — so the *old* pool actually had **two members sharing one front (Cloudflare)**; swapping OWT→ftorrent *increases* operator+ASN diversity as a side effect.

---

## 5. The CAG check-3 tension — honest verdict

`surface-hardening.md` frames the core tension (Complexity Adversarial Gate, check-3): **more operators means each one sees a smaller fraction of you (good for metadata privacy), BUT each new operator is a new party who could be malicious** — and `wargame-findings.md` §6.2 is explicit that **a relay is an on-path attacker** (best-effort by ToS, the WSS floor under WebRTC). So growing the pool is not free: every tracker you add is one more on-path party that can log `(your IP, infohash, who you met)`.

Applying that here:

- **Cycling's benefit is proportional to pool size N** (§3.4): at N=3, k=1, a single curious operator still sees ≈**33%** of your invites — weak. The benefit only becomes meaningful at N≈8–10 (≈10–12%).
- **But there is no supply of 8–10 independent working matchmakers.** The wild contains **three**. You cannot reach the pool size at which cycling's privacy benefit outweighs its complexity + desync risk.
- **A dead matchmaker is a pure metadata liability.** OWT relays nothing yet still learns `(your IP, infohash)` on every announce. Keeping it in the pool buys **zero** discovery value and **costs** one more on-path observer — the worst trade on the board. Remove it on metadata grounds alone, independent of the reliability argument.

**Net verdict:** at the achievable pool size (N=3), the CAG says **do not build cycling and do not chase operators** — the marginal privacy gain from a 4th *unknown* operator (33%→25% floor) is second-order and is paid for with a new unvetted on-path party. This **confirms** `surface-hardening.md` §3.6's deferral of cycling, and adds the empirical reason: **the ecosystem cannot supply the pool that would make cycling worth its complexity.** The right move is `burn` (v2), which closes the exposure *window* and does not depend on operator count.

---

## 6. Recommendation — the exact pool and the `TRACKERS` diff

### 6.1 Ranked vetted candidate list

1. **`wss://tracker.webtorrent.dev`** — ✅ 5/5, cross-IP YES, fastest reliable (~560 ms), Hetzner DE, ecosystem-canonical. **The anchor.**
2. **`wss://open.ftorrent.com`** — ✅ 5/5, cross-IP YES, ~890 ms, independent ASN (Pulse) + stack (Caddy/deSEC). **Best diversity add.** Caveat: single-source, no reputation record — UNVERIFIED longevity.
3. **`wss://tracker.btorrent.xyz`** — ✅ 4/5, cross-IP YES (flaky via Cloudflare), ~1100–1400 ms, sole survivor of the ngosang curated list. **Keep as third; do not anchor on it.**
4. *(none)* — no fourth working independent matchmaker exists to add.

### 6.2 Recommended pool (for the later build)

Swap the dead member for a live one. Net N stays **3**, but goes from **2-effective → 3-effective**, and operator/ASN diversity increases (drops one of the two Cloudflare-fronted members).

**Exact `src/rendezvous/tracker.js` diff (later build — NOT applied this pass):**

```diff
- // live-probed healthy 2026-07-11 (research/rendezvous.md appendix)
+ // live-probed 2026-07-12 (research/tracker-pool.md §3): openwebtorrent is a DEAD matchmaker
+ // (announce-OK but relays 0 offers, confirmed cross-IP over Tor) — swapped for open.ftorrent.
  export const TRACKERS = [
-   'wss://tracker.openwebtorrent.com',
    'wss://tracker.webtorrent.dev',
    'wss://tracker.btorrent.xyz',
+   'wss://open.ftorrent.com',
  ];
```

**Ordering note (matters only if cycling is ever built):** `tracker.webtorrent.dev` is placed first because it is the fastest *reliable* matchmaker; if a future prefix-selection (`surface-hardening.md` §3.1) ever uses this list, a `keyed_shuffle` reorders it anyway, so array order here is purely today's fan-out preference. **A dead matchmaker at `π[0]` would force expansion every rendezvous — which is the second, cycling-specific reason OWT must be removed before any cycling work.**

**On keeping OWT as a "4th insurance slot":** rejected. In today's fan-out `createTracker` races all trackers and a non-relaying one simply never yields — so it is not *reliability*-harmful, but it **is** metadata-harmful (§5: one more on-path observer for zero benefit). Minimalism + the weakest-link principle both say drop it.

---

## 7. Reliability guardrail (explicit — the owner's hard constraint)

> **Adding or swapping trackers in this recommendation NEVER reduces discovery success.**

Proof, per the two operations:

- **Removing `tracker.openwebtorrent.com`:** it contributes **zero** successful matchmakes today (0/5, 0/5, cross-IP 0/2×2). A surface that never yields a peer cannot be the one that made a rendezvous succeed, so removing it **cannot lower** the success probability. (It only *raised* connection count and metadata exposure.)
- **Adding `open.ftorrent.com`:** `createTracker` races every tracker in `TRACKERS` independently and dedupes peers (`tracker.js` `active`/`seen`), so **more live surfaces raced = strictly more paths to first contact = success probability monotonically non-decreasing.** A new live matchmaker can only help.
- **Net:** the swap replaces a 0-yield surface with a 5/5 surface → discovery success **strictly improves**. The LAN/mDNS fast path is untouched (`race.js` phases mDNS ahead of trackers regardless).

This is the fan-out guarantee, and it is exactly why cycling (which *subsets* the pool) is the risky variant deferred behind burn — whereas simply **fixing** the fan-out pool is pure upside and carries none of cycling's desync risk.

---

## 8. Honest status — flaky / UNVERIFIED / caveats

- **`open.ftorrent.com` longevity is UNVERIFIED.** It is live and relays cleanly (5/5, cross-IP YES) but is a single-source (trystero-only) find with no operator documentation or reputation history. It could vanish. Recommend a periodic `doctor`-style re-probe before relying on it long-term.
- **`tracker.btorrent.xyz` is flaky** (§3.3): Cloudflare-fronted, one cross-IP miss then success; its reachability depends on Cloudflare's view of the client IP. Works, but least reliable.
- **`tracker.openwebtorrent.com` "dead" is a 2026-07-12 snapshot.** It answers announces perfectly and is heavily defaulted across the ecosystem — it may be intermittently down rather than retired. The recommendation removes it because a matchmaker that doesn't matchmake is worse than useless here; if a future probe shows relay restored, it can return.
- **`trackerRelayProbe` (in `src/rendezvous/tracker.js`) gives false negatives** — 0/2 even against 5/5 trackers. Do not use it as a capability signal; use the `createTracker` matchmake probe.
- **The "8–10 pool" goal is UNMET by supply, not by effort.** Every documented public shared WSS matchmaker was enumerated and probed. Three work. Growing further requires **operating our own** tracker(s) — which introduces a party *we* run (a different trust model; out of scope for this lane, flagged for the roadmap).
- **btorrent latency measured under load-varying conditions**; treat the ~1100–1400 ms as indicative, not a benchmark.

---

## Appendix — raw probe log (2026-07-12, this lane; scripts in `scratch/`, gitignored)

```
# Tier-2 matchmake (createTracker; N pinned to one url), tries shown
tracker.webtorrent.dev        5/5   msToBlob ~552–594
open.ftorrent.com             5/5   msToBlob ~879–898
tracker.btorrent.xyz          4/5   msToBlob ~1081–1542
tracker.openwebtorrent.com    0/5   (deep re-run 0/5)   <- DEAD MATCHMAKER, in shipped pool
tracker.novage.com.ua         0/3   (announce timeout — WS port dead/firewalled)
tracker.magnetoo.io/announce  0/3   (non-101, no WS upgrade)
qot.abiir.top:443/announce    0/3   (non-101, no WS upgrade)

# Tier-3 cross-IP relay (peer A local 62.56.174.16, peer B via Tor exit 185.220.101.35)
tracker.webtorrent.dev        CROSS-IP-RELAY = YES   (control)
open.ftorrent.com             CROSS-IP-RELAY = YES
tracker.btorrent.xyz          CROSS-IP-RELAY = NO then YES on retry (Cloudflare edge challenge on Tor exit)
tracker.openwebtorrent.com    CROSS-IP-RELAY = NO  (0/2, twice)  <- confirms dead, not same-IP suppression

# Reachability / classification
tracker.files.fm:7073/announce   403 Forbidden on WS upgrade (Origin-gated; reachable, unusable)
tracker.novage.com.ua            WS connect timeout (HTTPS 443 also times out)
ghostchu-services.top, dnlab.net, file.pizza, bugout.link   NXDOMAIN
fastcast.nz, webtorrent.io, sloppyta.co, lab.vvc.niif.hu    NXDOMAIN / retired
peertube.cpy.re, video.blender.org, open.tube, tube.privacytools.io
                                 instance-scoped: "failure reason: Unknown infoHash … requested by ip"

# ASN / operator
tracker.webtorrent.dev  49.13.90.136    AS24940 HETZNER (DE)
tracker.btorrent.xyz    172.67.136.115  AS13335 CLOUDFLARENET (US edge)
open.ftorrent.com       149.106.106.25  AS394838 PULSE (US), server: Caddy, NS: deSEC
tracker.openwebtorrent.com 172.67.174.171 AS13335 CLOUDFLARENET (US edge)
```

*End of report. A senior engineer can apply the §6.2 diff and ship a 3-working-tracker pool, and knows — with live evidence — that cycling stays deferred because the ecosystem cannot supply the pool size that would make it worth the complexity.*
