# p2p v1 — ACCEPTANCE LOG (independent verification)

> 2026-07-11 · zenith-manager, independent verification + acceptance spine (Option A/C:
> zero src/ writes; every verdict from a fresh re-run or read-only review against LANDED
> code at git HEAD d774792, NOT from builder self-reports). Contract = 29 VAL-* assertions.
> RESULT: **28 PASS · 1 GAP (owner-gated) · 0 FAIL.**

## Environment
- Node v23.7.0 (>=22). Zero-dep: `package.json` deps={} devDeps={}; grep of src+bin found
  ZERO bare npm imports (node: builtins + relative only). src+bin = 3260 LOC (DESIGN §4 ~2.5-3.5k).
- git clean at HEAD d774792.

## The 6 acceptance-battery items (docs/ZENITH-BRIEF.md §Acceptance)
| # | Item | Verdict | Evidence |
|---|---|---|---|
| 1 | `node --test` green incl Noise official vectors | **PASS** | Independently reproduced 96/96 (82 deterministic core + 14 live-network). 0 fail/cancel. |
| 2 | Two fresh local processes, full protocol over loopback+mDNS, first ack proves gate+IK, 10/10 | **PASS** | `node scratch/trial.mjs 10` → **10/10** full cross-process chats over REAL mDNS multicast, avg 1760ms first-contact (mDNS→punch→Noise IK→wire). gate+IK proven by node.test.js (connect gate+IK first-ack) + integration adversarial. |
| 3 | Two DIFFERENT networks connect via public rendezvous + punch, chat realtime | **GAP (owner-gated)** | Machinery gate-proven: LIVE public STUN reflexive (2.54.160.x), punch 10/10 forced-loss, LIVE Mainline DHT round-trip 5/5 (100%, avg 34.7s). A real two-distinct-network run is UNOBSERVED — needs a 2nd network (hotspot/VPS), owner's call. Not a FAIL; machinery ready. |
| 4 | Typo fails local zero-network; tampered HELLO pubkey gate-dropped+logged | **PASS** | key.test.js: every single-char typo (806 mutations) + length/alphabet/space throw TypoError; node.test.js "typo throws before any network work" (decodeKey is pure). integration adversarial #1 tampered HELLO pubkey → commitment gate DROPS, no handshake; #2 wrong key → gate fail. |
| 5 | Kill one side mid-chat + restart → reconnect + buffered resend | **PASS** | node.test.js "resend buffer + exactly-once across reconnect (dropped app-ack, then replay)": tears down, redials, outbox replays, no duplicate delivery. node.js has app-level outbox (seq+ack) + replay-on-attach + dedup-across-reconnect. Note: unit-level (mock transport), not a process-kill repro. |
| 6 | Honesty: total src LOC + zero deps | **PASS** | 3260 LOC src+bin (per-module tallied, in budget). deps={} devDeps={}. Zero bare npm imports anywhere. |

## Module contracts (21)
| Assertion | Verdict | Evidence |
|---|---|---|
| VAL-KEY-001 encode/decode roundtrip | PASS | key.test.js frozen KAT + review: 5b ver/110b commit/15b checksum layout exact |
| VAL-KEY-002 typo zero-network | PASS | 806-mutation typo suite; decodeKey pure; node.test pre-network throw |
| VAL-KEY-003 commitment binds ed+x, constant-time | PASS | review: SHA256("p2p-id-v1"‖ed‖x); verifyCommitment timingSafeEqual |
| VAL-KEY-004 rid HKDF domain-sep/epoch | PASS | HKDF-SHA256(S_ascii, "p2p-rv-"+ch+"-v1", epoch, L); deduped into key.js (gotcha #2 resolved) |
| VAL-NOISE-001 official KAT vectors | PASS | byte-exact vs TWO audited impls (cacophony+snow) msg1/msg2/transport + handshake_hash |
| VAL-NOISE-002 cross-impl interop | PASS | matching two independent audited outputs byte-for-byte = D5 interop assurance; shipped lib zero-dep; provenance re-verified via fresh curl fetch |
| VAL-NOISE-003 negative fail-closed | PASS | tampered tag/static, truncated, wrong static, all-zero/low-order X25519, nonce rollover, replay/out-of-turn, split-before-complete all throw |
| VAL-NOISE-004 split/nonce/node:crypto tags | PASS | review: nonce 4‖u64-LE + MAX_NONCE guard; AEAD verify only via node:crypto final() throw; no manual byte compare |
| VAL-WIRE-001 frame format + connId | PASS | wire.test.js encode/decode roundtrip; connId Buffer(8); foreign connId ignored |
| VAL-WIRE-002 ARQ under loss/reorder | PASS | 1000 msgs each way under 20% loss+reorder+dup → exactly-once, in-order |
| VAL-WIRE-003 connId roam + keepalive | PASS | roaming mid-stream keeps delivery; PING→PONG via tick; CLOSE both ends; backpressure |
| VAL-TRANSPORT-001 candidates + STUN | PASS | LIVE public STUN reflexive + XOR-MAPPED byte-exact + txid-bound |
| VAL-TRANSPORT-002 ladder punch | PASS (machinery) | punch.test.js 10/10 forced-loss; onConnection inbound-accept; TCP simo fallback; netchange. Cross-NAT → VAL-ACCEPT-XNET |
| VAL-RDV-MDNS-001 real cross-PROCESS mDNS (hardened) | PASS | trial 10/10 over REAL multicast between two OS processes; listener answers queries; mdns.test.js |
| VAL-RDV-DHT-001 live Mainline round-trip | PASS | 5/5 (100%, single-shot 80%), announce-reached 5/5, avg 34.7s; 4th bootstrap dht.libtorrent.org:25401 present (gotcha #1 resolved) |
| VAL-RDV-TRACKER-001 WSS announce/offer | PASS | 3/3 trackers reachable, announce/offer echo confirmed; live offer-RELAY matchmaker deferred to P1 (documented) |
| VAL-RDV-RACE-001 publish/race/epoch/netchange | PASS | race.test.js; lanGraceMs=1500 settle + {yesterday,today,tomorrow} epoch race + rank/dedup/cap (gotcha #3 resolved) |
| VAL-API-001 6-call API, connect() post-IK | PASS | node.test.js connect resolves only after IK first-ack; integration "public node.js API two real nodes first-contact + message" |
| VAL-NODE-001 lifecycle/reconnect/resend | PASS | node.test.js outbox replay exactly-once across reconnect |
| VAL-GROUP-001 pairwise fan-out | PASS | group.test.js |
| VAL-CLI-001 demo CLI chat | PASS | team-lead TTY-verified real two-terminal: dialer "✅ secure channel established — verified, no MITM", listener received. Minor: non-TTY stdin (</dev/null) self-closes on EOF (fine for real terminals) |

## Security + governance
| Assertion | Verdict | Evidence |
|---|---|---|
| VAL-SEC-001 crypto composition review to zero criticals | PASS | Independent NON-AUTHOR review (zenith-manager wrote zero code): Noise IK spec-correct; AEAD only via node:crypto; fail-closed; low-order/all-zero DH rejected (timingSafeEqual); nonce LE + rollover guard; constant-time commitment; domain-sep hashes; MITM by construction (adversarial #3: attacker with A's PUBLIC string but not static PRIVATE → NO first ack). ZERO criticals. |
| VAL-DIVERGENCE-001 divergences logged | PASS | docs/DIVERGENCES.md (d774792): D-INT-1 nonce LE (INTERFACES "be64" superseded — KAT truth), D-INT-2 5-bit version/flags (D12 defers flags to P2); explicit "no others"; D7 BEP44→plain-announce folded into DESIGN itself |

## Gaps / honest notes
1. **VAL-ACCEPT-XNET (owner-gated GAP):** real cross-network NAT traversal between two DISTINCT
   networks is UNOBSERVED. All machinery is gate-proven (live STUN, punch 10/10, live DHT 5/5),
   but "10/10 localhost ≠ cross-NAT." Needs an owner-provided 2nd network (hotspot/VPS). Do not
   read localhost success as cross-NAT done.
2. **VAL-CLI-001 minor:** CLI listener with non-TTY stdin (`</dev/null`) self-closes on EOF —
   fine for real terminals; minor robustness item.
3. **VAL-ACCEPT-RECONNECT:** proven at unit level (mock transport), not via a real process-kill
   repro. Logic (outbox/replay/dedup) is sound + tested; a kill-restart repro would harden it.

## Tally
**28 PASS · 1 GAP (owner-gated, VAL-ACCEPT-XNET) · 0 FAIL.** v1 is looks-done == is-done for
every observable surface except real cross-network NAT, which is machinery-ready and awaits a
second network. Independent verification by zenith-manager; no src/ writes.

---

## ⚠ CORRECTION / RETRACTION (2026-07-11, post zenith end_mission terminal review)

The zenith closure terminal-review + my own re-verification against current HEAD **fc01cdf**
(NOTE: the 28/29 above was against d774792 — the tree changed since: fc01cdf added a unified
CLI/TUI + stable identity, LOC 3260→2941) found REAL reliability bugs my battery MISSED. The
verdict above is **partially retracted**:

- **GAP-001 (High, CONFIRMED):** `node.tick()` (src/node.js:326) has ZERO production callers —
  `grep '\.tick(' src/ bin/` returns only the definition. wire.js RTO-resend + keepalive PING
  fire ONLY from `channel.tick()`. So in production there is NO keepalive (NAT mappings expire
  ~30s) and NO ARQ retransmit of lost DATA/HS frames (survives only on lossless loopback).
  → **VAL-WIRE-003 keepalive claim RETRACTED to FAIL-in-production** (unit test drove tick()
  manually; the real system never does). Endangers VAL-ACCEPT-XNET durability.
- **GAP-002 (High, CONFIRMED by code):** kill-mid-chat → restart → resend does NOT work through
  the product. `connect()` short-circuits on a stale dead peer (src/node.js:319), no
  keepalive/idle close means `peer.connected` stays true after remote death, outbox replay
  (attach()) never runs. → **VAL-ACCEPT-RECONNECT RETRACTED to FAIL** (my PASS rested on
  test/node.test.js:216, which force-`close()`s first — a real user gets no death signal).
- **GAP-003 (Med, partially fixed):** shipped `p2p-chat.js` had no key persistence; fc01cdf
  added a `p2p` command with stable identity + doctor (now in package.json bin). Re-verify which
  CLI is the demo surface for VAL-CLI-001.
- **GAP-004 (Low):** VAL-ACCEPT-LOOPBACK #2 "log the commitment check" is silent on the success
  path (only under P2P_DEBUG=1 or on failure).

**Corrected standing:** ~25/29 PASS · 2 real FAIL (VAL-WIRE-003 production-keepalive,
VAL-ACCEPT-RECONNECT) · 1 owner-gated GAP (XNET, durability now also impaired by GAP-001) ·
2 notes (CLI persistence, gate logging). Root cause is small in surface (drive node.tick() on
an interval; add keepalive-timeout close; redial dead-but-"connected" peers; wire persistence
into the registered CLI) — but the build does NOT satisfy the battery as observed. Fixes belong
to the build lanes (zenith-manager does not write src/); re-validation required after they land.
LESSON: unit tests that call tick()/close() manually hid an integration gap — the same
mock-vs-real class flagged earlier for mDNS. Real-surface repros must drive the production path.

---

## ✅ RE-VALIDATION (2026-07-11, after fix commit e62943f "durability: drive node.tick() on an interval + wire liveness-death detection")

Fix verified in code: src/node.js:343 `setInterval(node.tick, 250)` cleared on close (tick now
DRIVEN in production); src/wire.js livenessMs=keepaliveMs*3, tick() closes channel on silence
(liveness death). Re-ran the RETRACTED contracts on the REAL production path (tick on its own
interval, SIGKILL not force-close, cross-process, real mDNS):

- **Repro A/C (GAP-001 + GAP-002 liveness):** listener SIGKILLed mid-chat @1783798505 → dialer
  detected disconnect @1783798511 = **6.08s = exactly livenessMs (keepaliveMs*3)**; peer.connected
  flipped false. Beats flowed over real transport for 14s with NO manual tick → tick IS driven in
  production. (Pre-fix: connected stayed true 35s+ forever.)
- **Repro A part 3 (buffered exactly-once after app redial):** send `BUFFERED-while-down` AFTER
  disconnect (listener dead) → NOT delivered to listener1; app redials `connect()` → 'reconnect'
  event, connected=true; restarted same-identity listener2 received `BUFFERED-while-down` **exactly
  once, no duplicate**. Outbox replay on attach confirmed (node.js:130 + initiatorHandshake reuses
  the S-keyed record, node.js:211).
- **Repro B (retransmit):** covered by composition — wire.test.js ARQ exactly-once under 20%
  loss+reorder+dup PASS + tick now empirically driven in production (Repro A/C).
- **Full suite:** `node --test` = **98/98** pass (was 96; +2 new liveness tests), 0 fail. Regression clean.
- **GAP-003 (CLI persistence):** RESOLVED — primary registered command `p2p` (bin/p2p.js, first in
  package.json bin) uses loadOrCreateIdentity → ~/.p2p/<profile>.json (0600), stable key across
  restarts + doctor. (bin/p2p-chat.js remains an ephemeral quick-demo secondary.)

**RE-VALIDATED VERDICTS:** VAL-WIRE-003 → **PASS** (keepalive/liveness driven in production);
VAL-ACCEPT-RECONNECT → **PASS** (v1 bar: disconnect + app-redial + buffered exactly-once; auto-redial
deferred v1.1, not a fail); VAL-CLI-001 → **PASS** (stable-identity `p2p` command); VAL-ACCEPT-TEST →
**PASS** (98/98).

**RESTORED STANDING: 28/29 PASS · 0 FAIL · 1 owner-gated GAP (VAL-ACCEPT-XNET, real cross-network run
unobserved — durability now real via live keepalive; awaits owner 2nd network).** Remaining Low note:
GAP-004 — success-path commitment-gate log is DBG-only (acceptance #2 literal "log the commitment
check"); recommend one unconditional log line. The two retracted High FAILs (GAP-001/002) are fixed
and empirically re-validated on the production path.

---

## 2ND-REVIEW ADDENDUM (pending doc fix) — tracker divergence unlogged

The 2nd zenith terminal review (post-fix) confirmed the durability fix but surfaced a divergence
I under-weighted: **src/rendezvous/tracker.js `lookup()` yields NO peers** — the D6 "live
matchmaker" role is deferred to P1 (announce = echo-only, candidate blob parked). So v1
cross-network peer discovery rests on the **DHT ip:port hint alone** (mDNS = LAN-only). This is a
deliberate v1 scope cut, BUT it is a real divergence from DESIGN D6 and is NOT recorded in
docs/DIVERGENCES.md (which currently asserts "No other intentional divergences"). → VAL-DIVERGENCE-001
is INCOMPLETE and VAL-RDV-TRACKER-001's PASS is conditional on that entry. Escalated to team-lead
(docs owner) to add D-INT-3 (tracker matchmaker → P1; v1 cross-net = DHT + mDNS-LAN) + correct the
completeness line. Mission held OPEN until logged. Also GAP-004 (Low): success-path gate check
logged only under P2P_DEBUG=1.

---

## FINAL (HEAD 5907120 — all escalated items resolved)

Team-lead resolved the doc gaps:
- **D-INT-3 logged** (commit 5907120): docs/DIVERGENCES.md now records the tracker v1-stub / D6
  deferral (v1 cross-network discovery = DHT hint + mDNS-LAN; tracker matchmaker → P1) and the
  false "no other intentional divergences" line is corrected. → **VAL-DIVERGENCE-001 PASS**
  (D-INT-1/2/3 all logged); **VAL-RDV-TRACKER-001 PASS** (v1 stub, deferral now honestly logged).
- **API-SKETCH reconnect wording reconciled** (76f2106): "app-initiated connect() redial +
  exactly-once outbox flush; auto-redial v1.1" — matches VAL-ACCEPT-RECONNECT reality.

Repro B (retransmit) — forced-loss on the REAL transport needs a drop-injection hook not present
in src (owned by build lanes; not added). Covered by composition: wire.test.js proves 1000-msg
exactly-once under 20% loss+reorder+dup at the channel level, and that channel now runs the
PRODUCTION tick path (node.js:343 setInterval + 2 new liveness tests that drive the real interval,
not hand-called tick). Tick-driven-in-production independently proven by Repro A/C (retransmit +
keepalive timers fired with zero manual tick). Direct forced-loss real-transport run: not executed
(no hook); would duplicate the channel-level test.

**FINAL STANDING: 28/29 PASS · 0 FAIL · 1 owner-gated GAP (VAL-ACCEPT-XNET).**
Notes (non-blocking): GAP-004 (Low) success-path gate log DBG-only; and a pre-existing
embed-cleanliness item — node.close() does not release rendezvous/transport sockets, so an
embedding host process won't exit on close() alone (CLI force-exits, so unaffected) — routed to
build lanes separately, relevant to the "embeddable" goal, NOT part of the v1 acceptance battery.

---

## OWNER ACCEPTANCE + CLOSE (2026-07-11)

Three independent zenith terminal reviews confirmed core v1 works (all 6 acceptance items observed).
Remaining items resolved by explicit OWNER (team-lead) decisions:
- **Reduced-scope rendezvous ACCEPTED for v1:** the WSS tracker is a P1 stub (D-INT-3); v1 cross-network
  discovery rests on the DHT single rung (+ mDNS LAN). Owner: "product is v1-correct (deliberate scope
  cut, DHT covers cross-net single-rung)." This is the explicit owner acceptance the closure review
  required. VAL-RDV-TRACKER-001 PASS (v1 stub, deferral logged + accepted); VAL-DIVERGENCE-001 PASS
  (D-INT-1/2/3 logged, contradiction fixed).
- **GAP-004 → WON'T-FIX BY DESIGN (owner):** a library that console.logs on every connection is poor
  hygiene; the visible success surface is the CLI/TUI line "✅ secure channel established — verified,
  no MITM" + the test assertions. Acceptance #2's "log the commitment check" intent is met at the
  user-facing CLI layer, not the library.
- Low notes accepted: node --test is network-coupled (live DHT gate) — intentional live-gate design;
  bin/p2p-chat.js ephemeral-identity demo doesn't cover item-5 restart (capability present via bin/p2p.js).

**FINAL VERDICT: 28/29 VAL-* PASS · 0 FAIL · 1 owner-gated GAP (VAL-ACCEPT-XNET, real 2-network run
unobserved).** v1 is looks-done == is-done for every observable surface, with the tracker matchmaker
and real cross-network run as explicitly-accepted, honestly-logged deferrals. Independent verification
by zenith-manager (validator-spine, zero src writes); durability regression caught by the terminal
review and fixed + re-validated on the real production path before this close.

### CLOSED — owner (fire17) explicit decision 2026-07-11
- **(A) v1 ACCEPTED + CLOSED** at 28/29 VAL-* PASS · 0 FAIL · 1 owner-gated GAP (VAL-ACCEPT-XNET).
  Reduced-scope rendezvous accepted: cross-network discovery = DHT (proven) + mDNS (LAN); tracker
  matchmaker deferred. D-INT-3 documents it. **VAL-RDV-TRACKER-001 = accepted reduced-scope (owner),
  matchmaker → v1.1 in progress — NOT a fail.**
- **(B) tracker matchmaker → v1.1**, routed to lane-key in parallel (live WSS offer/answer); does NOT
  hold the v1 close. When it lands, cross-network gains its redundant rung; D-INT-3/DESIGN D6 update then.
- Low notes (owner-acknowledged): node --test live-DHT coupling → CI backlog (hermetic/offline split),
  intentional live-gate value, not a blocker; bin/p2p.js (stable identity) is the shipping/demo surface
  for #5, bin/p2p-chat.js is legacy — capability present on the real surface, note only.
- Verdict trustworthiness: earned through 4 independent terminal reviews + real-path repros, incl. a
  caught-and-fixed durability regression and a divergence-honesty correction. v1 core is is-done.

### TRACKER UPGRADE + MY CORRECTION (2026-07-12) — reduced-scope framing now MOOT
The v1.1 tracker matchmaker landed early (69d8976) into the tree. I initially reported "live relay
times out" — **that was MY ERROR: I ran test/gate/tracker.test.js, which exercises `trackerRelayProbe`
(the OLD one-shot helper, tracker.js:64), NOT the shipped `createTracker()` matchmaker (tracker.js:136)
wired into the race (node.js:157).** team-lead corrected me with primary evidence; I re-ran the CORRECT
function and independently reproduced it:
- Two SEPARATE OS processes, `createTracker().announce` in one + `createTracker().lookup` in the other,
  over real public trackers (openwebtorrent / webtorrent.dev / btorrent.xyz): the looker received the
  EXACT candidate the announcer published ({udp4 203.0.113.5:4444}) — a value only the announcer knows,
  so genuinely relayed by the real tracker between two independent WSS connections — **3/3 trials, 546 /
  1193 / 581 ms.**
- → **VAL-RDV-TRACKER-001 = PASS (live-verified matchmaker)**, not "stub" and not "implemented-pending".
- docs/DIVERGENCES.md D-INT-3 updated (ca680b0) to the honest resolved status; the reduced-scope
  deferral is now MOOT — the full 3-channel rendezvous (mDNS LAN + DHT + tracker) ships + is verified.
- **Cross-network now has TWO mechanism-proven internet rungs (DHT + tracker)** instead of one; real
  two-DISTINCT-network relay remains the VAL-ACCEPT-XNET owner-gated gap (same caveat as DHT — the 3/3
  relay trials are same-machine separate-process).
- node --test: 105/105 green on the current tree (team-lead-confirmed).

**FINAL (updated): 28/29 VAL-* PASS · 0 FAIL · 1 owner-gated GAP (VAL-ACCEPT-XNET, now 2 mechanism-proven
rungs).** Tracker is a live-verified 3rd channel, not a deferral. Lesson (again): test the SHIPPED code
path, not a same-named legacy helper — I measured trackerRelayProbe when createTracker is what ships.

---

## ⚠ RETRACTION #2 (2026-07-12) — VAL-ACCEPT-RECONNECT → FAIL (bidirectional-after-restart drop)

The 6th zenith terminal review found — and I INDEPENDENTLY REPRODUCED — a HIGH correctness bug my Repro A
missed (I tested only the survivor→restarted direction; the bug is in the REVERSE direction):
- **Repro (deterministic):** dialer connects, sends m1, receives `echo:m1`; listener SIGKILLed; dialer
  sends m2 (buffers); listener restarted (same identity); dialer redials. Result: **listener2 receives m2
  and calls send('echo:m2'), the echo:m2 frame decrypts fine on the dialer's live channel, but the dialer
  NEVER fires a message event for it** (no MSG-EVENT, no divergence) — silently dropped.
- **Root cause:** `src/node.js` makePeer keeps a per-peer `delivered` Set keyed by the remote app-seq
  (node.js:113), persisted across reconnect (for outbox-replay exactly-once). A peer that restarts as a
  FRESH process resets its OUTBOUND `appSeqNext` to 0, so its post-restart messages reuse seqs 0,1,…
  already in the survivor's stale `delivered` Set → dropped as "duplicates." Dedup is NOT scoped to a
  session/handshake epoch. (Confirmed by the review's control: same flow with NO pre-kill message → the
  echo IS delivered.)
- **Impact:** any real chat that exchanged ≥1 message before the kill silently loses the restarted peer's
  first replies after reconnect. Acceptance #5 (bidirectional chat after restart) is BROKEN one direction,
  with no user-visible signal. → **VAL-ACCEPT-RECONNECT = FAIL.**
- **Fix direction (owner code, lane-wire/node):** scope inbound dedup to the noise session — reset/namespace
  the `delivered` Set on a genuinely NEW handshake (new connId/handshakeHash), so a restarted peer's fresh
  seqs aren't deduped against the prior session; keep dedup within a session for transport-reconnect replay.
- **Also GAP (LOW, docs):** README:26-27 + API-SKETCH show `identity()` sync returning `{key}`; shipped
  `identity()` is async and exposes the contact string as `S` (not `key`). Verbatim quickstart copy breaks.

**CORRECTED STANDING: 27/29 VAL-* PASS · 1 FAIL (VAL-ACCEPT-RECONNECT, bidirectional-after-restart) · 1
owner-gated GAP (VAL-ACCEPT-XNET).** node --test (105/105) does not cover this — it only tests
survivor→restarted replay (node.test.js:216) + force-close, not a fresh-process restart replying after a
prior exchange. Fix belongs to the code lane; re-validate the bidirectional path after it lands. Same
lesson as the durability regression: real-surface repros must exercise the FULL bidirectional production
path, not one direction.

### ✅ RESOLVED (2026-07-12) — VAL-ACCEPT-RECONNECT FAIL→PASS (dedup scoped to peer instance)

Fix commit **576eb59** ("node.js: scope inbound dedup to peer INSTANCE"): the `delivered` Set is RESET on
a new peer instance (fresh handshake / restarted process), while a SAME-instance transport-reconnect keeps
it (preserving outbox-replay exactly-once). The instance discriminator is correct — handshakeHash/connId
also change on same-process reconnect, so they can't distinguish restart from reconnect; a per-instance
nonce can. TRIPLE-VERIFIED (zenith-manager + lane-wire + team-lead), independent cross-process runs:
- My multi-message repro: pre-kill echo:m1a/m1b (delivered seqs 0,1) → SIGKILL → restart (fresh instance,
  same id) → redial → restarted peer's echo:m2/echo:m3 (seqs RESET to 0,1) DELIVERED, not dropped;
  FINAL=[echo:m1a,echo:m1b,echo:m2,echo:m3], exactly-once, zero dups. Previously-dropped echo:m2 now delivered.
- All 4 checklist cases met: both directions after restart; multi-msg seq-reuse not dropped; exactly-once
  intact (same-instance dedup preserved); regression test present (test/node.test.js:258 "peer RESTART
  (fresh instance) reply is NOT deduped against the dead session (bidirectional)").
- node --test 54/54 deterministic core green (no regression); team-lead's full tree-wide live suite
  confirming in parallel.

→ **VAL-ACCEPT-RECONNECT = PASS.**

## ✅✅ FINAL VERDICT (2026-07-12, owner GO): 28/29 VAL-* PASS · 0 FAIL · 1 owner-gated GAP (VAL-ACCEPT-XNET)

All 6 acceptance items + 21 module contracts + VAL-SEC + VAL-DIVERGENCE PASS on real surfaces. Tracker is a
live-verified 3rd rendezvous channel (createTracker 3/3 relay); durability (keepalive/liveness) and the
bidirectional-reconnect dedup are both fixed + re-validated on the real production path. The SOLE remaining
item is VAL-ACCEPT-XNET — a real two-DISTINCT-network run (owner-gated; needs a 2nd network) — with TWO
mechanism-proven internet rungs (DHT 5/5 + tracker 3/3, both same-machine separate-process). Trust earned
through 6 independent terminal reviews + real-path repros that caught two real regressions (a unit-mocked
durability gap, a one-direction reconnect gap) that `node --test` green alone never would have. v1 is
is-done for every observable surface; XNET awaits the owner's second network.

### 🏁 ZENITH MISSION CLOSED — state=`done` (2026-07-12)

The zenith harness reached clean closure on the 8th terminal review (`mission-001` → `done`). Final
blocker (README Install block advertising p2p.akeyo.io before it shipped) resolved when the owner shipped
tasks #16/#17/#18; I independently re-verified: `https://p2p.akeyo.io/init` → **http=200, ssl_verify=0**
(valid cert), body `#!/bin/sh # p2p installer`, and `https://p2p.akeyo.io/` serves the live SPA. The
earlier SSL(60) was the Pages cert still provisioning. README is now accurate — docs match reality.

**CLOSED AT: 28/29 VAL-* PASS · 0 FAIL · 1 owner-gated GAP (VAL-ACCEPT-XNET).** All 6 acceptance items
observed-PASS; owner's full tree-wide suite 106/106. Informational note carried forward: several modules
exceed DESIGN §4's ±30% per-module soft guardrail (total 3126 LOC still within the 2.5–3.5k envelope, AC6
honesty holds) — owner will relax the §4 wording in a polish pass.

**Sole remaining real work: VAL-ACCEPT-XNET** — a chat between two processes on two DISTINCT networks.
Unobservable single-host; both internet rungs (DHT 5/5, tracker 3/3) are mechanism-proven same-machine.
Needs the owner's second network (hotspot/VPS). Everything else: is-done, observed.

### 🌐 BROWSER CLIENT P1 — browser↔browser, VERIFIED IN A REAL BROWSER (2026-07-12)

Design study: `research/browser-client.md`. Build: `src/browser/` (client + shims + vendored crypto +
WebRTC transport) — the TUI's core `src/` is untouched. The browser runs the SAME protocol source as
the TUI (`key.js`/`noise.js`/`wire.js`/`node.js`/`group.js`) via a `node:crypto` import-map shim + a
Buffer shim, so interop is structural (same source ⇒ same bytes), not a re-implementation.

**Observed (not claimed):**
- **BC-G1 — crypto/protocol parity (CI-gated):** the real `src/noise.js` on the browser stack (shim
  crypto + vendored noble) reproduces BOTH official Noise KAT vectors (cacophony + snow) BYTE-EXACT,
  and browser+TUI `deriveRid` agree — `test/browser-noise-parity.test.js`. Every primitive is byte-equal
  to `node:crypto` — `test/browser-shim.test.js` (12 cases).
- **BC-G2+G3 — real browser E2E:** two Chromium contexts (distinct origins) found each other over the
  LIVE public WSS trackers and completed a verified Noise IK handshake over a real WebRTC DataChannel,
  chatting both directions in **~3.5 s**; a bogus key is rejected locally by the checksum —
  `test/browser-e2e.mjs` (Playwright, loaded from the npx cache so package.json stays zero-dep).
- **BC-GROUP — groups >2 in real browsers:** 3 Chromium peers, `group.send()` pairwise fan-out, all
  ACKed + received E2E — `test/browser-group.mjs`.
- **BC-SEC — MITM resistance, adversarially:** the commitment gate rejects an attacker's substituted
  keys (2¹¹⁰), Noise IK fails CLOSED against an impostor responder, the honest path still completes —
  `test/browser-mitm.test.js`. Security on the wire is **= TUI**, by running the identical handshake.
- **Regression:** the existing deterministic suite stays green — **104/104 `test/*.test.js`**, +26 new.

**Two real CSP bugs were caught by actually running it in a browser** (import map is an inline script →
now allowed by hash not `unsafe-inline`; `frame-ancestors` is invalid in `<meta>` → dropped) — the exact
kind of gap `node --test` green never shows.

**Remaining (honest):** browser↔TUI (P2) is DESIGNED not built — it needs the owner's interop decision
(optional `werift` dep for direct P2P vs the zero-dep WSS-relay in `src/transport-wss.js`); and a
two-real-networks browser↔browser run (same XNET gate the TUI has). Sender-keys groups are the P3 scale
upgrade (pairwise fan-out is correct for small groups). Code-delivery trust (§8.4) documented, not
eliminated.
