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
