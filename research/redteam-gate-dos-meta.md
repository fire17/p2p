# Redteam CAG Gate — b9b6819 (DOS-1 accept-path + META-1 HELLO gate)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Independent review leg. Analysis + verification only.
> **Date:** 2026-07-12. **Commit:** `b9b6819` — `src/transport.js` + `src/node.js` + `test/dos-meta-harden.test.js`.
> **Isolation:** clean detached worktree @ b9b6819 (main tree was dirty with browser-pc-churn's
> `OFFERS_PER_ANNOUNCE→PARKED_OFFERS_PER_SLOT` WIP — kept out). Parent for RED: `2a4169a`.

## Verdict: **CONFIRMED-SHIP** (both DOS-1 and META-1). No DEVIATION, no open GAP.

Last HIGH before v0.3.0-dev.2. The commit's own `UNVERIFIED` note (werift/browser witnesses) is **closed
by me** below — it was a WIP artifact, not a real regression.

## My own test output

**dos-meta-harden.test.js @ b9b6819 → 9/9 pass, 0 fail:**
```
✔ DOS-1 (transport): pending cap bounds _accepted/_peers under a PROBE flood — GREEN vs unguarded RED
✔ DOS-1 (transport): accepted-but-no-HS1 probes are idle-evicted after the pending TTL
✔ DOS-1 (transport): per-source PROBE rate-limit drops a same-IP flood before it allocates
✔ DOS-1 (node): a delivered accept that never sends HS1 creates NO peer record (deferred to auth)
✔ DOS-1 (node): inbound peer records are capped — a flood cannot exhaust memory or evict live peers
✔ META-1 (transport): probeAuth gates the ACK+accept — a bad-proof PROBE gets NOTHING back
✔ META-1 (node): invite mode — a scanner without the K_inv proof never elicits the HELLO; the invitee does
✔ META-1 (e2e): the honest invitee completes a full IKpsk2 handshake THROUGH the live probeAuth gate (real UDP)
✔ META-1 (node): reusable-S mode is UNCHANGED — any PROBE still elicits the cleartext HELLO
```
Full deterministic glob `test/**/*.test.js` → **208 pass / 0 fail, exit 0**.

**RED-without / GREEN-with** (revert transport.js+node.js to parent 2a4169a, keep the tests):
```
DOS-1 transport pending-cap flood   : ✖ RED (assertion fails, then the unbounded flood also hangs) → ✔ GREEN
DOS-1 node inbound-cap flood         : ✖ RED (58ms clean assertion fail)                             → ✔ GREEN
META-1 transport bad-proof-gets-none : ✖ RED (4.5ms — unguarded, a bad proof still gets a PROBE_ACK) → ✔ GREEN
META-1 node scanner-no-HELLO         : ✖ RED (411ms — unguarded, the scanner DOES elicit the HELLO)  → ✔ GREEN
```
All four headline guards are genuine regression tests (fail without the fix, pass with it).

**Witnesses re-run at the clean milestone (closes the commit's UNVERIFIED note):**
- werift node↔node selftest → **PASS** (real ICE + DataChannel + Noise IK; both established,
  `peer.key === S`, bidirectional delivery).
- browser↔browser e2e (Playwright) → **PASS** (G2 tracker rendezvous + G3 WebRTC + Noise IK; both
  messages E2E-encrypted AND ACKed).

  The author marked these UNVERIFIED, blaming a `src/browser/webrtc.js:490` reference to undefined
  `OFFERS_PER_ANNOUNCE` "at committed HEAD". That was the **browser-pc-churn lane's uncommitted rename
  WIP** contaminating the shared tree — NOT b9b6819. At the clean b9b6819 worktree, `webrtc.js` is the
  working milestone (`OFFERS_PER_ANNOUNCE` defined :48, used :422) and both witnesses pass. b9b6819 does
  not touch the browser transports, so this was never its regression. **Independently confirmed.**

## Source facts I verified

- **META-1 rides the existing 21-byte PROBE — no wire change.** `probePkt` allocates exactly 21 bytes
  (`PUNCH_MAGIC 4 ‖ type 1 ‖ tok8 8 ‖ nonce8 8`); the proof IS the 8-byte nonce field. Reusable-S sends
  a random nonce, invite mode sends `probeProof = HKDF(K_inv,"p2p-rvk-probe-v1", info=tokenHex, 8)` — an
  HKDF output is indistinguishable from the random bytes it replaces, and `PROBE_ACK` echoes it exactly
  as before. No new field, no length/shape signal. The `reusable-S HELLO unchanged` test passes GREEN.
- **The proof compare is constant-time** — `invite.js equal()` is `timingSafeEqual` (length-checked).
- **The HELLO gate is airtight for the off-path adversary** — `_acceptInbound` runs
  `if (this._probeAuthCb && !this._probeAuthCb(tok, nonce, rinfo)) return` BEFORE the `PROBE_ACK` and
  before any accept; an unauthenticated prober gets total silence (not even the ACK that would confirm a
  listener lives here). The authenticator recomputes the proof over the RECEIVED token, so only a
  K_inv holder matches. `node.js` installs it **only** in invite mode (`if (node._invite …)`).
- **Peer records are deferred to auth (DOS-1).** `socket.confirm()` is called in `acceptConnection`
  only AFTER `hs.readMessage` authenticates HS1; the peer record is minted no earlier. A flood of
  never-handshaking PROBEs stays in the transport's pending sub-cap and never becomes a record.
- **Inbound is capped separately from dials.** `admitInbound` counts only `r._inbound` records against
  `MAX_INBOUND_PEERS`; outbound dials are uncounted, so an inbound flood can never block the user's own
  `connect()`. When full it sheds a *worthless* record (inbound + `!connected` + empty outbox) or
  **refuses the newcomer — it never evicts a live/owed peer** (correct: evicting the stalest connected
  peer would hand a flooder session-teardown power).

## CAG §6

1. **Residual-closed:** DOS-1 — an unauthenticated PROBE/HS1 flood minted *unbounded* pre-auth
   `socketLike`s + peer records (zero-cost, remote, no spoof needed); now hard-capped
   (`MAX_ACCEPTED=256`, pending sub-cap `MAX_PENDING=64`), swept (`PENDING_TTL 20s`, `ACCEPT_IDLE 90s`),
   and rate-limited (per-source PROBE bucket + global accept bucket). META-1 — a cleartext HELLO handed
   `edPub‖xPub` to *any* party reaching the socket (an off-path IP↔identity confirmation oracle that
   undercuts invite mode); now only a K_inv-proving invitee elicits it.
2. **Attack-surface enumeration:** new parts = two token buckets, LRU limiter table (`MAX_SOURCES=4096`),
   sweep timer, pending/confirmed split, `probeAuth`. Adversaries: (a) PROBE flood one source → per-source
   bucket + hard caps; (b) **spoofed-source** flood → per-source bucket is defeated by construction
   (honestly conceded in-code) but the hard caps + sweep bound memory regardless; (c) never-send-HS1 →
   pending sub-cap + `PENDING_TTL`; (d) reusable-S HS1 flood with fresh statics → `MAX_INBOUND_PEERS`
   cap; (e) forge/omit the META proof → silence; (f) the limiter table itself → LRU-bounded (not a leak).
3. **Weakest-link:** pre-change weakest link was an *uncapped* pre-auth allocation path (0 bound).
   Post-change the weakest link is the `MAX_INBOUND_PEERS` slot budget — a bound where there was none.
   Strictly stronger. Honest-load headroom is real: `MAX_ACCEPTED=256` ≈ 25× the <10 realistic peak,
   `PENDING_TTL 20s` = 10× the 2s HELLO-retransmit window, `ACCEPT_IDLE 90s` > wire `livenessMs=75s`
   (so the wire declares a peer dead *before* this sweep can touch it — a live channel is never killed).
4. **Reliability proof:** the honest dialer costs exactly one accept token and one inbound slot; its ICE
   burst (~50 PROBEs/s/source) sits far under `PROBE_RATE=200`; the META proof is deterministic from
   `(K_inv, token)` so the invitee always matches. The real-UDP e2e (IKpsk2 through the live gate) +
   both witnesses prove the honest path is intact. `P(connect)` for a legitimate peer is unchanged.
5. **Degenerate-safe:** reusable-S installs no authenticator and is **byte-identical** (test :339 GREEN);
   all bounds default to the shipped constants; under attack it refuses newcomers rather than dropping
   below baseline (never evicts a live peer).
6. **Monitoring hook:** the nine `dos-meta-harden.test.js` assertions ARE the standing regression guards
   (all verified RED-without / GREEN-with by me).
7. **Flag-gated/reversible:** every bound is a constructor opt; META-1 is scoped to invite mode only;
   reusable-S wire is byte-identical. The invite-mode HELLO-gate is a deliberate behavior change (a
   scanner now gets silence) — correct, not a compat break (invite mode is new in the 0.3.0 line).
8. **Simplicity dominance:** token-bucket + bounded table + TTL sweep is the minimal standard accept-path
   bound (mirrors the already-shipped DOS-1-WSS guards — one doctrine, two transports). The META proof
   reuses the existing nonce field — no new wire real-estate. Not dominated.

## Residuals (honestly stated in-code, and I concur they are acceptable)

- **DOS-1:** a flooder that *keeps 256 handshaked channels alive* (must keepalive each — wire kills a
  silent channel at `livenessMs`) can deny NEW inbound peers. Memory stays bounded, established sessions
  and outbound dials keep working. This is slot-exhaustion, not memory-exhaustion — the right trade.
- **META-1:** an ON-PATH observer can replay a `(token, proof)` pair, but gains nothing — the same
  position already reads the cleartext HELLO. The closed adversary is the OFF-PATH prober (scanner /
  infra-collusion address holder), which is exactly META-1's target. Correct scoping.

## Standing-resident

b9b6819 clear to ship — the last HIGH before v0.3.0-dev.2. Remaining lane: **browser-pc-churn** (BRW-4b,
just landed as c43d647) — I will gate it with a REAL-CHROMIUM soak per the method fix in
`redteam-gate-brw-dos-wss.md` (werift cannot see the construction-churn axis).
