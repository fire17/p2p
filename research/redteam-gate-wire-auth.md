# Redteam CAG Gate — d651605 (WIRE-1/2/3 control-plane authentication)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Independent review leg (wire-auth flagged advisor unavailable — this IS the second pair of eyes). Analysis + verification only.
> **Date:** 2026-07-12. **Gated commit:** `d651605` "harden(wire): authenticate the control plane — MAC every frame".
> **Isolation:** clean detached worktree pinned at `d651605` (grp-harden's concurrent `group.js` WIP kept out).

## Verdict: **CONFIRMED-SHIP** — with one release-coordination note (below), not a defect.

The fix is correct, the tests are rigorous (not hollow), the invalidated real-wire witnesses pass on the
new format, and the MAC gates every control-plane state transition. No DEVIATION in the security logic.
The single flag is a **breaking wire change vs released v0.2.0** — right for a fail-closed security fix,
but the release must treat it as a coordinated protocol bump (see §Ship-note).

## What the fix does (verified against source)

Every channel frame gains a trailing 16B truncated-HMAC-SHA256 over `type‖connId‖seq‖ack‖payload`
(`src/wire.js` `macTag`, `encodeFrame(...,macKey)`). `decodeFrame(buf, macKey)` recomputes and
`timingSafeEqual`-checks it, returning `null` (fail-closed) on any mismatch. Keys are DIRECTIONAL,
derived by `node.js wireMacKeys(handshakeHash, role)` via HKDF-SHA256 over the Noise handshake hash
(`i2r`/`r2i` domains); initiator `{tx:i2r, rx:r2i}`, responder the mirror ⇒ my-tx == your-rx.
`createChannel` FAILS CLOSED without valid distinct keys.

Two independent source facts I verified (the load-bearing ones):

1. **`noise.split()` returns a real handshake hash** — `src/noise.js:409-417` returns
   `handshakeHash: Buffer.from(this.h)`. Not undefined ⇒ `wireMacKeys` HKDF has real input material.
   (If it were undefined the keys would silently collapse to a constant; it is not.)
2. **The MAC gate sits ABOVE every state mutation** — `src/wire.js` `onDatagram` (lines ~309-343):
   ```
   const hdr = decodeFrame(buf)                 // cheap connId check only
   if (!hdr || !hdr.connId.equals(connId)) return
   const f = decodeFrame(buf, macRx)            // AUTHENTICATED decode
   if (!f) { authFails++; return }              // ← nothing below runs for a forged frame
   lastRecvAt = now()                            // liveness  — below the gate
   ... onRoamCb(rinfo)                           // roaming   — below the gate
   onAck(f.ack)                                  // WIRE-1    — below the gate
   case DATA: onData(f.seq,...)                  // WIRE-3    — below the gate
   case CLOSE: closed=true; onCloseCb('peer')    // WIRE-2    — below the gate
   ```
   No ack, no rcvNext, no roam, no teardown, no liveness-extension for a frame that does not
   authenticate. WIRE-1/2/3 are genuinely gated at the single choke point.

## My own test output

**Deterministic suite (isolated worktree @ d651605):**
- `node --test 'test/**/*.test.js'` → **196 pass / 0 fail / 0 skipped, exit 0** (182s).
- `node --test` (full auto-discovery incl. .mjs) → **206 pass / 0 fail, exit 0** (188s).
- targeted `node.test.js + invite-mode.test.js + gate/integration.test.js` → **25 pass / 0 fail**.
  (An earlier combined run showed exit 1 — traced to a manual `.mjs` e2e returning nonzero under
  auto-discovery, NOT a deterministic-test failure: zero `not ok` lines in its output. The clean
  re-runs above are exit 0.)

**The three WIRE forgery tests + hardening set (`test/wire.test.js`) — bodies read, confirmed rigorous:**
```
✔ WIRE-1: a forged ack (even inside a PING) does NOT drain the send window
✔ WIRE-2: a forged CLOSE is ignored; the real CLOSE still closes
✔ WIRE-3: a forged DATA does NOT advance rcvNext — the real frame for that seq still delivers
✔ reflection: our OWN frames echoed back at us do not authenticate (directional keys)
✔ a single flipped byte in an authentic frame is dropped (integrity, not just origin)
✔ createChannel FAILS CLOSED without directional MAC keys (no unauthenticated mode)
✔ MAC rides inside the MTU budget (sendReliable still refuses to exceed the datagram)
```
Not hollow: WIRE-1 drives 5 real in-flight segments, fires 3 forged inflated-ack frames
(PING/ACK/DATA), asserts `inflight==5` + `authFails==3`, THEN a real cumulative ack still drains to 2.
WIRE-3 injects garbage at the exact next-expected seq, asserts `rcvNext` unmoved + nothing delivered,
then the real seq-0 frame still delivers (the precise silent-loss scenario). The reflection test feeds
the channel's OWN emitted bytes (`sent[0]`) back in — a real reflection, rejected by `tx≠rx`. The
`forged()` helper signs with NO key (models the on-path bare-header forger); `peerFrame()` signs with
the peer's real directional key. Correct threat model.

**Legit ARQ unchanged (CAG check 4), MACs live on every frame:**
```
✔ 1000 msgs each way under 20% loss + reorder + dup arrive exactly-once in-order (78ms)
✔ connId roaming mid-stream: peer IP change keeps delivery flowing (D9)
✔ exactly-once under pure duplication (no loss)
✔ resend buffer + exactly-once across reconnect (dropped app-ack, then replay)  [node.test.js]
```

**Wire-format-invalidated WITNESSES, re-run on the new format (isolated worktree):**
- **werift node↔node selftest** — CONFIRMED it RAN (werift present, not self-skipped). PASS: two peers
  over the REAL public WSS trackers, real ICE + real DataChannel, Noise IK; both established,
  `peer.key === S` on both sides (MITM-free), bidirectional messages delivered. *This is the empirical
  proof the directional MAC keys derive identically end-to-end* — if my-tx ≠ your-rx, zero frames would
  authenticate and nothing would deliver; both directions delivered.
- **browser↔browser e2e** (Playwright) — PASS: G2 tracker rendezvous + G3 WebRTC + Noise IK; both
  messages delivered **E2E-encrypted AND ACKed** (the ACK proves both the MAC'd DATA and the MAC'd ACK
  authenticate over the real browser wire).
- **reusable-S + invite** — reusable-S proven by werift + browser (real wire) and by `node.test.js`
  (real wire.js + MAC under a mocked transport: 25/25 incl. reconnect/exactly-once); **invite** proven
  by `invite-mode.test.js` (green in the targeted run — invite handshake → authenticated channel).

## CAG §6

1. **Residual-closed (quantified):** closes WIRE-1 (forged ack drains the send window ⇒ silent loss +
   wedged sender), WIRE-2 (forged CLOSE ⇒ channel teardown), WIRE-3 (forged DATA advances `rcvNext`
   pre-AEAD ⇒ the real frame for that seq is later dropped as "already delivered" — permanent silent
   per-message loss). Adversary: any on-path observer or hostile WSS relay that reads the cleartext
   connId. Cost to attacker pre-fix: **1 forged packet = 1 erased message / a drained window / a dead
   channel.** Post-fix: forging a valid tag is 1/2¹²⁸. Does NOT change payload confidentiality (already
   AEAD) and does NOT stop a raw garbage-flood DoS — but such a flood now moves ZERO state (one cheap
   HMAC verify, then drop).
2. **Attack-surface enumeration:** new parts = `macTag` (HMAC), authenticated `decodeFrame` path,
   `wireMacKeys` HKDF, `createChannel` key guards, `encodeFrame` macKey arg, `authFails` counter.
   Adversary tries: (a) forge a tag → 1/2¹²⁸; (b) reflect our own frame → directional keys reject
   (tested); (c) cross-session replay → fresh-per-handshake keys reject; (d) within-session replay →
   existing ARQ seq-dedup (DATA) / idempotent cumulative-ack (ACK) absorb it; (e) strip the MAC → length
   + verify fail-closed (tested: truncated frame dropped); (f) 1-byte tamper → HMAC fail (tested);
   (g) undersized or equal tx==rx keys → `createChannel` throws (tested). No unenumerated part.
3. **Weakest-link map:** post-change weakest link = the 128-bit truncated-HMAC tag — same strength
   class as the AEAD 128-bit tag the system already trusts. Baseline weakest link was an
   **UNAUTHENTICATED (0-bit) control plane.** Strictly, enormously stronger.
4. **Reliability proof:** authenticated frames are exactly the frames a real peer sends (my-tx==your-rx,
   proven live by werift/browser bidirectional delivery), so `P(delivery)` for legit traffic is
   unchanged — and the 1000-msg 20%-loss+reorder+dup exactly-once, roaming, and reconnect tests all pass
   WITH the MAC on every frame. ✅
5. **Degenerate-safe:** no keys ⇒ `createChannel` throws (there is deliberately no unauthenticated
   mode — that mode WAS the bug); under attack ⇒ forged frames dropped while the legit stream keeps
   flowing (WIRE tests show the real frame still delivers after the forgery). Never degrades below
   baseline behavior for an authenticated peer.
6. **Monitoring hook:** `stats().authFails` counts every MAC-gate drop (i.e. every forgery/tamper/
   reflection attempt). The WIRE tests assert exact `authFails` values (3, 1, 1, 2). Standing
   attack-monitor in place — CAG check 6 satisfied.
7. **Flag-gated + reversible:** **INTENTIONALLY NOT flag-gated / NOT byte-identical.** A flag that
   re-enabled the un-MAC'd mode would re-open WIRE-1/2/3, so fail-closed is the correct design — but
   this is a formal departure from CAG check 7's letter and, more importantly, a **breaking wire change**
   (see Ship-note). Reversibility is by reverting the commit, not by a runtime flag.
8. **Simplicity dominance:** truncated-HMAC-per-frame is the minimal standard construction for
   control-plane authentication. The alternative (encrypt the whole frame) is heavier and redundant
   with the AEAD payload. Not dominated.

## Ship-note (the one thing the owner must weigh — not a defect)

**d651605 is wire-incompatible with released v0.2.0 peers.** Pre-handshake frames (HELLO/HS1/HS2) are
unchanged, so a v0.2.0 peer and a d651605 peer still COMPLETE the Noise handshake — but then:
- new→old: the new peer's MAC'd DATA reaches the old peer's `decodeFrame(buf)` (no key), which treats
  the trailing 16 MAC bytes as payload ⇒ AEAD fails ⇒ garbage/drop;
- old→new: the old peer's un-MAC'd frame fails the new peer's `decodeFrame(buf, macRx)` ⇒ dropped as
  a forgery.

Result: **handshake succeeds, then NO application messages flow** — a silent post-handshake break.
For a fail-closed security fix this is *acceptable* (you WANT to refuse the vulnerable protocol), and
the `maxMessage` budget also shrank 1162→1146 (16B MAC), correctly recomputed in BOTH
`wire.js maxPayload` and `node.js peer.maxMessage`. But it means the release is a **breaking protocol
bump (→ v0.3.0)**, and every peer must be on the new build to interop. Since the owner is bumping the
clean test build (:8000) wholesale to d651605, there is no mixed-version fleet in practice — flagging
so the version bump + CHANGELOG note is deliberate, not accidental.

## Standing-resident

Gate GREEN for d651605. grp-harden (GRP-1/2/3/4/5) has since landed on top (8aa4b10, 29b66c0, 575f1d4,
adb99f2). This lane stands resident to gate those `group.js` commits next, same CAG §6 discipline.
