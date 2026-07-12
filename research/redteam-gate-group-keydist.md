# Redteam CAG Gate (POST-SHIP) — 43ccd5d (group sender-key self-heal)

> **Lane:** redteam / CAG-gate (opus @ xhigh). **43ccd5d is LIVE on p2p.akeyo.io** (rode into the
> v0.3.0 push ungated). Gated the COMMIT as-is @ 43ccd5d (parent 0feb879) — the dirty working-tree
> src/group.js (tui-group's follow-up) was NOT included. In-process only, no live network.

## Verdict: **CONFIRMED-SHIP — production is clean.** No DOS, no key-leak, honest FS, no regression.

Fix: `toMember()` rides an existing live pairwise peer (`livePeer(S)`) before falling back to
`connect(S)`, so a member who cannot dial back (browser/NAT) still receives sender keys; + a self-heal
that HOLDs an undecryptable MSG and pulls the key via KEYREQ, then replays.

## Angle 1 (PRIORITY — is the self-heal BOUNDED? yes) — NOT a DOS

- **Stash key count is membership-gated.** `onMsg` runs `if (!members.has(S)) { emit 'msg-nonmember';
  return }` as its FIRST act — BEFORE any `hold(S,body)` or `requestKey(S)`. So an attacker cannot mint
  stash entries with invented `S` values; only signed-chain members reach the stash. Distinct stash
  keys ≤ |members| (an admin-controlled, finite set).
- **Per-sender cap.** `hold(S,body)`: `if (q.length >= MAX_STASH) return` with `MAX_STASH = 32`. So the
  whole stash is bounded by `|members| × 32` MSG bodies — no unbounded heap growth.
- **KEYREQ is deduped + gated.** `requestKey(S)`: `if (pulling.has(S) || recvChains.has(S) || S===me)
  return` — one outstanding KEYREQ per member (the `pulling` Set), cleared on arrival/failure; and it
  is only reached past the `members.has(S)` gate. No KEYREQ storm from a chatty/hostile peer.
- **earlyKeys** capped at `MAX_EARLY = 64`. The KEYREQ SERVE path (`type===T.KEYREQ`) is
  `bindIdentity(R)` + `members.has(R)` gated and re-sends statelessly (no memory growth; a repeated
  KEYREQ costs one proportional keydist, not heap).
⇒ Bounded on every axis. **Not a shipped-build DOS. No FIX-FIRST on angle 1.**

## Angle 2 (no key-leak to the wrong peer) — sound

`toMember(S,env)` sends over `livePeer(S) = peers.find(p => p.connected && p.key===S)`. `p.key` is the
Noise-authenticated remote static (S is the commitment to the peer's pubkeys, verified in the IK
handshake), so the channel is cryptographically bound to S in BOTH directions. The fallback is
`node.connect(S)` — a fresh authenticated dial. A member's sender key can only travel a channel
authenticated to S; it cannot be mis-routed to an unintended member. ✓

## Angle 3 (forward-secrecy honesty) — honest, documented, no broken-ratchet

`applyKeydist(S,body)`: the arriving chain key is for seq `q`; the ratchet is one-way, so `for (const b
of held) if ((b.q||0) >= q) onMsg(b)` — only messages from `q` on are replayed. Anything with `b.q < q`
is NOT recovered; instead `emit('divergence', { reason:'unrecoverable-history', count:lost })`. No
attempt to un-ratchet or fabricate a prior key. The code comment states it plainly ("forward secrecy
doing its job … never claim a message we cannot actually read"). ✓

## Angle 4 (no regression) — verified

- **RED→GREEN:** reverting `src/group.js` to parent 0feb879 → `group-keydist.test.js` **0 pass / 5
  fail** (the 5 new tests genuinely fail without the fix); restored → all pass. Genuine guards.
- **Full group suite @43ccd5d:** `group.test.js + group-secure.test.js + group-keydist.test.js` →
  **19/19 pass, 0 fail** — GRP-1..5 (forged authorship, blind relay, cryptographic removal, checksum)
  regression intact, plus the 5 new keydist tests incl. "10/10: the cannot-dial-back member round-trips
  on every one of ten runs" and "a missed keydist + a later message must trigger a KEYREQ pull, not a
  forever-warning" (the owner's exact symptom).

## CAG §6
1. Closes no-sender-key for a member that can't dial back (browser/NAT) — the shipped bug.
2. New parts: `livePeer` ride, `stash`/`hold`, `requestKey`/KEYREQ, `applyKeydist` replay — each
   membership-gated + bounded (enumerated above).
3. Weakest-link unchanged: authorship is still Ed25519-signed + ratchet-AEAD; the ride only changes
   TRANSPORT selection, not the trust boundary.
4. Reliability: the cannot-dial-back member now delivers (10/10); existing members unaffected.
5. Degenerate-safe: no live peer ⇒ falls back to `connect()` (old behavior).
6. Monitor: group-keydist.test.js (RED→GREEN) + the unrecoverable-history divergence.
7. Reversible; wire adds only KEYREQ (already present since GRP-4).
8. Reused the existing pairwise link — minimal.

## Standing-resident
43ccd5d CONFIRMED-SHIP — production is clean; no hotfix needed on these axes. The bounded-stash values
(MAX_STASH=32, MAX_EARLY=64) are already present as-shipped; the tui-group follow-up (uncommitted tree)
is a separate gate. Resident.

---

## FOLLOW-UP GATE — d2d6c0c (bound the self-heal) — CONFIRMED-SHIP + honest correction + a test-weakness note

d2d6c0c is ALSO LIVE (rode the v0.3.1 hotfix 35132da). Gated @ d2d6c0c (parent 32b8dbf), in-process.

### Honest correction to my 43ccd5d call
In the 43ccd5d gate I wrote "no KEYREQ storm." That was INCOMPLETE. `requestKey` clears the `pulling`
dedup on a FAILED pull (`.catch(() => pulling.delete(S))`), so a sender whose key never lands AND who is
unreachable (`toMember` rejects — precisely the cannot-dial-back browser case 43ccd5d targets) fires a
FRESH KEYREQ for EVERY subsequent dropped message: a ~1:1 message→KEYREQ traffic storm (not a heap DOS —
the stash bound I verified holds — but a real network-amplification storm). d2d6c0c closes it; both are
live so prod is now clean, but I should have flagged the storm in 43ccd5d.

### The fix (verified by code)
- `MAX_KEYREQ = 8`, a `keyReqs` Map (S→count). `requestKey`: `if (spent >= MAX_KEYREQ) return; keyReqs
  .set(S, spent+1)` — at most 8 KEYREQs over a gap's life, surviving the failed-pull re-fire.
- Reset: `keyReqs.delete(S)` fires ONLY in `applyKeydist` (a valid signed key actually landed → gap
  closed). An attacker cannot force `applyKeydist` (needs the sender's real key), so the budget cannot
  be gamed into re-storming. **Angle 1 sound.**
- `MAX_STASH 32→16`, evict-OLDEST (`while (q.length >= MAX_STASH) q.shift()`). The stash is PER-SENDER,
  so evicting oldest touches only that sender's own held messages — an attacker flooding under their own
  S cannot force-evict a DIFFERENT member's message (different S ⇒ different queue). Keeping the newest
  is correct: a chain key at seq q decrypts only seq ≥ q. **Angle 2 sound.**

### Tests (my runs)
- GREEN @d2d6c0c: `group + group-secure + group-keydist` → **20/20** (GRP-1..5 intact + "bounded
  self-heal" + "10/10 cannot-dial-back").
- RED @parent 32b8dbf (bounds reverted): the "bounded self-heal" test FAILS at **BOUND 2** —
  `AssertionError: the admin must hold at most MAX_STASH(16) … replayed 32`. So the STASH bound is a
  genuine RED→GREEN guard.

### ⚠️ Test-weakness note (angle 3) — BOUND 1 does NOT reproduce the storm
The test drops D's KEYDIST **response** but its `interceptSends(A.node, …)` **allows A's KEYREQ send**
(`return true`), and A↔D have a live peer — so the KEYREQ send SUCCEEDS, `pulling` STAYS set, and no
per-message re-fire happens: `keyreqs ≈ 1`, which is `≤ 8` with OR without `MAX_KEYREQ`. Evidence: the
RED run at parent (no cap) still PASSED BOUND 1 and only failed BOUND 2. So the `≤8` assertion is
trivially satisfied and does **not** guard the KEYREQ-cap regression — the storm needs a send-FAILURE
(`toMember` reject → `pulling.delete`), which this setup never creates. The FIX is correct by code
(above); only its regression guard is weak. **Recommend:** strengthen BOUND 1 to make `toMember(D)`
reject (D unreachable — no livePeer, `connect` fails), so `keyreqs` genuinely storms to ~FLOOD without
the cap and the `≤8` assertion actually bites.

### Verdict
**d2d6c0c CONFIRMED-SHIP** (and 43ccd5d stands CONFIRMED-SHIP — the KEYREQ storm it carried is now
closed by d2d6c0c, both live). The bounds are correct and the stash guard is genuine; the KEYREQ-cap's
test guard is weak (noted, SHOULD-strengthen, not a product defect — the code is right). No hotfix
needed. The AUDIT-style follow-up (task #16) and the BOUND-1 strengthening are test-only.
