# Redteam CAG Gate — GRP cluster (group.js hardening, 4 commits)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Independent review leg (advisor was unavailable to grp — this is the second pair of eyes). Analysis + verification only.
> **Date:** 2026-07-12. **Isolation:** clean detached worktree @ HEAD (4bd4032); per-commit RED/GREEN by reverting `src/group.js` to each commit's TRUE parent.
> **Commits:** 8aa4b10 (GRP-1/5) · 29b66c0 (GRP-2) · 575f1d4 (GRP-3) · adb99f2 (GRP-4). All touch only `src/group.js` + `test/group-secure.test.js`.

## Verdicts

| Commit | Item | Verdict |
|---|---|---|
| 8aa4b10 | GRP-1 canonical Kahn fold + rival-create divergence | **CONFIRMED-SHIP** (fix + genuine test; residual noted) |
| 8aa4b10 | GRP-5 sign the `init` roster | **CONFIRMED-SHIP (fix)** + **GAP (test is a false guard)** |
| 29b66c0 | GRP-2 every survivor rotates on removal | **CONFIRMED-SHIP** (headline verified; old test proven vacuous) |
| 575f1d4 | GRP-3 sign KEYDIST bodies | **CONFIRMED-SHIP** |
| adb99f2 | GRP-4 durable late-join KEYREQ pull | **CONFIRMED-SHIP** (residual correctly out of scope) |

Escalations: **(a) GRP-2 O(n) survivor rotations — BLESSED** (required; O(n²) KEYDIST cost noted). **(b) GRP-1 lowest-opHash-create-wins — BLESSED as canonical+detectable, with an honest residual: it does NOT prevent an insider from seizing admin, it makes the contest deterministic and surfaced.**

## Per-commit RED-without / GREEN-with (my own runs)

Method: revert ONLY `src/group.js` to the commit's true parent, keep the HEAD test, run the named test.
True parents (verified via `git rev-parse`): 8aa4b10←c9d567b, 29b66c0←d651605, 575f1d4←29b66c0, adb99f2←575f1d4.
(d651605 (WIRE) does not touch group.js, so its group.js == 8aa4b10's — the GRP-2 parent revert is valid either way.)

```
GRP-1  RED @c9d567b: ✖ "all peers must agree the SAME admin, got [08601B…, 0KQ079…, 08601B…]"  → GREEN @HEAD ✔
GRP-2  RED @parent : ✖ "the removed member decrypts NOTHING even handed B's ciphertext (GRP-2)"  → GREEN @HEAD ✔
GRP-3  RED @29b66c0: ✖ "B rejects the forged KEYDIST (signature gate)"                            → GREEN @HEAD ✔
GRP-4  RED @575f1d4: ✖ "the late joiner decrypts after being re-keyed (GRP-4)"                    → GREEN @HEAD ✔
GRP-5  @c9d567b     : ✔ PASSES pre-fix — NOT a RED guard (see GAP below)
```
Full group suites @HEAD: `group-secure.test.js` + `group.test.js` → all ✔ (incl. both GRP-1..5 and the legacy tests).

### GRP-2 headline — verified NOT vacuous, and the old test verified vacuous

The new GRP-2 test taps a NON-ADMIN survivor's (B's) post-removal MSG ciphertext off the wire
(`nA.on('message')` filtering GMAGIC `0x67` type `2`) and injects it straight into the removed member C
(`nC.emit('message', {}, captured)`) — the conceded on-path/relay adversary. C must fail to decrypt.
- **Without the survivor-rotation hunk** (source@parent): the test FAILS at `the removed member decrypts
  NOTHING …` — i.e. C, handed B's ciphertext, DOES decrypt it. The leak is real and the test catches it.
- **The OLD test** (`removal is cryptographic — after rotation the removed member decrypts nothing`) I ran
  against the SAME pre-fix source: it **PASSES**. Confirmed vacuous — after removal the sender drops C
  from its fan-out, so C never receives ciphertext and rotation was never exercised; it passed for the
  wrong reason. grp's headline finding is correct; the new injection test is the real guard.

### GRP-5 — GAP: the fix is correct, the test does not test it

The forged create in the GRP-5 test carries `sig: 'AAAA'` (garbage), which fails Ed25519 verification
under BOTH the old and new `opBytes` — so it is rejected as `op-signature` either way and the test
**passes with or without the fix** (confirmed against the true parent c9d567b). It asserts "garbage sig
rejected" (already true pre-fix), NOT "a genuinely-signed op with a spliced `init` is rejected".

The fix itself IS correct — proven directly (harness, using the project's own `signEd`/`verifyEd`):
```
OLD opBytes: a genuine A-signature over init=[B,C] still verifies after a relay splices D → true  (VULNERABLE)
NEW opBytes: the same splice breaks the signature                                        → false (FIXED)
```
So the roster-splice vulnerability is real and GRP-5 closes it — but the shipped regression guard is a
false one. **Recommend strengthening**: author a real create with a member's key, splice `init`, assert
`op-signature` divergence — that version REDs against pre-fix `opBytes`. Not ship-blocking (fix verified
by construction + harness), but CAG check 6 for GRP-5 is currently not satisfied by the committed test.

## Escalations

**(a) GRP-2 → O(n) survivor rotations per removal — BLESSED.** Necessary, not optional: sender keys are
per-member and the ratchet is one-way, so any survivor that does NOT rotate lets the removed member
compute that survivor's entire future keystream. Complete ejection therefore REQUIRES every survivor to
rotate its own chain. Cost: one removal ⇒ O(n) rotations, each redistributing to O(n) survivors ⇒ **O(n²)
KEYDIST messages** + externally-observable key traffic. Acceptable for the small-group v1 target; worth a
scaling note if groups grow large. Safe: the rotate is gated `o.by === m.admin` on a signature-verified
admin remove (a forged non-admin remove can't trigger it) and is idempotent (opHash dedup fires it once).

**(b) GRP-1 → lowest-opHash `create` wins — BLESSED as canonical + detectable, with an honest residual.**
groupId = SHA256("p2p-grp-v1"‖G) is bound to the shared secret, so ANY G-holder can author a valid,
signed rival `create`; admin = the first create in the canonical (lowest-hash-first) topo-order. This is a
real improvement over the pre-fix receipt-order fold — all honest peers now agree on ONE admin (no silent
split-brain / partition) and a rival root raises a `rival-create` divergence (fires on whichever create is
applied second, so it's detectable regardless of arrival order). **Residual (state honestly):** `opHash =
sha256(opBytes, sig).slice(0,32)`; a malicious G-holder can vary `init` and re-author until its create's
hash is lower than the legit admin's — expected ~2 tries (beating a uniformly-random target is p≈0.5/try)
— and thereby SEIZE admin deterministically on all honest peers. So GRP-1 does **not** *prevent* insider
admin seizure; it makes the contest deterministic and observable. The commit message's "closes
admin-escalation-via-rival-create" slightly overstates it — closer to "converts silent, race-dependent
escalation into deterministic, surfaced contention." True prevention needs a founder-pin / PKI trust root
the v1 secret-shared model deliberately omits, and any G-holder is already a full member (reads all
traffic), so the residual power gained is add/remove authority — now surfaced via divergence. Net: BLESS.

**(c) GRP-4 residual (founding member holding ONLY G, no member contact) — CONFIRMED correctly out of
scope.** `pullKeys()` draws from `bootstrap` (the `members` seed) ∪ `others()` (folded members); with
neither, there is no peer to KEYREQ and the member simply gets no key until an admin re-pushes — identical
to today, never worse (degenerate-safe). KEYREQ is groupId-gated (only G-holders form one) and served only
to CURRENT members (`membership().members.has(R)` — a removed member cannot re-pull). Closing this last
case needs group-rid rendezvous in node/transport, a separate lane. Correctly deferred.

## CAG §6 (condensed, per commit)

- **GRP-1** (1) closes silent same-input admin divergence + converts escalation to detectable; (3) fold is
  now order-independent — not weaker; (5) single-create case folds identically to before; (6) GRP-1 test
  asserts convergence + divergence (genuine, REDs pre-fix); residual per (b). **PASS w/ residual.**
- **GRP-5** (1) closes real roster-splice (harness-proven); (2) `init` now in signed bytes + opHash;
  (6) **monitoring hook inadequate — test is a false guard (GAP).** Fix ships; test needs strengthening.
- **GRP-2** (1) closes read-forever for ALL n−1 non-admin sender chains (not just admin's); (2) reactive
  rotate idempotent + gated on admin-authored (sig-verified) removes; (3) every chain rotates — strictly
  stronger; (5) admin-only-send case unchanged; (6) injection test genuine (REDs pre-fix, old test proven
  vacuous). Cost per (a). **PASS.**
- **GRP-3** (1) closes forged-KEYDIST per-sender DoS; (2) one Ed25519 sig, `verifyEd` fail-closed on
  malformed; (3) KEYDIST now as authenticated as OP/MSG; (5) legit handout unchanged; (6) test genuine
  (REDs pre-fix). **PASS.**
- **GRP-4** (1) closes permanent un-keying of late joiners that know ≥1 member; (2) KEYREQ groupId-gated +
  current-member-only + `pulling`-bounded (no amplification); (3) adds no decrypt path (KEYDIST still
  Ed25519-verified per GRP-3); (5) knows-no-member case == today; (6) test genuine (REDs pre-fix); residual
  per (c). **PASS.**

## Cross-cutting note (not a blocker)

GRP-5 changed `opBytes` field order/content (added `init`). Like the WIRE MAC, this is a **breaking change
to the op-signature format**: an op signed under the old `opBytes` will not verify under the new one and
vice-versa. Fine for a fresh all-new-code fleet (the owner's :8000 bump), but any persisted/relayed op
chain from an older build won't validate — fold it into the same v0.3.0 protocol-break envelope as WIRE.

## Standing-resident

GRP cluster gated. Four fixes CONFIRMED-SHIP; one GAP (GRP-5 test is a false guard — strengthen it) and
two blessed escalations with an honest residual on GRP-1. This lane stays resident for any further landings.

## UPDATE 2026-07-12 — GRP-5 GAP CLOSED (commit 6f401cf, re-verified independently)

grp-harden rewrote the GRP-5 guard to a real one (test-only; src untouched). New mechanics: capture A's
GENUINELY-signed create off the wire → splice a confederate into `init` WITHOUT re-signing → deliver to
a FRESH receiver (no prior copy ⇒ no opHash-dedup can mask the tamper) → assert `op-signature` divergence
AND the confederate is absent from the fold.

Re-verified myself in an isolated worktree @6f401cf:
- **GREEN@HEAD** (init in opBytes): `✔ group GRP-5 … (init is signed)`; group-secure suite 11/11.
- **RED** (opBytes reverted to drop the `init` term — the surgical pre-fix state): `✖ … AssertionError:
  the tampered roster must fail the op signature (init is signed)` — under pre-fix opBytes A's genuine
  signature still verifies over the spliced init and the confederate folds in.

The test now genuinely REDs without the fix and GREENs with it — it uses A's REAL signature (not the old
`sig:'AAAA'` shortcut), so it distinguishes old vs new opBytes. **CAG check-6 for GRP-5 is now met.**
