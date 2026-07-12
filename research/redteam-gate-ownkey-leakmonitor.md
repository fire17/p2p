# Redteam CAG Gate — 6ff9656 (CLI own-key guard) + 9ab0cf8 (standing leak-monitor)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Analysis + verification only.
> **Date:** 2026-07-12. **Isolation:** clean detached worktree @ 9ab0cf8 (chain 1047406→6ff9656→9ab0cf8).
> **Constraint honored:** in-process / loopback / injected-backend only — no live mDNS/DHT/LAN binding
> (owner is live-testing this machine). For dev.4.

## Verdicts

| Commit | Item | Verdict |
|---|---|---|
| 6ff9656 | CLI own-key guard (`isOwnKey`, 3 dial entry points) | **CONFIRMED-SHIP** |
| 9ab0cf8 | standing leak-monitor (Observer + battery, tests-only) | **CONFIRMED-SHIP** |

---

## 6ff9656 — own-key guard

`isOwnKey(target, ownKey)` resolves the target's 26-char S (`parseShare(...).S`, so a bare key OR the
S-half of an `S-<tail>` invite) and compares its **14-byte keypair COMMITMENT** to this session's, in a
try/catch (malformed → `false`). Guard fires BEFORE any network at `bin/p2p.js` lineMode, `bin/p2p-tui.js`
dial, `bin/p2p-chat.js` runConnect — refuse + exit 2 (CLI) / status line (TUI).

**CAG check-6 — is a simpler string compare safe? NO (empirically proven, my probe):**
```
own S            : 0SJRGK9HTQ5CZE972NFYDYQNRD
own-invite share : GSJRGK9HTQ5CZE972NFYDYQJ8P-S89D8...      (INVITE_FLAG set)
string compare (shareS === own) : false   ← a naive guard MISSES self-dial via your own invite
commitment equal (decodeKey)    : true    ← the 14-byte commitment matches
isOwnKey(bare own)  = true    isOwnKey(invite share) = true    ← both caught
isOwnKey(other key) = false   isOwnKey(garbage)      = false   isOwnKey(null own) = false
```
The invite-flag bit changes the encoded S string but NOT the commitment, so string-compare is
insufficient and the commitment-compare is justified — the lane's claim holds.

**Adversarial angles (all clear):**
- **False positive (refuse a legit peer)?** No. `a.equals(b)` is true only on a 14-byte (112-bit)
  commitment match with THIS session's own key — i.e. the same identity, which is exactly what to
  refuse. A distinct peer never collides (probed: other key → false). Malformed input → catch → `false`
  (never a false positive; the bad-key error is handled by the normal dial path). `--selftest` (a real
  two-node dial) still PASSES — the guard does not break legitimate dials.
- **Uncaught throw on attacker target?** No. `parseShare(String(target).trim())` is inside the try;
  every throw → `false`. Verified with garbage input.
- **Timing / oracle leak?** None that matters. Both operands are PUBLIC commitments (my own key S is
  public; the target is attacker-supplied). `Buffer.equals` is not constant-time, but there is no secret
  to leak — unlike a MAC/password compare. Non-issue.

**My test output:** `test/own-key-guard.test.js` → **8/8 pass** — refuses own bare key (case-insensitive),
refuses own invite share, ALLOWS a different peer key (no false-positive), malformed no-op, actionable
message, CLI subprocess `p2p connect <own-key>` REFUSES + never dials, bare `p2p <own-key>` refuses,
`--selftest` still PASSES.

**CAG §6:** (1) closes the #1 self-dial footgun on the CLI (mirror of the browser guard); (2) surface =
one pure predicate + 3 call-site guards, no network, no new deps; (3) not weaker — additive refuse path;
(5) degenerate-safe — malformed/absent own-key → `false` → normal dial; (6) monitor = the 8-test file;
(7) reversible, no wire change; (8) commitment-compare is the minimal correct predicate (string compare
is DOMINATED — it's wrong for the invite case).

---

## 9ab0cf8 — standing leak-monitor (tests-only; `git show --stat` = test/ + scratch/ only, src untouched)

`test/observer.js` generalizes `privacy.test.js`'s SpyRelay/spyDhtBackend into a reusable `Observer`
(records every text an operator relays + every sealed byte buffer) + `assertNoLeak` (A no plaintext IP,
B no plaintext port, C no marker `p2p-blob`/`"candidates"`, D every sealed value == `SEALED_LEN` 544 B).
`test/leak-monitor.test.js` runs it against the REAL modules over injected/loopback backends.

**Angle 1 — faithful, or a strawman?** Faithful. The tracker adapter (`SpyRelay`) records the RAW
relayed SDP JSON (`obs.text(data)`) — exactly the tracker operator's view — and extracts the sealed blob
from the invite-mode SDP attribute; the DHT adapter records every BEP44 put value (the storing node's
view). Candidate IPs are greppable RFC-5737/3849 documentation addresses, so a plaintext leak of ANY of
them trips `wire.includes(c.ip)`. Each seal test is **double-sided**: `assertNoLeak(observer, cands)`
AND `got[0].candidates === cands` (the K_inv holder still reads the real candidates) — so a silently
broken publish can't pass green (empty wire → `wire.length > 0` fails; empty got → deepEqual fails). The
DHT test additionally checks `puts[0].v.length === 544` and `bep44Verify` (K_inv-signed).

**Angle 2 — MDNS-1 pin: real tripwire or greenwash?** Real tripwire, honestly the opposite of greenwash.
The test ASSERTS THE LEAK EXISTS: `observer.wire().includes(cands[0].ip) === true`. Premise verified on
disk — `src/node.js:294` wires `mdns.createMdns(rz)` with NO codec (comment: "LAN broadcast … plaintext
TXT (LAN-only)"), so invite-mode mDNS genuinely broadcasts the plaintext candidate on the LAN (accepted
MDNS-1 tradeoff, tracked as task #4). The assertion FLIPS TO FAILING the day mdns.js gains a codec or is
wired to a non-LAN surface — forcing a review, at which point it becomes `assertNoLeak`. Not a false
green: it pins documented reality and alarms on change in EITHER direction.

**Angle 3 — any test that goes green if the invariant silently weakens?** No. `assertNoLeak` THROWS on
any IP/port/marker/length leak; the WIRE-1/2/3 test asserts forged ack/close/DATA move NO state AND the
real frame still delivers (remove the MAC → forgeries move state → fail); the DOS-1 tripwire asserts
`_accepted.size ≤ 8` under a 40-PROBE flood (remove the cap → fail); rid-unlinkability and K_inv
locate/open are double-sided (invitee CAN, everyone else CANNOT).

**RED-fires proof (my run of `scratch/leak-red-proof.mjs`, in-process):** deliberately injects a plaintext
IP into a "sealed" 544-B value → `assertNoLeak` **THROWS (RED fired)**; a forged wire frame decodes under
no key but is `null` under the receive key (secure property holds) → **"All detectors fired. ✅"**, exit 0.
The detectors genuinely bite — the battery is not vacuously green.

**My test output:** `test/leak-monitor.test.js` → **14/14 pass** (injected backends, no live mDNS/DHT):
tracker×4 + DHT×4 candidate sets (A,B,C,D), rid unlinkability (S≠invite, cross-invite, cross-epoch),
S-holder-without-K_inv can neither LOCATE nor OPEN, WIRE-1/2/3 behavioral, DOS-1 flood-bounded, MDNS-1
pinned tripwire.

**CAG §6:** (1) executes the owner's "always monitor" law (§7) as a standing battery — CAG check-6 for
the whole hardening line; (2) surface = test-only Observer, no src imported internals, no module mutation;
(3) not weaker — adds detection; (5) degenerate-safe — offline/injected; (6) IS the monitor; (7)
tests-only, no wire change; (8) reuses privacy.test.js's proven capture, minimal. The MDNS-1 residual is
stated honestly as a pinned known gap (task #4), not silently sealed over.

---

## Standing-resident

Both CONFIRMED-SHIP → clear for v0.3.0-dev.4. No src risk from 9ab0cf8 (tests-only); 6ff9656 adds a
refuse path that never touches a legit dial (`--selftest` green). Resident for anything further.
