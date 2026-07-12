# Redteam CAG Gate — ae06ff4 (burn-after-connect v2) + 20db733 (p2p group CLI)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Analysis + verification only.
> **Date:** 2026-07-12. **Isolation:** clean detached worktree @ 20db733 (chain 9ab0cf8→ae06ff4→20db733).
> **Constraint honored:** in-process/loopback only — no mDNS/live-infra (owner live-testing).

## Verdicts

| Commit | Item | Verdict |
|---|---|---|
| ae06ff4 | burn-after-connect v2 (invite single-use + route disappears) | **CONFIRMED-SHIP** |
| 20db733 | `p2p group` CLI | **CONFIRMED-SHIP — with a verified GAP** (ghost-group on a valid-base64 typo; see §2.1) |

---

## 1. ae06ff4 — burn-after-connect v2 · CONFIRMED-SHIP

Three effects fire the instant the invitee completes the invite handshake (`burnInvite`): stop-republish
(`_publishHandle.stop()` + close `_channels`), K_inv retire (`_inviteBurned` → acceptConnection refuses
new sockets, META-1 probe gate silent), and the dialer marks the share spent by a K_inv fingerprint.

**My test output:** `test/burn.test.js` → **4/4 pass** (stop-republish across netchange · captured share
refused by a dark listener · dialer second-dial refused · reusable-S unaffected). RED-without/GREEN-with
confirmed: reverting `node.js`+`invite.js` to parent 9ab0cf8 → **all 4 FAIL** (`not burned before anyone
connects`), fix → 4/4.

**Adversarial angles (all clear):**
- **Attacker-triggered burn / DOS a legit invite?** No. `burnInvite` is reachable ONLY from
  `acceptConnection`'s HS1 branch, AFTER `hs.readMessage(f.payload)` SUCCEEDS — and in invite mode `hs`
  is the IKpsk2 responder, so a msg1 WITHOUT the K_inv-derived psk throws at `readMessage` and is caught
  (`divergence` + `socket.close` + `return`) BEFORE the burn line. So only a K_inv holder can burn — and
  a K_inv holder completing the handshake IS the invitee (or a leaked-share holder, whose first use is
  exactly the single use the design intends). A partial/failed handshake cannot set `_inviteBurned`
  (verified by code path: burn is the last statement of the successful branch, after `rec.attach` +
  `socket.send(HS2)`; an `admitInbound` rejection `return`s before it).
- **Does channel-close on burn kill the live peer?** No. `burnInvite` closes `node._channels` (the
  RENDEZVOUS publish channels) and stops `_publishHandle`. The established peer rides its TRANSPORT
  socket bound in `rec.attach({ socket, ... })`, which is untouched — burn kills the ROUTE, not the
  connection. The "reusable-S unaffected" + stop-republish tests exercise a live peer surviving burn.
- **CAG-6 — is `_burnedInvites` unbounded growth a leak?** No. One 16-byte-fingerprint hex string is
  added per SUCCESSFUL invite-DIAL (`connect(share)`) — a user-initiated action, not remotely
  triggerable (an attacker cannot make your node dial invites). Bounded by your own dials, in-memory,
  cleared on restart. ~32 bytes/entry; not a DoS surface.
- **Latent leak fixed:** the node-level netchange path previously spawned a fresh publish handle and
  discarded it, orphaning that handle's own netchange listener → it re-announced forever and survived
  burn's `stop()`. Now it REPLACES `_publishHandle` (stops prev, stores new) and is gated on
  `_inviteBurned` — so burn's `stop()` always reaches the one live handle. Verified: initial handle is
  tracked at `listen()` (`node._publishHandle = deps.publishAll(...)`), so `stop()` reaches it too.

**CAG §6:** (1) closes the invite-reuse / route-persistence residual (§9-v2) at the operational layer
(honest scope: in-memory, restart re-arms — documented, not over-claimed); (2) surface = burn flag +
fingerprint set + handle-replace, each enumerated; (3) not weaker — reusable-S is byte-identical
(`_inviteBurned` stays false); (5) degenerate-safe; (6) burn.test.js is the monitor; (7) reversible, no
wire change; (8) minimal. **Ship.**

---

## 2. 20db733 — `p2p group` CLI · CONFIRMED-SHIP with a verified GAP

A thin driver over `createSecureGroup` (bin/p2p-group.js, 218 lines): `newGroupCode` (base64 of 32 random
bytes), `parseGroupCode`, `makeGroup`, a readline UI, and `/members //add //code //quit`.

**My test output:** `test/tui-group.test.js` → **4/4 pass** (typo refused · new→join→send round-trips
decrypted+authorship-verified · admin /add third member · 10/10 independent runs).

**Angles that are CLEAN:**
- **Member-key validation before network:** create path runs `decodeKey(k)` on every listed member
  (TypoError → `exit 2`) BEFORE `mod.listen`; `/add` validates too; own key is skipped. ✓
- **Secret framing honest?** Yes. The code IS the secret (base64 of G); README §4 says "A group is a
  **code** (base64 of a 32-byte secret) — share it like a key," and `printCodeBox` labels it "GROUP CODE
  — share with the members." Framed as a shareable credential, not hidden. (It does land in shell history
  as an argv — same as any `p2p connect <share>`; acceptable for a share-anyway code.) ✓
- **CAG-6 — drift from src/group.js?** None. The CLI calls `createSecureGroup` (the library); all
  membership/crypto/fold logic stays in src/group.js. The test drives the shipped exports, not a copy.
- **Browser interop:** browser (`app.js`) and CLI both use base64-of-32-byte-G → `createSecureGroup`
  → `groupIdFor(G)=SHA256("p2p-grp-v1"‖G)`, so one code joins both (README + browser-group-tui.mjs). ✓

### 2.1 GAP (verified, my own probes) — a valid-base64 typo silently forms a GHOST GROUP

`parseGroupCode` is strict about MALFORMED input (length≠32 → throw; non-canonical base64 → throw via the
`G.toString('base64') !== s` round-trip), but the round-trip catches only the NARROW non-canonical cases
(padding / the last char's don't-care low bits / invalid chars). A single-char typo in the code BODY that
lands on valid base64 is silently accepted as a DIFFERENT 32-byte secret → a different `groupId` → a
"ghost group" where you hear no one and no one hears you. My probes on a real code:
```
middle-char typo       → ACCEPT, DIFFERENT G (ghost group!)
last-char w→A (valid)  → ACCEPT, DIFFERENT G (ghost group!)
last-char w→x / w→z    → THROW  (don't-care-bit case — the round-trip DOES catch these)
truncated / garbage    → THROW  (length ≠ 32)
```
So the code comment + test claim "a truncated/typo'd code must fail LOUDLY … not silently produce a
different groupId" is **only true for malformed codes** — the common case (a body typo that stays valid
base64) ghosts silently, which is exactly the risk flagged for this gate.

**Why this is a GAP, not a ship-blocker:** it is INHERENT to the checksum-free code format (raw base64 of
G, no error-detection), which the BROWSER already ships and which the CLI faithfully matches — blocking
the CLI alone would neither fix the format nor be consistent. It is **not a security hole** (colliding
with another REAL group needs guessing that group's actual 32-byte secret — infeasible); the failure mode
is a silent no-connectivity usability trap, partially surfaced today by the CLI's `· membership: N
members` line (a ghost joiner sees only itself).

**Recommendation (follow-up task, cross-client):** add a short checksum to the group CODE (e.g. a few
HMAC/SHA bytes over G appended before base64, verified on parse) so a mistyped code fails loudly in BOTH
the CLI and the browser — this must land in both clients together to preserve interop. Cheaper interim
mitigation (CLI-only, no interop impact): after `join()`, if membership stays at 1 (only you) past a
short grace, warn "no members reachable — double-check the code."

**CAG §6 (20db733):** (1) closes "no terminal group chat" — real feature; (2) surface enumerated;
(3/4/5) library-backed, not weaker; (6) tui-group.test.js is the monitor; (7) reversible; (8) minimal
driver, no drift — EXCEPT check-2/6 flags the code-parse GAP above (the guard is weaker than its claim).

---

## Standing-resident

ae06ff4 clear. 20db733 clear to ship with the ghost-group GAP recorded — owner's call on whether to gate
the cross-client checksum follow-up before or after dev.4. Resident.
