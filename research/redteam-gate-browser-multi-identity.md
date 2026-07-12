# Redteam CAG Gate — 90e5bfd (browser multi-identity + own-key guard + BRW-2)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Analysis + verification only.
> **Date:** 2026-07-12. **Merge commit:** `90e5bfd` (parents `3d8bfa5` dev.2 + `2054f5d` lane). Browser-only.
> **Isolation:** clean detached worktree @ 90e5bfd. This is v0.3.0-dev.3.

## Verdict: **CONFIRMED-SHIP.** No DEVIATION. One minor doc-accuracy note (not a GAP).

The lane branched from a STALE pre-hardening base (86bb571), but the 3-way merge onto dev.2 is clean —
**independently verified: every backend/hardening file is byte-identical to dev.2.** All four browser
suites pass on the merged tree.

## Stale-base merge — the key risk, verified CLEAN

Net change `3d8bfa5..90e5bfd` touches ONLY 4 browser files:
```
app/index.html            | 17 +
src/browser/app.js        | 68 +
src/browser/p2p.js        | 128 +
test/browser-identity.mjs | 140 +
```
Every hardened backend file is BYTE-IDENTICAL to dev.2 (`git diff 3d8bfa5 90e5bfd -- <f>` = 0 lines):
`src/wire.js` · `src/node.js` · `src/transport.js` · `src/browser/webrtc.js` · `src/transport-wss.js` ·
`src/group.js`. Presence spot-check at 90e5bfd: wire `MAC_LEN=16` ✓, webrtc `PARKED_OFFERS_PER_SLOT` ✓,
node `MAX_INBOUND_PEERS` + `probeProof` ✓, transport `MAX_ACCEPTED` ✓. **WIRE MAC / DOS-1 / META-1 /
BRW-4b all intact after the merge** — git kept main's hardened versions because the lane never touched
them. Team-lead's post-merge claim independently confirmed.

## My own test output (browser suites, @ 90e5bfd, Playwright/Chromium — backend suite deliberately NOT
run to avoid polluting the owner's live mDNS; backend is byte-identical to the already-gated dev.2 208/208)

```
browser-identity.mjs  ✔ PASSED
  I1: two tabs in ONE shared-storage context (#id=alice, #id=bob) → DISTINCT keys
  I2: browser↔browser chat BOTH ways between the two same-browser identities (Noise IK over WebRTC, 0.7s)
  I3: ＋New identity opens a new window with a distinct key
  I4: dialing your OWN key is refused with a clear message, no dial attempted
  I5: concurrent first-run on the same slot → ONE consistent identity (p1==p2, no clobber) + persisted
browser-e2e.mjs        ✔ PASSED  (G2 tracker rendezvous + G3 WebRTC + Noise IK + chat)
browser-group-ui.mjs   ✔ PASSED  (create + add + join + chat via the shipped /app/ buttons)
browser-typing.mjs     ✔ PASSED  (real keystrokes land in both chat boxes)
```

## CAG §6 (source-verified)

1. **Residual-closed:** the "message went to myself" trap — one IndexedDB record meant two tabs shared
   ONE identity. Now one identity PER SLOT (separate record), slot chosen per-tab via `#id=<name>`; plus
   an own-key dial guard and the BRW-2 concurrent-first-run fix. All four proven by I1/I4/I5.
2. **Attack-surface enumeration:**
   - **URL-controlled slot** → `sanitizeSlot(s) = (s||'').toLowerCase().replace(/[^a-z0-9-]/g,'').slice(0,32) || 'default'`.
     Clamped to `[a-z0-9-]`, ≤32 chars, non-empty. It is used only as an IndexedDB record key
     (`slotKey`) and as `textContent` (`#idname`) — never `innerHTML`, never a dynamic import path — so
     no injection/XSS/path surface. ✓
   - **Backward-compat:** `slotKey('default') === ID_KEY` ('default') — the legacy flat record — so
     existing users keep their identity; named slots namespace as `'id:'+slot`. `listIdentities` maps a
     legacy `ID_KEY` record back to slot 'default'. ✓
   - **Own-key guard:** `if (myKey && S === myKey) { say(...); return }` — exact string compare to THIS
     tab's key, refuses before any dial (I4 confirms no dial attempted). ✓
   - **BRW-2:** `identity()` fast-path `idbGet(k)`; else `create()` — which RE-CHECKS `idbGet(k)` inside
     the critical section (adopts a concurrent tab's just-persisted identity via `hydrate` instead of
     clobbering) — wrapped in a per-slot `navigator.locks.request('p2p-identity-'+slot, create)`. I5
     proves it: two concurrent first-runs on one slot converged to the SAME key (p1==p2). ✓
   - **Storage integrity:** `hydrate` re-runs `verifyCommitment` on every load — a corrupt stored record
     is rejected, not trusted. ✓
3. **Weakest-link:** unchanged — the security boundary is still the Noise/commitment layer (untouched,
   byte-identical). Multi-identity is a client-side storage/UX partition; it adds no new trust.
4. **Reliability:** I2 shows two same-browser identities complete a real Noise IK channel + chat both
   ways; e2e/group-ui/typing regressions all green. No path regressed.
5. **Degenerate-safe:** default slot === legacy behavior (byte-identical record key); a browser without
   `navigator.locks` falls back to bare `create()` (see note).
6. **Monitoring hook:** `test/browser-identity.mjs` (I1–I5) is the standing regression assertion.
7. **Reversible / no wire change:** browser client-only; no protocol/wire bytes touched (backend
   byte-identical). NOT part of the v0.3.0 protocol break.
8. **Simplicity:** raw IndexedDB per-slot record + a URL slot param — no wrapper lib, no new store.

## Note (minor doc-accuracy, not ship-blocking)

The BRW-2 comment says the in-lock re-check "is the actual correctness guarantee (works even where the
Web Locks API is unavailable)." Precisely: WITHOUT Web Locks, two genuinely-concurrent first-runs can
both observe `null` in the re-check and still clobber — the **lock is what serializes so the second
tab's re-check sees the first's write**. The two together are the guarantee. This is a non-issue in
practice: `navigator.locks` is available in every current target browser (Chrome 69+/FF 96+/Safari
15.4+), and I5 confirms the real-Chromium behavior is correct. Worth tightening the comment; no code
change needed.

## Standing-resident

90e5bfd clear to ship → v0.3.0-dev.3. Backend hardening confirmed intact through the stale-base merge.
Resident for anything further.
