# Redteam CAG Gate — fff96ee (dedup peers across inbound/outbound keying)

> **Lane:** redteam / CAG-gate (opus @ xhigh). In-process only (no network; LIVE skipped). Worktree @
> fff96ee (parent 2558240). Task #14 — last of the v0.3.3 batch (with 0124a16 + 3540a56).

## Verdict: **CONFIRMED-SHIP.** No new security assumption; burn neither weakened nor bypassed;
exactly-once preserved; peers() can't double; DOS-1 can't shed mid-dial. RED 3/7 → GREEN 7/7.

Root: `node._peers` is keyed two ways — dialed peers by `S`, accepted peers by `'static:'+xPub` — and
`decodeKey(S)` yields a 110-bit COMMITMENT, not the pubkeys, so `_peers.get(S)` structurally missed an
inbound peer ⇒ `connect()` minted a 2nd record + a whole 2nd Noise session against someone we already
talk to. Fix: `findPeer()` bridges the two key spaces by the commitment; `initiatorHandshake` ADOPTS the
accepted record (keeping its `'static:'` key + outbox); `connect()` short-circuits either direction.

## Angle 1 — the commitment scan matches ONLY Noise-authenticated pubkeys (no new assumption)
`findPeer` returns a rec only when `deps.verifyCommitment(dec.commitment, p.remoteEd, p.remoteStatic)` —
and `p.remoteEd/remoteStatic` are the STORED, Noise-IK-authenticated pubkeys set at the HELLO/HS1 gate.
It is the SAME `verifyCommitment(commitment, edPub, xPub)` the gate itself trusts to bind `S`↔pubkeys —
so adopting a record asserts nothing the handshake didn't already prove. Records that never handshaked
(`!remoteEd`) are skipped. **Negative control (test :154):** a DIFFERENT peer's S — whose commitment
matches no stored authenticated pubkey — is NOT matched; it gets its own record and a real dial. ✓

## Angle 2 — BURN neither weakened nor bypassed (source-traced + 3 tests)
`connect()` order: `existing = findPeer(…); if (existing && existing.peer.connected) return existing.peer`
— the short-circuit fires ONLY on a CONNECTED peer, and returns it WITHOUT touching the burn state.
- (a) **still-connected invite re-dial** → returns the live peer, no 2nd dial, invite NOT spent
  (`_burnedInvites` unchanged, `_inviteBurned` still exactly one). Test :199. ✓
- (b) **re-dial after the session ENDED** → the record is disconnected, so `existing.peer.connected` is
  false ⇒ falls through to the invite path where `if (node._burnedInvites.has(fp)) throw 'already used
  (burned)'` runs BEFORE `initiatorHandshake` (hence before any adopt). An adoptable disconnected record
  therefore CANNOT smuggle past the burn guard. Test :227 (REFUSED). ✓
- reusable-S is invite-agnostic and still reconnects after a session ends (test :253) — burn does not
  over-refuse. ✓

## Angle 3 — outbox-replay-on-adopt respects exactly-once
Adopt keeps the record's `outbox` (only UNACKED app msgs — acked ones are already deleted) and its
inbound `delivered` set. On `attach` the outbox replays in seq order; the peer dedups by appSeq
(`delivered`), so a replay the peer already delivered is dropped — the SAME exactly-once-across-reconnect
mechanism (wire MAC gate + delivered-dedup) already in place. Adopt does not reset `delivered` (only a
different peer instance does, correctly), so no double-delivery and no stale replay. Test :139 ("B can
talk to A on the adopted record") + node.test.js's exactly-once-across-reconnect (green) exercise it. ✓

## Angle 4 — peers() emits no duplicate
Adopt keeps the record's `'static:'+xPub` key (it does NOT re-key the map to `S`), so exactly one map
entry survives per peer — `peers()` can't list the same peer twice. Test :125 asserts no 2nd record. ✓

## Angle 5 — DOS-1 can't shed the peer mid-dial
Adopt sets `rec._inbound = false`. `admitInbound` sheds exactly "inbound + disconnected + empty outbox";
clearing `_inbound` removes the record being dialed from that shed set, so a concurrent inbound flood
can't delete it out from under the in-flight handshake (which would attach into an orphan peers() no
longer lists). Test :171. ✓

## My test output
```
RED  @parent 2558240 : peer-dedup.test.js → 4 pass / 3 fail (the 3 dedup/adopt guarantees fail w/o the fix)
GREEN @fff96ee       : peer-dedup 7/7; + node.test.js + invite-mode.test.js + burn.test.js = 30/30, 0 fail
```

## CAG §6
1. Closes the duplicate-record/duplicate-Noise-session bug. 2. New parts: findPeer commitment-scan +
   adopt — enumerated, each on already-authenticated data. 3. Weakest-link unchanged (verifyCommitment is
   the gate's own primitive). 4. Reliability: one session per peer; outbox replays. 5. Degenerate-safe
   (reusable-S byte-identical; no findPeer match ⇒ fresh dial). 6. peer-dedup.test.js is the monitor
   (RED 3/7). 7. Reversible. 8. Reuses verifyCommitment — minimal.

## Standing-resident
fff96ee CONFIRMED-SHIP — v0.3.3 batch (0124a16 + 3540a56 + fff96ee) fully gated. Resident.
