# p2p — divergences from DESIGN / INTERFACES

> Per `docs/PREMORTEM.md` divergence rule: where the built code intentionally deviates
> from `DESIGN.md` / `docs/INTERFACES.md`, log it here with the reason. These are the
> deliberate, reviewed deviations — not bugs. Each was flagged in-code at the site too.

## D-INT-1 — Noise transport nonce is little-endian u64 (INTERFACES said "be64")

- **Where:** `src/noise.js` (transport `tx.encrypt`/`rx.decrypt` nonce counter);
  `docs/INTERFACES.md` §src/noise.js originally wrote "nonce = internal be64 counter".
- **Actual:** the nonce is a **little-endian** u64 counter.
- **Why:** the Noise Protocol Framework spec and the official
  `Noise_IK_25519_ChaChaPoly_SHA256` KAT vectors (rweather/noise-c, cacophony, snow) all
  use a **little-endian** 8-byte counter. Big-endian would fail every KAT and break
  interop with any other Noise implementation. The spec/KAT is interop truth; the doc
  wording was imprecise.
- **Status:** code is correct; treat the INTERFACES "be64" phrasing as superseded by this
  entry. Verified by KAT byte-exactness against two independent audited impls.

## D-INT-2 — Key's 5-bit field read wholly as `version`, `flags` reserved (P2)

- **Where:** `src/key.js` `encodeKey`/`decodeKey`; the 130-bit layout's first 5 bits are
  labelled "version/flags" in DESIGN D2 / INTERFACES.
- **Actual:** v1 reads the full 5 bits as an integer `version` (0..31); `decodeKey`
  returns `flags: 0` reserved. `encodeKey` exposes only a `version` parameter.
- **Why:** DESIGN **D12** defers mode flags (mutual-expected, one-time sealed-invite) to
  **P2**. A literal 5-bit version is v1-correct, round-trips exactly, and leaves the exact
  version/flags sub-split (e.g. 3b version + 2b flags) as a one-line future change without
  breaking v1 strings. No flag semantics are needed until the P2 sealed-invite feature.
- **Status:** intentional; v1-correct. When P2 adds flags, carve them out of this 5-bit
  field and update DESIGN D2 + INTERFACES + this entry.

---

No other intentional divergences. Reality has not contradicted DESIGN elsewhere; where it
did during the build (e.g. rendezvous BEP44→plain-announce, D7), that was folded into
DESIGN.md itself rather than logged here, because it changed the design of record.
