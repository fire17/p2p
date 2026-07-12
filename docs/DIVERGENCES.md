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

## D-INT-3 — WSS tracker was a v1 stub — RESOLVED 2026-07-12 (matchmaker landed)

> **RESOLVED** in commit 69d8976: the tracker is now D6's live matchmaker (persistent WSS,
> candidate blob carried in the offer SDP, real `lookup()` peer discovery). Verified live —
> tracker-only two-process discovery returns `channel: tracker` in ~0.55s over real public
> WebTorrent trackers, and a full tracker-only two-process chat delivered end-to-end. So
> **cross-network discovery is no longer DHT-only** — it is now mDNS (LAN) + DHT + tracker,
> the full 3-channel race per D6. The deferral below is kept for history; it no longer holds.
> (Cross-network real-NAT between two DISTINCT networks is still owner-gated / unobserved —
> that's VAL-ACCEPT-XNET, separate from this rendezvous-redundancy divergence.)

<details><summary>Original deferral (historical)</summary>

- **Where:** `src/rendezvous/tracker.js` — `createTracker().lookup()` is an empty async
  generator (yields no peers); `announce()` is an echo-only probe; the full candidate blob
  is accepted but parked.
- **DESIGN says (D6):** the tracker is a **LIVE MATCHMAKER** — the listener holds persistent
  tracker connections and answers offers, and the FULL candidate list rides the tracker
  offer blob. Shipped v1 does none of that peer discovery.
- **Why:** the live offer-relay matchmaker (sustained connections + offer retention) is more
  machinery than v1 needs; it is deferred to **P1** (flagged in-code and in `research/
  rendezvous.md` §4). mDNS + DHT cover v1 discovery.
- **CONSEQUENCE — state it plainly:** v1 discovery uses **mDNS (LAN only)** + **DHT (the one
  cross-network rung — returns an ip:port hint)**. So **cross-network first contact rests on
  the BitTorrent DHT alone** in v1; the "publish-to-N / race-reads" redundancy across three
  channels (D6) is really two for LAN and *one* for the internet until the tracker matchmaker
  lands. The DHT round-trip is empirically proven (5/5 live), but it is a single rung — if a
  network blocks the DHT's UDP, cross-network discovery has no fallback in v1. **This is the
  main reason the cross-network claim is "machinery ready," not "redundantly ready."**
- **Status:** intentional scope cut, product works for v1. When P1 adds the tracker
  matchmaker, restore the 3-channel race and update DESIGN D6 + this entry.

</details>

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

No other intentional divergences beyond D-INT-1/2/3 above. Where reality changed the design
of record during the build (e.g. rendezvous BEP44→plain-announce, D7), that was folded into
DESIGN.md itself rather than logged here.

> 2026-07-11 correction: D-INT-3 (tracker stub) was added after a second acceptance review
> caught that it was logged only in ACCEPTANCE-LOG.md, and that this file wrongly claimed
> "no other intentional divergences." The divergence rule requires every intentional
> deviation to live here — fixed.
