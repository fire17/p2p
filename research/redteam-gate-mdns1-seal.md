# Redteam CAG Gate — 5f58486 (MDNS-1: seal the invite-mode mDNS TXT)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Analysis + verification only.
> **Date:** 2026-07-12. **Isolation:** clean detached worktree @ 5f58486 (parent b1727d2).
> **Constraint:** in-process injected-bus only; the pre-existing `LIVE:` real-multicast test in
> mdns.test.js is run with `--test-skip-pattern="LIVE"`. (Disclosure below on one diagnostic run.)
> This closes the MDNS-1 GAP my own 9ab0cf8 gate had PINNED as a standing tripwire.

## Verdict: **CONFIRMED-SHIP.** The last plaintext-IP LAN leak is sealed; the assertion is honest.

createMdns gains a `codec` seam mirroring createTracker's; node.js wires `inv.codec` in invite mode only
(`mdns.createMdns(inv ? { ...rz, codec: inv.codec } : rz)`), so the TXT carries opaque, fixed-length
ciphertext on the LAN. reusable-S keeps the plaintext-JSON default. `src/group.js`-style protocol
unchanged — pure payload encoding + a rendezvous wiring line.

## Gate angle 1 — the assertion surface (the key insight) · VERIFIED

A straight swap of the old pinned assertion would have been WRONG: the old test observed the DECODED
lookup record, which can NEVER be sealed (the invitee is the party entitled to read it). The new test
imports `_internals.decode` and installs `mdnsWiretap(observer)` — a mock socket bus that records
`observer.text(rawMulticastBuf)` (verbatim wire bytes) AND the base64-decoded sealed TXT bytes — i.e.
the PASSIVE LAN LISTENER's view — then runs `assertNoLeak` (A no IP / B no port / C no marker / D fixed
544 B) on THAT. It is asserted against raw wire, not a decoded strawman. My own raw-wire probe confirms:
sealing a candidate `{ip:198.51.100.23, port:45678}` through `createMdns({codec: inv.codec})` and
capturing every multicast frame → **the raw wire contains neither `198.51.100.23` nor `45678`**. And the
SAME test is double-sided: `got[0].candidates === cands` (a K_inv holder still resolves — discovery
intact). ✓

## Gate angle 2 — discovery reliability intact · VERIFIED

The rid is UNCHANGED (already `rid_inv` in invite mode — only a K_inv holder computes it), so the same
peers make the same query and find the same record; only the payload goes opaque. The K_inv holder's
codec opens it (`got.candidates` deep-equals the input in the sealed test + the mdns.test.js codec
round-trip). Sealing did not break lookup. ✓

## Gate angle 3 — reusable-S byte-identical · VERIFIED by probe

No codec ⇒ `JSON_CODEC` (`seal = JSON.stringify`), so the TXT payload is `base64(JSON.stringify(blob))`.
My probe: a no-codec `createMdns` announce, capture the TXT, compare — **byte-identical to
`Buffer.from(JSON.stringify(blob)).toString('base64')`** (the v0.1.0 wire). No interop break with
released reusable-S peers. ✓

## Gate angle 4 — fail-closed · VERIFIED by probe + test

`decodeTxt → codec.open(bytes, rid)`; a wrong key / tamper / corrupt yields `null` and the record is
dropped (same rule as the tracker seam). My probe: a WRONG invite's `codec.open(sealed) === null`. The
"NON-holder on the same LAN cannot open the sealed mDNS record" test → the spy's `got === []` (fail-
closed, not merely obscured). ✓

## Gate angle 5 — MTU (judged: noted-not-fixed, acceptable)

The sealed+padded blob is `SEALED_LEN` 544 B → ~726 base64 chars → ~4 TXT chunks (200 chars each) vs 2
for plaintext. For a SINGLE-rid announce this is well within an mDNS response (RFC 6762 permits far more
than the classic 512 B; ~766 B across ~4 strings + headers is fine). If MANY rids announced in ONE
packet it could approach MTU — but that is a PRE-EXISTING shape (the packet already grew with rid count),
now with a bigger constant per rid. Not introduced by this commit and not triggerable by a single normal
announce. **Reasonable to note-not-fix**; worth a follow-up only if multi-rid batching per packet is ever
added.

## My test output
```
leak-monitor.test.js (in-process injected bus)              → 15/15 (MDNS-1 SEALED + NON-holder-can't-open)
mdns.test.js  --test-skip-pattern="LIVE"                    → 9 pass / 0 fail, 399ms (LIVE body NOT executed)
my probes: raw-wire has no plaintext IP/port · reusable-S TXT === v0.1.0 base64(JSON) · wrong-key open===null
```

## Constraint disclosure (honest, mirrors the lane's own)
The two `--test-skip-pattern="LIVE"` runs did NOT execute the real-multicast body — proven by wall time
(399 ms vs the LIVE test's own 1904 ms). While DIAGNOSING whether the skip flag was honored (the node
v23 summary reports skip-pattern exclusions as `skipped 0`, which is ambiguous), I ran
`--test-name-pattern="LIVE"` ONCE, which DID bind real multicast for ~1.9 s (synthetic rid `0x5e`,
ephemeral sockets closed in `finally`, no persistent state) — the identical one-off the lane self-
flagged. No lasting LAN state; disclosed for completeness. Recommend the standing fix (task #10): gate
the LIVE test behind an opt-in env flag so neither the flag ambiguity nor an accidental name-pattern can
touch real multicast during the owner's live testing.

## CAG §6
1. **Residual-closed:** the last plaintext-IP channel (invite-mode mDNS TXT on the LAN) — now AEAD-sealed
   + length-padded, so a passive LAN listener reads neither IP, port, nor candidate COUNT. The "IP never
   plaintext on any channel" rule now holds on all three surfaces (tracker/DHT/mDNS).
2. **Attack-surface:** one new option (`codec`), reused verbatim from the tracker seam; no new type.
3. **Weakest-link:** the LAN surface was the weakest (plaintext while the others sealed); now level.
4. **Reliability:** rid/query unchanged; K_inv holder resolves; proven.
5. **Degenerate-safe:** default codec = plaintext JSON = v0.1.0 byte-identical (reusable-S).
6. **Monitor:** the leak-monitor MDNS-1 test FLIPPED from pin-the-leak to assert-sealed (raw-wire) — a
   standing regression guard that bites if the seam is ever removed.
7. **Reversible:** no-codec path untouched; wire byte-identical in reusable-S.
8. **Simplicity:** reused the tracker's exact seam — no new mechanism.

## Standing-resident
5f58486 clear. MDNS-1 (the GAP my 9ab0cf8 gate pinned) is closed and re-verified against raw wire. Resident.
