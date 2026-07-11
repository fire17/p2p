# Noise KAT vectors — provenance

`noise_ik_25519_chachapoly_sha256.json` carries the official
`Noise_IK_25519_ChaChaPoly_SHA256` known-answer test vector from **two independently
audited Noise implementations**, under `extracted.<source>.vector`:

- **cacophony** — centromere/cacophony
  - URL: https://raw.githubusercontent.com/centromere/cacophony/master/vectors/cacophony.txt
  - prologue: "John Galt"; publishes `handshake_hash`.
- **snow** — mcginty/snow
  - URL: https://raw.githubusercontent.com/mcginty/snow/main/tests/vectors/snow.txt
  - prologue: "There is no right and wrong. There's only fun and boring."; no `handshake_hash` field.

Each vector fixes both parties' static + ephemeral private keys, the prologue, and the
per-message payload→ciphertext pairs (2 handshake messages + N transport messages,
alternating starting with the initiator).

`test/noise.test.js` asserts, for BOTH sources, byte-exact equality of handshake msg1/msg2,
every transport message, and (where published) the handshake hash. Matching two separate
implementations' outputs byte-for-byte IS the cross-implementation interop assurance
required by DESIGN D5 — the shipped `src/noise.js` stays zero-dep; the audited libs are
consulted only as frozen test data here.

> A single-source extract from rweather/noise-c (`tests/vector/noise-c-basic.txt`, prologue
> "Prologue123") was also verified during the spike and is equally valid; this file keeps the
> two-source cacophony+snow set for stronger interop coverage.

## Integrity re-verification (2026-07-11)

This JSON was originally written by a now-stood-down duplicate agent (lane-noise), so its
authenticity was re-checked from scratch before the GATE was declared PASS: both the
`cacophony` and `snow` entries here were compared **byte-for-byte** against fresh independent
curl fetches of the two upstream raw files (URLs above) — every field matched (prologues,
statics/ephemerals, all message payload/ciphertext pairs, and cacophony's handshake_hash). A
third source (rweather/noise-c, handshake_hash `3d8748e8…613eeb`) was also cross-checked. The
on-disk vector set is authentic; no regeneration was needed.
