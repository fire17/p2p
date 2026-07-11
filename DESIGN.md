# p2p — DESIGN (v1)

> 2026-07-11 · synthesized from 4 research lanes (`research/*.md` — read them for depth;
> every claim here is anchored there with primary sources). Companion: `docs/PREMORTEM.md`
> (divergence rule applies: reality contradicts this doc → STOP, log, escalate).

## 1. What this is

Tiny, embeddable, **zero-dependency** P2P chat/data framework. One 26-char string is a
person's whole contact surface: copy it to a friend, they can find you, connect direct
(NAT punched), and talk E2E-encrypted — with **provably MITM-proof first contact** — no
server of ours, no accounts, no config. Friends + groups. Realtime.

## 2. Decisions (D-table — the load-bearing choices)

| # | Decision | Why (lane) |
|---|---|---|
| D1 | **Runtime: Node ≥ 22, plain ESM JS + JSDoc, no build step, zero npm deps** | only runtime where ALL primitives are native: X25519, Ed25519, ChaCha20-Poly1305, HKDF, SHA-256 (`node:crypto`), UDP/TCP (`dgram`/`net`), WebSocket client (global, ≥22). Go needs x/crypto; Python stdlib fails crypto. Spec stays language-neutral for future ports. (A, D) |
| D2 | **Key = 26-char Crockford base32 = 130 bits: `[5b version][110b identity commitment][15b checksum]`** — commitment = `trunc(SHA256("p2p-id-v1" ‖ ed25519_pub ‖ x25519_pub), 110)` | self-authenticating PUBLIC string, not a secret → reusable safely; 2^110 second-preimage bound; version bits = agility; checksum before any network work. NO PAKE (high entropy). (D §1, §11) |
| D3 | **Identity = Ed25519 signing pair + X25519 static pair, generated together, both bound by the one commitment** | avoids ed→x curve conversion (not in Node native); sign records with Ed25519, run Noise with X25519. (D + synthesis) |
| D4 | **First contact = fetch-then-gate-then-Noise-IK**: resolve rendezvous → dial → peer's hello carries full pubkeys → accept iff hash matches commitment → Noise `IK` (msg1 `e,es,s,ss` / msg2 `e,ee,se`) → msg2 decrypt = THE ACK | key-confirmation transcript: successful first ack proves no MITM, forward secrecy via `ee`. Exact security statement: research/crypto-firstcontact.md §10. (D §9) |
| D5 | **Noise IK implemented in-house (~350 LOC), validated against official Noise test vectors in CI** | zero-dep rules out audited libs; composition-per-spec of native primitives, NOT novel crypto; adversarial review gate before v1 tag (premortem #3). |
| D6 | **Rendezvous v1: mDNS (LAN) + BitTorrent Mainline DHT `announce/get_peers` + public WSS trackers, all keyed by `rid = HKDF(S, "p2p-rv-v1", epoch_day)`; publish-to-all, race-reads, checked ±1 epoch** | multi-operator, ownerless or :443-camouflaged, all live-probed healthy 2026-07-11. Uniform model: every channel resolves rid → candidate endpoints; authenticity comes from the hello-gate + IK, so channels need zero trust. (C §9–10) |
| D7 | **DIVERGENCE from Lane C: plain DHT announce instead of BEP44 mutable for v1.** | BEP44 mutable target = SHA1(pubkey‖salt) — readers can't compute it from a commitment-only string without giving every holder the DHT write key (squat risk). Plain announce needs no signing, ~half the LOC, same job (find owner's IP:port; blob authenticity comes from hello-gate anyway). BEP44 records return in P2 for richer presence. |
| D8 | **Transport ladder: IPv6 direct → LAN → UDP hole punch (STUN, in-house ~100 LOC client) → TCP simultaneous-open → birthday-punch (P2) → peer-relay via mutual friend (P2)** — candidates raced ICE-style, best kept | ~70–90% direct, fallbacks guarantee connectivity; full WebRTC/QUIC skipped (LOC death, cited). Keepalive 25s UDP; QUIC-style connection ID in our header for roaming/reconnect. (B) |
| D9 | **Wire: own tiny protocol over UDP** — 1-byte type, connection ID, seq/ack sliding-window ARQ (~150 LOC), ChaCha20-Poly1305 frames from Noise `Split()`, nonce = counter | chat needs ordered-reliable; TCP fallback reuses same framing. (B + synthesis) |
| D10 | **Groups v1 = pairwise fan-out** over the same peer links; group = named set of contact keys | zero new crypto; sender-keys documented as P2 scale upgrade. (D §6) |
| D11 | **Offline dead-drop = P2 (nostr, vendored single-file audited noble-secp256k1 — “inhouse” per owner’s rule)** | nostr needs BIP340 Schnorr, not Node-native; keeps v1 truly zero-vendor. v1 buffers + resends while both online; honest about offline gap. (C §4 + synthesis) |
| D12 | **Revocation = rotate identity key (new string)**; one-time sealed-invite strings (Noise NNpsk0) = flag-bit P2 feature | no extra bits spent; default UX stays one copyable string. (D §4) |

## 3. The protocol, end to end

```
Alice (owner): S_A = encode26(version ‖ trunc(SHA256(ctx‖edA‖xA),110) ‖ checksum)
  listen(): every rendezvous channel gets announce(rid_A = HKDF(S_A,"p2p-rv-v1",epoch));
            keepalives hold NAT mappings; re-announce per channel clock.

Bob (holder of S_A):
  1 checksum-validate S_A locally (no network on typo)
  2 resolve: race mDNS / DHT get_peers(rid_A) / tracker announce(rid_A) → endpoint candidates
  3 dial candidates in parallel (punch choreography via shared rendezvous when needed)
  4 HELLO ← Alice: {v, edA_pub, xA_pub, sig_edA(transcript)}
  5 GATE: trunc(SHA256(ctx‖edA_pub‖xA_pub),110) == commitment(S_A) ? continue : drop
  6 Noise IK: msg1 → (e,es,s,ss)   msg2 ← (e,ee,se)
  7 Bob decrypts msg2 = KEY CONFIRMATION = the first ack the owner specified.
    Alice TOFU-pins Bob's static (or gates it against S_B if Bob shared his string).
  8 Split() → per-direction ChaCha20-Poly1305 keys → framed, reliable, encrypted chat.
```

**Security claim earned (full text + bounds: research/crypto-firstcontact.md §10):** active
MITM on any/all rendezvous channels, without Alice's private key, cannot impersonate her or
read anything; forgery ≤ max(2⁻¹¹⁰, 2⁻¹²⁸). Mutual acks ⇒ mutual auth. Residual, stated
honestly: initiator direction is TOFU with a single string; relay sees topic-timing metadata;
pre-quantum harvest (P3 hybrid ML-KEM path noted).

## 4. Module map + budget (~2.5–3.5k LOC total)

| Module | Job | LOC |
|---|---|---|
| `src/key.js` | keygen, encode/decode/checksum, commitment gate | ~150 |
| `src/noise.js` | Noise IK + Split(), vector-tested | ~350 |
| `src/wire.js` | framing, connection ID, seq/ack ARQ, nonce mgmt | ~200 |
| `src/transport.js` | UDP core, STUN client, punch, keepalive, TCP fallback | ~450 |
| `src/rendezvous/mdns.js` | LAN fast-path | ~150 |
| `src/rendezvous/dht.js` | bencode + KRPC + iterative lookup + announce | ~450 |
| `src/rendezvous/tracker.js` | WSS announce (native WebSocket) | ~150 |
| `src/rendezvous/race.js` | publish-fanout + read-race + epoch handling | ~120 |
| `src/node.js` | public API, peer lifecycle, resend buffer | ~250 |
| `src/group.js` | pairwise fan-out groups | ~100 |
| `bin/p2p-chat.js` | demo CLI chat (dogfood + verification surface) | ~120 |

API surface: `docs/API-SKETCH.md` (6-call budget holds).

## 5. Phases

- **P0 — spike gates (premortem kill-criteria):** (a) STUN+punch between two real networks;
  (b) DHT announce/get_peers round-trip on public Mainline; (c) Noise IK handshake w/ native
  crypto passing official vectors. Any gate fails → escalate per premortem.
- **P1 — v1 core:** modules above, CLI chat, cross-network verified, adversarial crypto
  review to zero criticals, README + spec.
- **P2:** nostr dead-drop (vendored noble), BEP44 presence records, birthday punch,
  peer-relay, sealed invites, sender-keys groups, browser adapter study.

## 6. Rejected alternatives (so nobody re-litigates silently)

WebRTC/libwebrtc (~50MB dep vs our ~1k LOC) · QUIC (not stdlib-ready; stole connection-ID
idea only) · PAKE/SPAKE2 (for low-entropy codes; ours is 130-bit) · shared-secret-as-key
(breaks reusability — holder could MITM introductions) · full-pubkey-in-string (needs ~52
chars; owner fixed 26) · Python core (stdlib crypto gap) · iroh-wrapper (best NAT numbers,
but Rust core + bindings violates zero-dep and kills "smallest possible") · BEP44-first
(D7) · MQTT in v1 (ToS "don't rely"; fallback slot only) · IPFS gateways (no anon write).

## 7. Open items owner may weigh in on (defaults chosen, work proceeds)

1. D1 Node-first (Go port later) — flag if Go/binary matters more than embed-in-JS.
2. D11 offline delivery deferred to P2 — flag if dead-drop is v1-critical.
3. Group size target (pairwise fine ≤ ~20; sender-keys earlier if bigger groups matter).
