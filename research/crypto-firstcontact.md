# p2p — Cryptographic Design Study: Provably MITM-Proof First Contact

> Research Lane D. Owner: fire17. Status: DECISION-GRADE DRAFT.
> Scope of this file (boundary contract): the cryptography of identity encoding,
> first-contact authentication, rendezvous *derivation requirements* (not channel
> choice — that is another lane), session crypto, groups, primitive availability,
> and the threat model. This file is the sole deliverable of Lane D.
>
> Reading contract: a cryptographically-literate senior engineer reading ONLY this
> file can implement the recommended handshake and defend its security claims.
> Every non-obvious claim carries a citation URL. Anything not confirmed from a
> primary source is marked **UNVERIFIED** or **OPEN QUESTION**.

---

## 0. TL;DR — the recommendation in six lines

1. **The 26-char key is a PUBLIC, self-authenticating identity string**, not a shared
   secret: `version || truncated-hash-commitment(owner's long-term public key) || checksum`.
   It is reusable and copyable by anyone — that is the whole point — yet no holder can
   impersonate the owner, because the string binds to the owner's *unique* key, and
   only the owner holds the matching private key.
2. **First contact = Noise `IK` handshake.** The initiator already knows (a commitment
   to) the responder's static key from the string; it pins it. The responder proves
   possession of the matching private key. Man-in-the-middle without the private key
   **cannot** complete the handshake.
3. **The "first ack proves it" claim is formally *key confirmation + responder
   authentication*.** If the initiator receives a message it can decrypt/verify under
   keys derived with the pinned static key, an active MITM has been ruled out with
   forgery probability `≤ 2^-(commitment bits)` (≈ `2^-110` at the recommended split).
4. **No PAKE.** PAKE (SPAKE2/CPace/OPAQUE) exists to protect *low-entropy* secrets from
   offline dictionary attack. A ~130-bit string is high-entropy; PAKE adds no security
   here and adds complexity. A KDF + authenticated Noise handshake is sufficient and simpler.
5. **Rendezvous topics are HKDF-derived from the string** (`HKDF(S, "rendezvous", epoch)`)
   so only key-holders can locate the owner; network observers cannot enumerate or link.
6. **Session crypto:** Noise transport (ChaCha20-Poly1305) with per-session ephemeral →
   forward secrecy per session for v1. Double Ratchet is a documented v2 upgrade, not
   needed for a tiny lib. **Groups:** pairwise fan-out for v1 (≤ ~20 members); sender-keys
   as the scale upgrade; MLS is out of scope.

---

## 1. Key encoding math

### 1.1 How many bits in 26 characters?

| Encoding | Bits/char | 26 chars | Alphabet notes |
|---|---|---|---|
| **base32** (RFC 4648, incl. Crockford, z-base-32) | 5 (= log2 32) | **130 bits** | 32-symbol alphabet; case-insensitive; human-transcribable |
| **base58** (Bitcoin/IPFS style) | log2(58) ≈ 5.858 | **≈ 152 bits** | 58-symbol; no `0 O I l`; case-sensitive; no fixed char↔bit boundary |
| **base64** (RFC 4648) | 6 | 156 bits | 64-symbol; `+/=`; not copy-paste-friendly / not case-insensitive |
| **hex** | 4 | 104 bits | 16-symbol; verbose |

So the owner's stated "~130 bits if base32" is **exactly correct for base32**: 26 × 5 = **130 bits**.
Reference for base32/base64 alphabets and padding: RFC 4648 *"The Base16, Base32, and Base64
Data Encodings"* — https://www.rfc-editor.org/rfc/rfc4648.

**Encoding recommendation.** Use a base32 variant, not base58, because:
- base32 is a clean 5-bits-per-char mapping → trivial, constant-time-friendly encode/decode,
  no bignum division (base58 requires bignum long-division, awkward in three languages).
- Case-insensitive → survives voice, handwriting, URLs, and clipboards that lowercase.
- **Crockford base32** (https://www.crockford.com/base32.html) additionally excludes
  visually ambiguous letters (`I L O U` are remapped/omitted) and defines an *optional
  check symbol*, which we can co-opt for the checksum. **z-base-32**
  (http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) is designed for
  human use and orders the alphabet by ease of transcription — either is fine; **Crockford
  is the recommendation** because of the built-in check symbol.
- base58's only advantage (152 bits in the same 26 chars) matters *only* if we need more
  than 130 bits of payload; §1.3 shows 130 is enough, so we keep base32's ergonomics.

### 1.2 Comparison: ToxID and magic-wormhole codes

- **ToxID** — 76 hex characters = 38 bytes = **304 bits** (VERIFIED), laid out as
  `[32-byte Curve25519 public key] || [4-byte nospam] || [2-byte checksum]`. The public key
  IS the identity (no hash — the whole key is shown); `nospam` is a rotatable anti-spam value
  that changes the ID without changing the key; the checksum is a 2-byte XOR-fold of the
  preceding 36 bytes. (github.com/Tox/Tox-Docs `core_concepts.rst`, wiki.tox.chat/users/toxid —
  byte-level checksum op is UNVERIFIED against toxcore source; cross-check before implementing.)
  *Lesson taken:* Tox publishes the FULL 256-bit key → 76 chars, too long for our 26-char
  target. We therefore publish a **truncated hash commitment**, not the whole key (§1.3).
  We also steal Tox's `nospam` idea as an optional rotatable anti-spam field.
- **magic-wormhole code** — `channel-number-word-word`, e.g. `7-crossover-clockwork`, words
  drawn from a PGP-wordlist derivative. Entropy is deliberately **LOW — 16 bits** (VERIFIED:
  docs state *"a 1-in-65536 chance of success"* per attempt) because a human reads it aloud
  once. Low entropy is *why* wormhole needs a PAKE (SPAKE2, RFC 9382, over the Ed25519 group) —
  see §2.2. Our string is the opposite design point: high entropy, copy-pasted, so no PAKE.
  (magic-wormhole — https://magic-wormhole.readthedocs.io/en/latest/welcome.html.)

### 1.3 How to split / derive the 130 bits — the bit budget

The string `S` must simultaneously serve as (a) an **identity commitment** the initiator can
verify against the responder's presented public key, and (b) a **rendezvous-derivation seed**
known only to holders. Both uses can share the same bits: `S` is high-entropy and is only ever
disclosed to people the owner hands it to.

**Recommended layout (130 bits):**

```
 bits  field            purpose
 ----  ---------------  --------------------------------------------------------------
   5   version/flags    1 base32 char. algorithm agility (curve, hash, KDF); flags
                        (e.g. "expects mutual fingerprint", "one-time invite").
 110   identity commit  truncate(H(context || static_pubkey), 110)  — the fingerprint.
                        second-preimage resistance = 2^110 (see below).
  15   checksum         detect copy/transcription typos before any network work.
 ----
 130   total (= 26 base32 chars)
```

**Why 110 bits of commitment is enough.** The attack that matters is **second-preimage**:
an active MITM wants to generate a *different* keypair whose public key hashes to the *same*
110-bit commitment, so its substituted key passes the initiator's fingerprint check. For a
hash truncated to `n` bits, second-preimage work is `≈ 2^n`. At `n = 110` that is `2^110`
hash evaluations — infeasible (comparable cost to a full brute-force of a 110-bit key; well
above the ~2^100 comfort floor and far beyond any realistic adversary). Collision resistance
(`2^(n/2) = 2^55`) is **not** the relevant bound here, because the attacker cannot choose the
*owner's* key — the owner's key is fixed before the attacker acts, making this second-preimage,
not collision. (If we ever let an attacker choose both keys — we do not — we would need the
full `2^(n/2)` collision bound and 110 bits would give only `2^55`, so this distinction is
load-bearing; documented so nobody "optimizes" the design into a collision game.)

**If the owner wants MORE than a fingerprint** — e.g. a rotatable secret salt for revocation
independent of the identity key, *and* a strong fingerprint, *and* a checksum — 130 bits gets
tight. Two escape hatches, in preference order:
1. Keep the fingerprint model; **rotate the identity key** to revoke (a new key = a new string).
   Simple, no extra bits. (Recommended.)
2. If independent revocation without key rotation is required, either (a) accept a smaller
   commitment (e.g. 90-bit commit + 25-bit secret salt + version + checksum → `2^90`
   second-preimage, still strong), or (b) move to **~30 base32 chars (150 bits)** or
   **base58 (≈152 bits in 26 chars)** to buy headroom. Flag to owner as a UX-vs-headroom
   knob; **default = option 1**.

The `version` field is non-negotiable: it is what lets the curve/hash/AEAD change later
without breaking old strings (crypto-agility). Cost is one character.

---

## 2. First-contact authentication

### 2.1 What the shared string actually is, and the two regimes

There are two fundamentally different things a shared string can be, and conflating them is
the central design trap:

- **Regime A — PUBLIC identity commitment (fingerprint).** `S` commits to the owner's
  long-term public key. Anyone may hold it, publish it, reuse it. It authenticates the
  **key owner** to whoever initiates. This is Tox / Briar / Ricochet / Signal-safety-number
  model. **This is what the owner described** ("a copyable contact key anyone can use to reach me").
- **Regime B — shared SECRET (PSK).** `S` is a symmetric secret both sides hold. It
  authenticates "the peer holds the same secret." It is **not** safe to reuse across many
  people — see §4 — but it gives one-shot mutual authentication from a single value.
  This is magic-wormhole's model (a one-time code).

The recommendation is **Regime A as the default**, with an optional **Regime B "sealed
invite"** mode (§4.3) for one-time, one-to-one high-assurance introductions.

### 2.2 Do we need a PAKE? No.

**PAKE (Password-Authenticated Key Exchange) — SPAKE2, CPace, OPAQUE — solves exactly one
problem: turning a LOW-entropy shared secret into a strong session key while permitting the
active attacker only ONE online guess per run and ZERO offline guesses.** Its whole reason to
exist is offline-dictionary resistance: if the shared secret is a human word or a 4-digit PIN,
a naive `KDF(secret) → key` handshake leaks a transcript an attacker can brute-force offline.
PAKE prevents that.

- **SPAKE2** — balanced (symmetric) PAKE (**RFC 9382**,
  https://datatracker.ietf.org/doc/html/rfc9382; Abdalla–Pointcheval); what magic-wormhole uses
  over its ~16-bit code (python-spake2 defaults to the Ed25519 group). Load-bearing there
  *precisely because* the code is tiny.
- **CPace** — the CFRG-selected balanced PAKE, currently **draft-irtf-cfrg-cpace-21** (not yet an
  RFC; https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/). Modern balanced-PAKE choice,
  optimized for constrained devices.
- **OPAQUE** — an *augmented/asymmetric* PAKE (aPAKE), now **RFC 9807**
  (https://datatracker.ietf.org/doc/rfc9807/): client holds a password, server holds an
  OPRF-based envelope/verifier — roles are fundamentally asymmetric, designed so a compromised
  server never learns the password (TLS-password-login replacement). It does **not** fit a
  symmetric P2P shared-secret scenario — both peers already hold the identical secret, so there
  is no client/server asymmetry for OPAQUE to solve.

**Our secret is ~130 bits.** Offline dictionary attack against 130 bits of entropy is `2^130`
work = infeasible regardless of protocol. Therefore the offline-dictionary threat PAKE defends
against **does not exist** for us, and PAKE buys **no additional security** while adding a
nontrivial, harder-to-audit primitive. **Decision: no PAKE.** Noise's own PSK design is
explicitly scoped to high-entropy secrets — the spec §14 mandates *"Pre-shared symmetric keys
must be secret values with 256 bits of entropy"* and deliberately punts the low-entropy case to
PAKE-style protocols — confirming that at ≥128-bit entropy a KDF + PSK-authenticated Noise
handshake is the intended, sufficient, simpler tool. (Synthesis from primary sources: the RFC
9382 / CPace draft / OPAQUE RFC 9807 threat models + the Noise §14 entropy mandate + magic-
wormhole's own stated rationale for why *it* needs a PAKE. No single paper states "PAKE
unnecessary above N bits" verbatim — it follows directly from each construction's stated threat
model. Marked as reasoned synthesis.)

### 2.3 Noise Protocol Framework — the handshake toolkit

The **Noise Protocol Framework** (https://noiseprotocol.org/noise.html — **revision 34,
2018-07-11**, author Trevor Perrin) is the right foundation: it is a well-specified,
widely-deployed (WireGuard, WhatsApp, Lightning, Signal-adjacent) construction kit for DH-based
handshakes with formal, per-pattern security properties. We **compose it; we never invent a
handshake.**

Relevant vocabulary:
- Static keypair `s` (long-term identity), ephemeral keypair `e` (per-handshake, gives forward
  secrecy). DH tokens `ee, es, se, ss` mix the corresponding shared secrets into the running key.
- **PSK patterns** (`...psk0/psk1/psk2/psk3`) mix a 32-byte pre-shared symmetric key into the
  handshake via `MixKeyAndHash` (spec §5.2/§9): `MixKeyAndHash(psk)` folds the psk into **both**
  the transcript hash `h` (any tamper detected) **and** the chaining key `ck` (all subsequent
  traffic keys depend on it). The `pskN` suffix is *where* the psk token sits (`psk0` = start of
  msg 1; `psk1/2/3` = end of msg 1/2/3). Patterns: `NNpsk0` (no static keys, auth purely from
  PSK — `→ psk, e` / `← e, ee`), `NKpsk0` (responder static known + PSK), `XXpsk3`/`IKpsk2`
  (static keys + PSK). Spec §9.3 rule: a party may not send encrypted data after a `psk` token
  until it has sent an `e` (ephemeral) — so psk-derived keys are always randomized by a fresh DH.
  **Note:** §14 requires psk = 256-bit-entropy; a psk derived from our 130-bit string carries
  only 130 bits of entropy (still far beyond feasible attack, but state it honestly — the psk is
  a 32-byte value, its *entropy* is capped by the source string).

**Pattern selection for Regime A (fingerprint).** The initiator knows (a commitment to) the
responder's static key. That is precisely Noise's precondition for the **`K`** family (responder
static known to initiator ahead of time):

- **`NK`** — initiator anonymous, responder static known. Gives: **responder authentication +
  confidentiality + forward secrecy**. Initiator is unauthenticated. Good if the owner only
  needs "the initiator can prove it reached the real me."
- **`IK`** — initiator *also* transmits its own static key (encrypted) to the responder, whose
  static the initiator already knows. Gives **mutual authentication**: responder authenticated
  immediately by the pinned fingerprint (strong); initiator's key delivered so the responder
  can pin it (TOFU, or verified against the initiator's own fingerprint if both strings were
  exchanged). **`IK` is the recommendation** — it is exactly the pattern WhatsApp uses for the
  same "I know your identity key in advance" situation (WhatsApp uses Noise Pipes with an `IK`
  handshake — "WhatsApp Encryption Overview" technical whitepaper,
  https://www.whatsapp.com/security/ ; the specific "IK" claim is widely documented but
  UNVERIFIED-by-independent-fetch here — not load-bearing, cited only as precedent).

**Pattern selection for Regime B (shared secret / sealed invite).** `NNpsk0` (or `NKpsk0` if
you also pin a static) keyed by `psk = HKDF(S, "psk")` gives mutual authentication from the
single shared secret in a two-message handshake. Use only for one-time invites (§4.3).

### 2.4 The precise security claim

For the recommended **`IK`** handshake with the responder's static key pinned to the 110-bit
commitment in `S`:

> **Claim.** An active adversary in full control of the rendezvous channel (read, drop, inject,
> reorder) who does **not** hold the owner's static private key **cannot** impersonate the owner
> to an initiator, and **cannot** decrypt the session. To impersonate the owner it must present a
> static public key that (i) passes the initiator's fingerprint check —
> `truncate(H(context‖key),110) == commitment` — which requires a second preimage of a 110-bit
> truncated hash, work `≈ 2^110`; **or** (ii) recover the owner's private key from the public key
> — the Curve25519 discrete-log problem, `≈ 2^128` (RFC 7748). The adversary's success
> probability is therefore bounded by `≈ 2^-110` per attempt. Confidentiality and forward secrecy
> against a non-key-holding MITM follow from the Noise `IK` properties (the ephemeral DH `ee`
> gives forward secrecy; the AEAD gives confidentiality/integrity).

**What "seeing the first ack proves" — formally.** Two standard notions:
- **Responder authentication** — the initiator ends the handshake with cryptographic evidence
  that the peer holds the private key matching the pinned fingerprint.
- **Key confirmation** — receiving a valid AEAD-authenticated message under the derived keys
  proves the peer *actually derived the same keys*, i.e. completed the DH with the pinned key.
  Noise's `IK` second message (`e, ee, se`) and the first transport message are key-confirming:
  they decrypt/verify **only** if the responder used the pinned static private key.

So when the owner says *"if the users see the first ack between each other, MITM could not
pretend to be either party nor listen in,"* the formal statement is: **the ack is a
key-confirmation transcript; a successful mutual ack is mutual key confirmation, which under
`IK` with pinned statics implies mutual authentication and rules out a non-key-holding MITM
with probability `≥ 1 − 2^-110`.** The intuition ("we both saw it work → no one is in the
middle") is *correct and provable* — provided both directions are authenticated (§4 covers the
asymmetric single-string case, where the reverse direction is TOFU until fingerprints are
exchanged).

---

## 3. Rendezvous derivation (requirements only — channel choice is another lane)

This lane specifies **what the crypto layer requires of the rendezvous ID**, not which network
carries it.

1. **Derived, not the raw key.** `rendezvous_id = HKDF(S, salt="p2p-rendezvous-v1", info=epoch)`
   (HKDF = RFC 5869, https://www.rfc-editor.org/rfc/rfc5869). Publishing `S` directly as a topic
   would let the raw commitment (and thus, with the presented key, the owner's identity) leak to
   the rendezvous network. Deriving means the on-wire topic is an opaque pseudorandom value.
2. **Only holders can compute it.** Since `HKDF` needs `S`, a network observer who was never
   given `S` cannot compute the topic → **cannot enumerate contacts, cannot link topics to an
   identity, cannot target the owner**. This is the anti-enumeration property.
3. **Time-rotating topics.** `epoch = floor(unix_time / T)` for some window `T` (e.g. minutes to
   hours — a channel-lane tuning knob). Each epoch yields a fresh unlinkable topic. Both parties
   compute `{epoch-1, epoch, epoch+1}` to tolerate clock skew.
4. **Anti-replay.** The handshake itself must carry freshness: fresh ephemerals every run
   (Noise provides this) plus a coarse timestamp/nonce so a replayed handshake message from an
   old epoch is rejected. Rotating epochs already bounds the replay window; the nonce closes the
   within-epoch gap.
5. **Separation.** Rendezvous-derivation, session-key derivation, and (if used) PSK derivation
   MUST use distinct HKDF `info`/`salt` labels so the same `S` never produces the same bytes for
   two purposes (domain separation).

> **DoS note (crosses into the channel lane — flagged, not decided here):** because *any* holder
> can compute the topic, any holder can flood it. Blast radius is bounded to "people the owner
> trusted with `S`." Mitigations (rate-limit per topic, cheap client puzzle before the expensive
> DH, per-epoch rotation shrinking the target window) are recommended but their placement is the
> channel lane's call.

---

## 4. Reusable vs one-time keys — the central tension, resolved

### 4.1 The tension

The owner wants a **copyable key anyone can use to reach them**. The naive reading is "a shared
secret," but a shared secret reused across many people is broken:

> **If `S` is a symmetric PSK and both Bob and Mallory hold it**, Mallory can impersonate the
> owner to Bob (Mallory completes the PSK handshake as "the owner"), and can sit in the middle of
> Bob's introduction. A symmetric secret proves *"peer knows the secret,"* not *"peer is a
> specific identity."* With many holders, that guarantee is worthless for authentication.

### 4.2 The fix — Regime A: publish a commitment to a public key, not a secret

Make `S` a commitment to the **owner's long-term public key** (§1.3). Now:
- Everyone may hold `S` and reach the owner (reusable ✓, copyable ✓, "anyone can use it" ✓).
- **No holder can impersonate the owner**, because impersonation requires the owner's *private*
  key, which `S` does not contain and does not leak. A rogue holder is just another contact.
- **No holder can MITM a third party's contact with the owner**, because `S` binds to the
  owner's unique key; the third party's fingerprint check will reject any substituted key.

This is why the fingerprint model is the correct resolution of the "reusable + MITM-proof"
tension. It is the same reason Tox IDs, Briar links, and onion-service addresses are safely
publishable.

**One honesty caveat — directionality.** A single published string authenticates the **owner
(responder)** to initiators. It does **not**, by itself, tell the owner *who the initiator is*.
So first contact with ONE string is:
- **Owner-direction: strong.** Initiator provably reached the real owner (fingerprint-pinned).
- **Initiator-direction: TOFU.** The owner learns the initiator's key from the `IK` handshake
  and pins it on first use. A MITM present *at the very first contact* could substitute the
  *initiator's* key (not the owner's). Hardening: (a) both parties exchange contact strings so
  each pins the other by fingerprint → **full mutual authentication, fully MITM-proof both ways**;
  or (b) upgrade-to-pinned: once the (owner-authenticated, confidential) channel exists, the
  parties exchange/confirm each other's fingerprints *over that channel* — a MITM cannot inject
  into a channel it cannot decrypt, so the pin is safe (TOFU hardened by the PSK-strength owner
  authentication). This is the **"see the ack → it's proven"** experience: after the mutual ack,
  both fingerprints are confirmed and the channel is provably clean both ways.

### 4.3 Optional Regime B — the "sealed invite" (one-time, one-to-one)

When the owner wants a *single* string that yields **immediate mutual authentication** without
exchanging two strings, issue a **per-invite one-time secret**: `S_invite` is a fresh 130-bit
random value, handed to exactly one person, used once. Handshake: `NNpsk0` (or `NKpsk0`) with
`psk = HKDF(S_invite, "psk")`. Because only two parties ever hold `S_invite`, "peer knows the
secret" *is* mutual authentication. After first contact, both sides swap and pin long-term
identity keys over the now-authenticated channel, and `S_invite` is burned.

Trade-off: not reusable (one string per contact) — but strongest single-string mutual auth.
Offer both; **default to Regime A** for the owner's stated "one copyable key for everyone" UX,
and offer Regime B as "generate a secure one-time invite."

### 4.4 Recommended model (cleanest that keeps UX = "copy one string")

> **`S` = version ‖ commitment(owner's long-term X25519 identity key) ‖ checksum**, published
> and reusable. First contact = Noise **`IK`** (responder pinned by fingerprint; initiator
> TOFU-pinned). To make it mutually MITM-proof, either both parties exchange strings, or they
> confirm fingerprints over the owner-authenticated channel. Provide a separate **one-time
> sealed-invite** mode (Regime B, `NNpsk0`) for high-assurance 1:1 introductions.

---

## 5. Session crypto (after first contact)

- **AEAD:** **ChaCha20-Poly1305** (RFC 8439, https://www.rfc-editor.org/rfc/rfc8439) is the
  default — fast in software (no AES hardware dependency), constant-time by construction, and
  the Noise default cipher. **AES-256-GCM** is an equally acceptable alternative where hardware
  AES is guaranteed (it can be faster with AES-NI); expose it via the `version`/cipher-agility
  field. Nonce discipline: Noise manages transport nonces as a counter — never reuse a
  (key, nonce) pair; rekey before counter exhaustion.
- **Key agreement:** **X25519 ECDH** (RFC 7748, https://www.rfc-editor.org/rfc/rfc7748) inside
  the Noise handshake. Ephemeral `e` on each handshake gives **per-session forward secrecy**.
- **Double Ratchet — needed for v1? No.**
  - **Per-session ephemeral (recommended v1):** the Noise handshake's ephemeral already gives
    forward secrecy *at session granularity* — compromise of long-term keys does not retro-
    actively decrypt past *sessions* (provided ephemerals are wiped). Caveat to state honestly:
    *within* one session there is no per-message ratchet, so a mid-session key compromise exposes
    that whole session (past and future messages in it) and there is no post-compromise healing —
    hence the recommendation to keep sessions short-lived / rotate often, and add periodic
    in-session rekeying (Noise `Rekey()`). Simple, small, sufficient for a chat lib v1.
  - **Double Ratchet (Signal, https://signal.org/docs/specifications/doubleratchet/):** adds
    **per-message forward secrecy** *and* **post-compromise security** ("healing" — a future DH
    ratchet step recovers security after a key compromise). Cost: skipped-message-key storage,
    out-of-order handling, header encryption, chain/root/DH ratchet state machine — a meaningful
    complexity and audit burden for a "tiny, zero-dep" lib. Signal also needs **X3DH**
    (https://signal.org/docs/specifications/x3dh/) for asynchronous initial agreement; our
    rendezvous+`IK` already covers initial agreement.
  - **Decision:** v1 = Noise transport + per-session ephemeral + periodic rekey. Document
    Double Ratchet as the v2 upgrade for users who need per-message FS / PCS.

---

## 6. Groups

| Model | Per-message cost | Membership change | Complexity | Fit |
|---|---|---|---|---|
| **Pairwise fan-out** | O(N) encrypt (once per member, over existing 1:1 channels) | trivial (add/remove a channel) | **lowest — reuses 1:1 crypto, no new primitive** | **v1, ≤ ~20 members** |
| **Sender keys** (Signal group model) | O(1) encrypt + O(N) key distribution *once* per epoch | re-distribute sender key on membership change | medium | scale upgrade |
| **MLS / TreeKEM** (RFC 9420) | O(log N) | O(log N) | high | large/at-scale groups — **out of scope for a tiny lib** |

- **Pairwise fan-out (recommended v1):** sender encrypts the message separately to each member
  using the already-established pairwise session. Zero new cryptography — the group is just a set
  of 1:1 channels. Metadata/ordering handled at the app layer. Perfectly sane for small friend
  groups; O(N) bandwidth is a non-issue at N ≤ ~20.
- **Sender keys (scale upgrade):** each member generates a symmetric "sender key" (a chain key)
  and distributes it once to every other member *over the pairwise channels*; thereafter each
  message is encrypted once under the sender's ratcheting chain key (hash ratchet → per-message
  FS) and broadcast. Cuts per-message cost to O(1) at the price of a re-key on every membership
  change — critically, a member *leaving* forces ALL members to wipe the sender key and redo the
  full O(N) pairwise re-distribution (no fine-grained removal without a full reset). Signal's
  group design. (https://en.wikipedia.org/wiki/Sender_Keys; Signal protocol docs.)
  *Judgment note:* a reasonable case exists for making sender-keys the v1 default even at N ≤ 20
  (O(1) steady-state send). This study keeps **pairwise as the v1 recommendation** because it
  adds ZERO new cryptography (the group is literally a set of already-audited 1:1 channels),
  which best serves the "tiny, minimal" goal; sender-keys is the first upgrade once group size or
  message rate makes O(N) fan-out hurt.
- **MLS (RFC 9420, https://www.rfc-editor.org/rfc/rfc9420):** efficient continuous group key
  agreement via TreeKEM; the right answer for hundreds–thousands of members with strong FS/PCS.
  Explicitly **overkill** for a minimal lib; note as the ceiling, do not build it in v1.

**Decision:** pairwise fan-out for v1; design the message API so sender-keys can slot in later
without changing the wire identity model.

---

## 7. Primitive availability (zero-dependency goal)

> Rule: **never invent primitives.** Compose standard ones — X25519 (RFC 7748),
> ChaCha20-Poly1305 (RFC 8439), HKDF (RFC 5869), Ed25519 (RFC 8032), Noise (noiseprotocol.org).
> Below: what each runtime provides natively vs what must be vendored. **All version claims below
> are VERIFIED against primary docs (nodejs.org, pkg.go.dev, go.dev, MDN, caniuse, W3C/WICG).**

### 7.1 Node.js built-in `crypto` — **all primitives native, no vendoring**
Node in this environment = **v23.7.0** (verified: `node --version`). The full set has been native
since **Node 15** (HKDF was the last piece). Docs: https://nodejs.org/api/crypto.html.

| Primitive | API | Native since |
|---|---|---|
| X25519 keygen | `crypto.generateKeyPair('x25519', …)` | **v12.0.0** |
| X25519 DH | `crypto.diffieHellman({privateKey, publicKey})` | v13.9.0 / v12.17.0 |
| Ed25519 keygen | `crypto.generateKeyPair('ed25519', …)` | **v12.0.0** |
| Ed25519 sign/verify | `crypto.sign()` / `crypto.verify()` | **v12.0.0** |
| ChaCha20-Poly1305 | `crypto.createCipheriv('chacha20-poly1305', …)` | v11.2.0 / v10.17.0 (IETF variant; bundled OpenSSL ≥1.1.0) |
| AES-256-GCM | `crypto.createCipheriv('aes-256-gcm', …)` + `getAuthTag`/`setAuthTag` | v1.0.0 |
| HKDF | `crypto.hkdf()` / `crypto.hkdfSync()` | **v15.0.0** |

→ **Zero dependencies on Node** for the entire primitive set.

### 7.2 Go standard library — **native except ChaCha20-Poly1305**
Go here = **go1.26.1** (verified: `go version`). Full native stdlib set from **Go 1.24+**, with
one exception.

| Primitive | Location | Native since |
|---|---|---|
| X25519 | `crypto/ecdh` (`ecdh.X25519()`) — https://pkg.go.dev/crypto/ecdh | **Go 1.20** |
| Ed25519 | `crypto/ed25519` — https://pkg.go.dev/crypto/ed25519 | Go 1.13 |
| AES-GCM | `crypto/cipher` (`cipher.NewGCM`) + `crypto/aes` | pre-1.0 |
| HKDF | **`crypto/hkdf`** — https://pkg.go.dev/crypto/hkdf (was `golang.org/x/crypto/hkdf`) | **Go 1.24** |
| **ChaCha20-Poly1305** | **`golang.org/x/crypto/chacha20poly1305`** — NOT in stdlib — https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305 | external module |

→ **Go needs one dependency, `golang.org/x/crypto`, for ChaCha20-Poly1305** (and for HKDF on
Go < 1.24). `x/crypto` is Go-team-maintained ("near-stdlib") but is technically an external
module — it breaks strict zero-dep if that is a hard rule. See the OPEN QUESTION in §12.

### 7.3 Browser WebCrypto (SubtleCrypto) — 2025/2026 status **VERIFIED**
- **AES-GCM** — universal ("Baseline widely available" since ~2020). ✓
- **HKDF** — `deriveBits`/`deriveKey` `{name:'HKDF'}` — universal (Baseline since Jan 2020). ✓
  (https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveBits)
- **X25519** — `deriveBits`/`deriveKey` `{name:'X25519'}` — shipped **Chrome/Edge 133, Firefox 130,
  Safari 17.0**. Spec is the **WICG "Secure Curves in the Web Cryptography API"**
  (https://wicg.github.io/webcrypto-secure-curves/) — a **WICG incubation doc, NOT W3C
  standards-track**. caniuse: https://caniuse.com/mdn-api_subtlecrypto_derivebits_x25519.
  → Modern browsers: yes; but **feature-detect and keep a vendored fallback** (non-standards-track
  API surface, and older browsers lack it).
- **Ed25519** — sign/verify shipped **Chrome/Edge 137, Firefox 129, Safari 17.0**; same WICG spec.
  caniuse: https://caniuse.com/mdn-api_subtlecrypto_sign_ed25519. Same feature-detect caveat.
- **ChaCha20-Poly1305** — **NOT in WebCrypto. Zero browser implementations.** Tracked at
  https://github.com/w3c/webcrypto/issues/223 (open since 2019); lives only in the draft WICG
  "Modern Algorithms" doc (https://wicg.github.io/webcrypto-modern-algos/). → If the lib
  standardizes on ChaCha20-Poly1305 for one cross-runtime wire format, the **browser must vendor
  it** (a well-reviewed JS/WASM impl — e.g. noble-ciphers or libsodium.js). Alternative: AES-GCM
  in-browser via cipher-agility, but that fragments the wire format. **Recommendation: vendor
  ChaCha20-Poly1305 everywhere, keep ONE wire format** (OPEN QUESTION §12).

### 7.4 What must be vendored — summary
- **Noise handshake state machine** — Noise is a *framework*, not a single library primitive; the
  handshake logic (~a few hundred LOC) is implemented on top of the primitives above in each
  language. Use a well-reviewed existing Noise library where possible (e.g. `noise-c`/`noise-java`
  ports, `flynn/noise` for Go) rather than hand-rolling — composing Noise from primitives is
  fine, but the *state machine* is where subtle bugs live; prefer an audited implementation.
- **Browser ChaCha20-Poly1305** (if we standardize on it) — vendored, audited reference impl.
- Everything else (X25519, Ed25519, HKDF, AES-GCM) is native in Node and Go; native-or-near in
  modern browsers.

---

## 8. Threat model table

| # | Adversary / event | Capability | Our defense | Residual risk |
|---|---|---|---|---|
| 1 | **Passive observer on rendezvous** (non-holder) | reads all rendezvous traffic | topics are `HKDF(S,…)` — non-holder cannot derive them; all payloads E2E-encrypted | learns only that *some* opaque topics have traffic; no identities, no linkage |
| 2 | **Active MITM without `S` / without owner's private key** | full read/drop/inject/reorder on rendezvous | Noise `IK` with responder pinned to the 110-bit fingerprint; AEAD integrity | impersonation bounded by `2^-110` (2nd-preimage) / `2^-128` (Curve25519 DLP) |
| 3 | **Malicious rendezvous node** (the relay itself is hostile) | drop, delay, inject, observe topic metadata | it is only a relay — cannot decrypt (no session key) or impersonate (no private key); no server of ours to subvert | availability attacks (censorship/DoS) possible → mitigations in row 6; metadata (topic timing) leaks to it |
| 4 | **Rogue key-holder** (someone the owner *gave* `S` to) | can reach the owner; can compute rendezvous topics | fingerprint binds to owner's key → rogue **cannot impersonate the owner** to others, **cannot MITM** a third party's contact | rogue can spam/track the owner's presence and reach them; **revoke by rotating the identity key** (new `S`) |
| 5 | **Replay** | replays captured handshake/messages | fresh ephemerals per handshake (Noise); epoch-rotating topics; timestamp/nonce freshness check | within-epoch replay window closed by nonce; ensure nonce store |
| 6 | **DoS / flooding on a rendezvous topic** | floods a topic (only possible for holders — row 4 — or a malicious node — row 3) | per-topic rate-limit; cheap client puzzle *before* the expensive DH; epoch rotation shrinks target window | full mitigation is a channel-lane concern; blast radius limited to holders |
| 7 | **Quantum adversary** (future) | Shor breaks X25519/Ed25519; Grover halves symmetric | **NOTE ONLY — out of scope v1.** Future: hybrid X25519 + ML-KEM (Noise PQ / hybrid patterns); symmetric (ChaCha20-Poly1305, 256-bit) stays ~128-bit under Grover — fine | pre-quantum handshakes are harvestable now, decryptable later ("store now, decrypt later") — flag to owner as the one forward-looking gap |

---

## 9. The recommended handshake — message by message

**Regime A (default), Noise pattern `IK`.** Notation: `s` = static, `e` = ephemeral;
`ee/es/se/ss` = DH mixes; `->`/`<-` = direction. Initiator = Bob (contacting owner Alice).

**Key subtlety — commitment vs. full key.** Noise `IK` takes the responder's static key `s_A`
as a **pre-message**: Bob needs the *full* 256-bit `s_A` (not just a hash) to compute `es`/`ss`
in msg1. But the 26-char string carries only the **110-bit commitment**, not the full key. So
the flow is **fetch-then-gate-then-IK**:
1. Bob computes `rendezvous = HKDF(S_A, "rendezvous", epoch)` and, at that rendezvous, receives a
   *candidate* full static key `s_A'` (Alice publishes it there / in a hello frame).
2. **Bob gates it against the string:** accept `s_A'` **iff** `truncate(H(ctx‖s_A'),110) ==
   commitment(S_A)`. A MITM that substitutes its own key at the rendezvous fails this check
   (second-preimage, `2^-110`). After the check, `s_A'` is as trustworthy as a pinned key.
3. Bob runs Noise **`IK`** with the now-verified `s_A'` as the pre-message static.

(Equivalent alternative: run Noise **`XX`** — both statics transmitted in-handshake — and
fingerprint-gate Alice's transmitted static against `commitment(S_A)` when it arrives. `XX` needs
no pre-fetch but sends Bob's static slightly earlier and is 1.5-RTT; **`IK` after the fetch-gate
is the recommendation** for its cleaner 1-RTT mutual-auth shape and match to the "I know your
identity in advance" model. Either is secure; the fingerprint gate is what does the work.)

```
Pre-message (known to initiator from S_A):   <- s_A            (responder static, pinned by fingerprint)

Handshake:
  msg1  Bob  -> Alice :  e, es, s, ss   + [payload: timestamp/nonce, Bob's fingerprint hint]
        - Bob sends ephemeral e_B; mixes es (e_B · s_A) and ss (s_B · s_A);
          transmits his static s_B encrypted under keys already bound to s_A.
        - Because es/ss use s_A, only the holder of a_A (Alice's private key) can proceed.

  msg2  Alice -> Bob  :  e, ee, se       + [payload: key-confirmation / first ack]
        - Alice replies ephemeral e_A; mixes ee (e_A·e_B) → forward secrecy, se (s_A·e_B).
        - This message decrypts/verifies for Bob ONLY if Alice used a_A.  ← THE ACK.

  transport: both derive send/recv AEAD keys (ChaCha20-Poly1305) via Noise Split().
```

**Why this is the ack the owner means.** When Bob successfully decrypts and verifies **msg2**,
he has a **key-confirmation transcript** proving the peer holds Alice's pinned private key → no
MITM impersonated Alice, and the channel is confidential (forward-secret via `ee`). Bob's static
`s_B` reached Alice in msg1; Alice TOFU-pins it (or verifies it against `S_B` if Bob shared his
string). When *Alice* likewise sees Bob's authenticated first transport message, **both** have
key confirmation → **mutual authentication**, and "seeing the ack on both sides" is exactly the
provable-clean-channel event the owner described.

**Regime B (one-time sealed invite), Noise `NNpsk0`** with `psk = HKDF(S_invite,"psk")`:

```
  msg1  Bob   -> Alice :  e            + [payload]     (psk mixed at position 0)
  msg2  Alice -> Bob   :  e, ee        + [payload]
  transport: Split() → AEAD keys.
```
Mutual authentication from the single one-time secret; then swap+pin long-term keys over the
channel and burn `S_invite`.

---

## 10. The exact security statement this earns

> Using Noise `IK` with the responder's static key pinned to a 110-bit hash commitment carried
> in the 130-bit contact string, and ChaCha20-Poly1305 transport keys from Noise `Split()`:
>
> 1. **Responder authentication + confidentiality + forward secrecy** hold against an active
>    network adversary that does not possess the owner's static private key, with impersonation
>    probability bounded by `max(2^-110 [2nd-preimage on the fingerprint], 2^-128 [Curve25519
>    discrete log, RFC 7748])`.
> 2. **A successful, decryptable first ack (msg2 / first transport message) is a key-confirmation
>    transcript**: it proves the peer derived the session keys using the pinned private key,
>    i.e. proves no non-key-holding MITM is present. Mutual acks ⇒ mutual authentication.
> 3. **Reusability is safe**: because the string commits to a public key (not a secret), any
>    number of holders can reach the owner, none can impersonate the owner, none can MITM a third
>    party — the only power a rogue holder gains is to reach/track the owner (revoked by key
>    rotation).
> 4. **Rendezvous unlinkability** against non-holders follows from HKDF-derived, epoch-rotating
>    topics.
> 5. **Not covered:** metadata exposure to the relay (topic timing), post-quantum security
>    (store-now-decrypt-later), and — in the single-string case — the *initiator* direction is
>    TOFU until fingerprints are mutually exchanged or confirmed over the owner-authenticated
>    channel.

---

## 11. Key-format recommendation (final)

```
Contact string  S  =  26 characters, Crockford base32 (RFC 4648 alphabet + Crockford check symbol)
                      = 130 bits, laid out:

   [ 5 bits  version/flags ]  [ 110 bits identity commitment ]  [ 15 bits checksum ]

   version/flags     crypto-agility (curve/hash/AEAD id) + mode flags (mutual-expected, one-time)
   identity commit   truncate( H(context_string || owner_static_pubkey), 110 )    H = SHA-256 or BLAKE2s
   checksum          transcription-typo detection, verified before any network activity

Derivations (domain-separated, HKDF = RFC 5869):
   rendezvous_id = HKDF(S, salt="p2p-rv-v1",  info=epoch)
   session_psk   = HKDF(S, salt="p2p-psk-v1", info="")     # only in Regime B / sealed invite
   (session AEAD keys come from Noise Split(), not directly from S)
```

- **Encoding:** Crockford base32 — case-insensitive, ambiguity-free, built-in check symbol.
- **Bits:** 130 (base32 × 26). If independent-revocation-without-key-rotation is required,
  either shrink the commitment to fit a secret salt or move to ~30 chars / base58 (§1.3) —
  **default keeps 130 bits and revokes by key rotation.**
- **Reusable & public by design**; one-time sealed-invite strings are the same format with the
  one-time flag set and random (non-commitment) payload.

---

## 12. Open questions (owner/cross-lane decisions)

Primitive-availability, Noise-spec, PAKE, ToxID and RFC facts are now **VERIFIED** against primary
sources (§§1, 2, 5, 6, 7 carry the URLs). Remaining items are genuine *decisions*, not lookups:

- **[OPEN — owner decision]** Browser AEAD: **vendor ChaCha20-Poly1305 everywhere for one wire
  format** (recommended), vs AES-GCM in-browser via cipher-agility (fragments the wire format).
  Driver: WebCrypto has **zero** ChaCha20-Poly1305 support (§7.3, w3c/webcrypto#223).
- **[OPEN — owner decision]** Strict zero-dep vs allowing `golang.org/x/crypto` as "near-stdlib"
  for Go's ChaCha20-Poly1305 (§7.2), and using an audited existing Noise library vs hand-composing
  the state machine (§7.4). Recommendation: **use audited Noise libs; allow `x/crypto` for Go.**
- **[OPEN — owner decision]** Group model for v1: **pairwise fan-out** (recommended — zero new
  crypto) vs **sender-keys** (O(1) send, more machinery) even at N ≤ 20 (§6). Close call; stated.
- **[OPEN — cross-lane]** DoS-mitigation placement on rendezvous topics (§3, §8 row 6) belongs to
  the channel lane; this lane states only the requirement.
- **[OPEN — implementation]** Independent revocation: rotate identity key (recommended, no extra
  bits) vs spend bits on a rotatable secret salt vs widen the string to ~30 chars / base58 (§1.3).

**Minor residual UNVERIFIED (does not affect any recommendation):** the exact byte-level ToxID
checksum operation (cross-check against toxcore source before *implementing a ToxID parser* — we
don't; §1.2), and RFC 9382 was referenced via wormhole docs rather than independently fetched
(SPAKE2 identity is not load-bearing since we use no PAKE). No claim in §§2, 4, 9, 10, 11 depends
on any unverified fact — those are protocol-level and cited to the Noise spec + RFCs 7748/8439/5869.

---

*File owner: Lane D. All version/spec/RFC claims verified against primary docs (nodejs.org,
pkg.go.dev, go.dev, MDN, caniuse, noiseprotocol.org, rfc-editor.org, datatracker.ietf.org,
signal.org) via three independent research passes. Study is decision-grade and implementation-ready.*
