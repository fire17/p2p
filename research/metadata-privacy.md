# p2p — Metadata-Privacy Hardening of the Rendezvous Layer

> **Research Lane: Metadata Privacy.** Owner: fire17. Status: **DECISION-GRADE DESIGN** (design only — no implementation).
> **Date:** 2026-07-12. **Author:** metadata-privacy lane (opus) + 3 sonnet research subagents; spec claims verified against primary sources (BEP44/BEP5, Noise rev-34, rend-spec-v3, Signal sealed-sender), URLs inline.
>
> **Reading contract:** a cryptographically-literate senior engineer reading ONLY this file can
> implement the recommended scheme and defend its exact privacy claim. Every non-obvious claim
> carries a citation. Anything not confirmed from a primary source is marked **UNVERIFIED**.
>
> **Boundary:** this file hardens the **RENDEZVOUS** layer. The security core is unchanged —
> the 26-char identity commitment string + the Noise `IK` + commitment-gate first contact
> (`research/crypto-firstcontact.md`, `src/key.js`, `src/noise.js`) stay exactly as they are.
> This lane makes the **IP metadata** private; it does not touch the MITM-proof authentication.

---

## 0. TL;DR — the recommendation in ten lines

1. **The leak is real and precisely located.** The rendezvous `rid` is already an opaque
   `HKDF` output (unlinkable to non-holders — good). But the **candidate payload beside it is
   plaintext**: the WSS tracker relays a base64-JSON `{candidates:[{ip,port}…]}` blob inside the
   offer SDP (`src/rendezvous/tracker.js` `packSdp`), and the DHT `announce_peer` **stores the
   announcer's raw ip:port and hands it to any `get_peers`** (`src/rendezvous/dht.js`). So today
   anyone who can compute the `rid` (any S-holder) — or any DHT/tracker operator watching that
   infohash — reads the IP in the clear. **The hash is hidden; the IP is not.**
2. **The fix is a per-invite secret `K_inv`**, shared *alongside* the identity key, that (a)
   derives the `rid`, (b) derives an AEAD key that **encrypts the candidate blob**, and (c) mixes
   into the Noise handshake as a **PSK**. One 32-byte secret, three domain-separated jobs.
3. **IP is never plaintext on any public channel.** Candidates are sealed under
   `k_ip = HKDF(K_inv,"ip")` before they touch a tracker or the DHT. Infra and passive observers
   see an opaque `rid` + opaque ciphertext + (unavoidably) your *connection* source IP — never
   your advertised candidate set.
4. **Only the one invited party can decrypt** — because `K_inv` is handed to exactly one person,
   not baked into the reusable public string. A *different* contact who holds your long-term key
   cannot read *this* invite's IP. This is the property `S`-alone cannot give.
5. **The one-time key REVIVES BEP44 on the DHT.** `D7` rejected BEP44 because a commitment-only
   `S` can't yield the 32-byte signing pubkey a reader needs for `target=SHA1(pubkey‖salt)`. With
   `K_inv` **both parties derive the same BEP44 keypair from `K_inv`** → both compute the target →
   reader fetches an **encrypted** value, never `announce_peer`'s plaintext ip:port. D7's objection
   was specific to reusable `S`; it does not apply to a per-invite secret.
6. **The same encrypted blob rides the tracker** (browser-reachable, no DHT) — so the scheme works
   for **both** the TUI (UDP+DHT+trackers) and the browser client (WebRTC+trackers only).
7. **"Decrypt exactly once" is cryptographically impossible for a stored blob** (see §7,
   ESCALATION). What is achievable and recommended: confidentiality to *only the invitee*
   (cryptographic) + **single-use by burn** (operational: stop-republish-after-connect, short TTL,
   epoch rotation, `K_inv` retire) → forward-secret metadata, no lingering route.
8. **PSK mixing strengthens, not just hides.** `IKpsk2` with `psk=HKDF(K_inv,"psk")` makes the
   handshake fail for anyone without `K_inv` **and** upgrades the initiator direction from TOFU to
   cryptographic auth for invite mode — the one-time key does double duty (this is the owner's
   "resign themselves so a true secure connection is kept through all passes," done properly).
9. **Fingerprint-resistant.** `rid`/target are random 20 bytes (blend into BitTorrent); sealed
   blobs are high-entropy (blend into any BEP44 app / WebTorrent SDP). Pad to a fixed length and
   match trystero announce cadence so size/timing don't distinguish a p2p user.
10. **Phased:** **v1** encrypted-payload + one-time `K_inv` (trackers everywhere; encrypted BEP44
    on DHT for TUI) → **v2** burn/rotate (forward-secret metadata) → **v3** onion / IP-hidden-from-
    peer (Tor v3, whose address *is* a derived key). Honest residual at every phase in §8.

---

## 1. The threat model (the owner's spec) and where each point lands

| # | Owner's requirement | Verdict | Where addressed |
|---|---|---|---|
| 1 | Today IP:port is essentially in the clear (announce_peer stores raw ip:port; tracker offer carries candidates; "all channels see an opaque hash + an IP") | **Confirmed — exact leak located** | §2 |
| 2 | IPs must be HIDDEN (encrypted) until decrypted — never plaintext on any public channel | **Achieved** (AEAD-sealed candidate blob) | §3, §4 |
| 3 | Encrypted IP decryptable ONLY ONCE, by ONE party | **Split:** only-one-party = cryptographic ✓; exactly-once = operational burn, not crypto (impossible for a stored blob) | §4, §7 (ESCALATION) |
| 4 | Fingerprint resistance — sniffers can't recognize "this = a p2p user" or extract IPs, even seeing *someone* attempts p2p | **Achieved for content**; residual "an encrypted announce exists" is unavoidable | §6, §8 |
| 5 | Owner's primitive: share pubkey + a ONE-TIME KEY the other party uses to decrypt the IP (and keep a true secure connection through all passes) | **Adopted + refined** = per-invite `K_inv` → rid + AEAD + Noise PSK | §3, §4, §5 |
| 6 | Future: fast-changing virtual IPs; upgrade channel after contact; single-connection-then-route-gone-no-trail; hide IP even from the connecting PEER (onion) | **Phased path designed** (v2 burn/rotate, v3 onion) | §7, §9 |

**One structural fact governs everything (from `crypto-firstcontact.md` §1 / `rendezvous.md` §1):**
*no free public channel offers read-side access control.* Discovery works because anyone who knows
the `rid` can look it up. Therefore **all metadata secrecy must live in the payload and the
derivation, never in the channel.** We already hide the *lookup key* (`rid` is HKDF-derived). This
lane closes the remaining gap: **hide the *payload* (the IP) too.**

---

## 2. What leaks today — exact, code-level

The current derivation is correct and already private for the *lookup key*:

```
rid_ch = HKDF-SHA256(ikm = canonical(S), salt = "p2p-rv-<ch>-v1", info = epoch, L)   // src/key.js deriveRid
```

`rid` is a pseudorandom 20 bytes; a non-holder of `S` cannot compute it, cannot enumerate, cannot
link (`crypto-firstcontact.md` §3). **That half is done.** The leak is the *value stored under it*:

- **WSS tracker (`src/rendezvous/tracker.js`).** `announce()` builds
  `blob = { v:1, ts, candidates:[…] }` and `packSdp()` base64-encodes it into an `a=p2p-blob:` SDP
  line, relayed by the tracker. **The candidate ip:ports are plaintext** — the tracker operator, and
  any peer that announces under the same infohash, reads them directly. (Works browser + TUI.)
- **DHT (`src/rendezvous/dht.js`).** `announce_peer` publishes the announcer's **source ip:port**
  under the infohash; `get_peers` returns compact `values` = raw 6-byte `ip:port` entries in the
  clear (BEP5, https://www.bittorrent.org/beps/bep_0005.html). Anyone doing `get_peers(rid)` gets
  the IP. Worse than the tracker: the IP is *published and queryable by the whole DHT*, and DHT
  crawlers ([bitmagnet.io](https://bitmagnet.io/), [Wolchok/Halderman WOOT'10](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Wolchok.pdf)) already harvest exactly this.
- **mDNS (`src/rendezvous/mdns.js`).** LAN-only broadcast; the TXT carries candidates on the local
  segment. Out of scope for the *internet* metadata threat (LAN exposure is inherent and low-value
  to a remote adversary), but the same encrypted-blob treatment applies for defense-in-depth.

**So the owner's point 1 is exactly right.** Every public channel currently pairs the opaque `rid`
with a **plaintext IP**. The rest of this file removes the plaintext IP.

**One residual that no payload encryption can remove — state it up front:** whenever you *talk to*
public infra (send a UDP packet to a DHT node, open a WSS to a tracker) **from your real IP**, that
node sees your connection source IP at the transport layer. Encrypting the *payload* stops the IP
being *published/relayed as advertised content*; it does not stop the one node you contacted from
seeing the packet came from you. Only an anonymity overlay (Tor, §9 v3) removes that. This is the
same residual `rendezvous.md` §1 flags ("source-IP to the nodes you query"). Honest, and it is the
gap v3 closes.

---

## 3. The primitive: per-invite secret `K_inv` (the owner's one-time key, made precise)

### 3.1 Why `S` alone cannot do this

`S` = `version ‖ commitment(edPub, xPub) ‖ checksum` is a **public, copyable commitment to a public
key** (`crypto-firstcontact.md` §2.1 Regime A). It is deliberately held by *many* people. Any key
derived from `S` alone — including an AEAD key `HKDF(S,"ip")` — is therefore readable by **every**
S-holder. That would satisfy "not plaintext to a *non*-holder," but it fails the owner's sharper
requirements:

- **(5c) a different contact holding your long-term key must not read THIS invite's IP** — fails,
  all S-holders share the key.
- **(3) decryptable by ONE party** — fails, N holders.
- **forward secrecy / unlinkability across invites** — fails, one static key forever.

The resolution the owner intuited is correct: **introduce a fresh secret per invite**, independent
of the long-term identity. This is `crypto-firstcontact.md` §4.3's "sealed invite" (`S_invite`),
now promoted from an optional mode to the **metadata-privacy default**.

### 3.2 `K_inv` and its three domain-separated derivations

Generate, per invite, a fresh random secret `K_inv` — **default 130 bits** (a 26-char base32 token,
reusing `src/key.js` machinery, symmetric with `S`; 128-bit/16-byte and 256-bit/strict variants in
§5 and §12). It is handed to exactly one person, out-of-band, alongside the identity key. From it, three domain-separated keys
(HKDF-SHA256, RFC 5869 — same primitive `src/key.js` already uses):

```
rid_inv_ch = HKDF(ikm=K_inv, salt="p2p-rvk-<ch>-v1", info=epoch, L=ridLen)   // the rendezvous id
k_ip       = HKDF(ikm=K_inv, salt="p2p-ip-v1",       info="",    L=32)       // AEAD key for candidates
psk        = HKDF(ikm=K_inv, salt="p2p-psk-v1",      info="",    L=32)       // Noise PSK (§5)
bep_seed   = HKDF(ikm=K_inv, salt="p2p-bep44-v1",    info="",    L=32)       // Ed25519 seed for BEP44 (TUI/DHT, §4.2)
```

Domain separation (distinct `salt`) guarantees the same `K_inv` never produces the same bytes for
two purposes (`crypto-firstcontact.md` §3.5). Note the **new `salt` namespace** `p2p-rvk-…`
(keyed-invite) — distinct from the existing `p2p-rv-…` (S-derived) so invite-mode rids never
collide or link with the public-mode rids.

**The result of each derivation:**

- **(a) Only the K_inv holder computes the rid** → only they can even *find* where you published.
  A passive observer without `K_inv` cannot compute `rid_inv` → cannot locate the record at all
  (strictly stronger than public-`S` mode, where any S-holder finds it).
- **(b) Only the K_inv holder decrypts the IP** → `k_ip` seals the candidate blob (§4).
- **(c) A different contact holding your long-term key can't read this invite** → they don't have
  *this* `K_inv`.
- **(d) `K_inv` is single-use → burn after connect → forward-secret, unlinkable across invites**
  (§7).

### 3.3 How `K_inv` rides with the 26-char key (share-string / UX)

The security core is unchanged: `S` (the 26-char commitment) still authenticates the owner via the
`IK` gate. `K_inv` is **appended**, not merged, so the MITM-proof property is untouched:

```
Invite string  =  S "-" base32(K_inv)
                  └26 chars┘ └26 chars┘        e.g.  9F3K…Wqueue  -  7H52…9QX2
                  identity      one-time rendezvous secret
```

- **UX stays "copy one string."** It is longer (two base32 groups joined by `-`), but a single
  copy-paste unit, like a longer wormhole code. A QR / deep-link (`p2p://KEY-INV`) hides the length
  entirely, matching the existing `/init/KEY` deep-link the SPA already ships.
- **Reusable mode still exists.** Share bare `S` (no `-INV`) → today's behavior (plaintext
  candidates, reusable by many). The client detects the `-INV` suffix and switches to private
  invite mode. **Recommend invite mode as the private default** in the UI ("generate a private
  one-time invite" vs "share my reusable key").
- **The `version/flags` field already reserved for this.** `crypto-firstcontact.md` §1.3 and
  `DIVERGENCES.md` reserve a flag bit ("one-time invite") in the 5-bit version/flags field. Set it
  in `S`'s flags so a parser knows an `-INV` tail is expected before it even sees the `-`.
- **Checksum:** `K_inv`'s base32 token carries its own checksum (reuse `src/key.js` checksum
  machinery) so a truncated/typo'd invite fails fast, before any network work.

**No change to `S`, `encodeKey`, `decodeKey`, the commitment gate, or the Noise `IK` bytes.** The
invite tail is a pure *rendezvous-layer* addition.

---

## 4. Encrypted rendezvous payload — the sealed candidate blob

### 4.1 The seal (channel-agnostic, works over trackers AND BEP44)

Replace the plaintext candidate blob with an AEAD ciphertext:

```
plaintext  P   = canonical-encode({ candidates:[{proto,ip,port,kind}…], ts })   // MessagePack/JSON, PADDED to a fixed length (§6)
nonce      N   = 24 random bytes  (XChaCha20) or 12 (ChaCha20-Poly1305/AES-GCM)
sealed     C   = nonce ‖ AEAD_seal(key=k_ip, nonce=N, ad = rid_inv ‖ epoch, plaintext=P)
```

- **AEAD:** **ChaCha20-Poly1305** (RFC 8439) — already the project's cipher, already vendored for
  the browser (`research/browser-client.md` §3.4). Nonce is random per publish (fresh each
  re-announce). *Browser-native alternative:* AES-256-GCM is fine **for the blob only** (it is not
  the Noise wire, so it does not fork the Noise suite the way §browser-client rejects for the
  handshake) — but defaulting to ChaCha20-Poly1305 keeps one primitive. **XChaCha20-Poly1305**
  (24-byte nonce) is the safest choice if you want random nonces without a counter — note it is not
  in RFC 8439 base and would need the extended-nonce construction (libsodium/noble); **UNVERIFIED**
  whether the vendored browser impl exposes XChaCha — confirm, else use 12-byte-nonce
  ChaCha20-Poly1305 with a random nonce (collision risk negligible at invite-scale publish counts).
- **Associated data** binds the ciphertext to `rid_inv ‖ epoch` → a blob captured under one rid/epoch
  cannot be replayed under another (integrity + anti-cross-context replay).
- **Authenticity:** the AEAD tag means only a `k_ip` holder could have produced a blob that decrypts
  — a squatter without `K_inv` cannot forge a candidate record readers will accept. (On BEP44 this
  is *belt and suspenders* with the ed25519 signature; on trackers the AEAD tag is the only
  integrity check, and it is sufficient because `k_ip` is secret to the two parties.)

The blob is now **indistinguishable from random** to anyone without `k_ip`. IP requirement (owner's
point 2) met on every channel.

### 4.2 On the DHT — switch invite mode from `announce_peer` to encrypted **BEP44** (TUI only)

This is the crux of revisiting `D7`.

**Why `announce_peer` is unfixable for privacy.** `announce_peer` stores *your source ip:port* and
`get_peers` publishes it (§2). There is no payload to encrypt — the leaked datum **is** the
transport source address, published and queryable. You cannot hide an IP that the protocol's whole
job is to publish.

**BEP44 stores an arbitrary value instead.** BEP44 (https://www.bittorrent.org/beps/bep_0044.html)
lets you `put` a value `v` under a `target`, fetched by `get(target)`:

- **Mutable item:** `target = SHA1(public_key ‖ salt)` (spec: *"the target field MUST be the SHA-1
  hash of this key concatenated with the salt"* — order pubkey-then-salt confirmed), salt optional
  and *"MUST NOT be longer than 64 bytes"*, signed with Ed25519 over the bencoded dict
  `{salt (if present), seq, v}`, monotonic `seq`. Readers `get(target)` and verify the signature.
- `v` may be *"any bencoded type"* — a **bencoded byte-string** carries our sealed `C` (§4.1) with no
  structural parsing, i.e. functionally an opaque ciphertext container. Size: storing nodes *MAY*
  reject a `put` whose bencoded `v` exceeds **1000 bytes** (a SHOULD-honor soft cap) → pad/keep the
  sealed blob well under 1000 B; a few candidates fit easily.

**The one-time key makes BEP44 usable where `D7` said it wasn't.** D7's blocker: a reader needs the
32-byte signing pubkey to compute `target=SHA1(pubkey‖salt)`, and commitment-only `S` doesn't carry
it; deriving the keypair from `S` makes the write key public-to-all-holders (squat). **With `K_inv`:**

```
(bep_sk, bep_pk) = Ed25519_from_seed( bep_seed = HKDF(K_inv,"p2p-bep44-v1") )
salt             = HKDF(K_inv,"p2p-bep44-salt-v1", info=epoch, L≤64)      // optional, rotates target per epoch
target           = SHA1( bep_pk ‖ salt )
publisher put:   v = C (sealed candidates),  signed with bep_sk,  seq = monotonic
invitee  get:    derives the SAME bep_pk+salt from K_inv → target → get(target) → verify sig → AEAD-open C with k_ip
```

Both parties derive the identical BEP44 keypair *from the shared `K_inv`*. The "write key is public
to holders → squat" objection now means "public to the **one** invitee" — who has no incentive to
squat their own invite. BEP44's `seq`+signature give write-authenticity; the AEAD gives
confidentiality. **D7's plain-announce decision stands for reusable-`S` mode; invite mode upgrades
to encrypted BEP44.** (Cost: the BEP44 put/get + Ed25519-sign path — `rendezvous.md` §11 budgets
~100–150 LOC on top of the existing KRPC client, and `src/key.js` already has Ed25519.)

> **Design note — keep both DHT paths.** Reusable-`S` mode keeps today's `announce_peer` (it leaks
> IP, documented). Invite mode uses encrypted BEP44. A node running both just derives the right
> primitive from whether an `-INV` tail is present.

### 4.3 On trackers — encrypt inside the SDP (browser + TUI)

Minimal change to `src/rendezvous/tracker.js`: `packSdp(blob)` currently base64s a **plaintext**
JSON blob. Instead it base64s the **sealed `C`**. `unpackSdp` AEAD-opens with `k_ip` (derived by the
receiver from `K_inv`) instead of `JSON.parse`. The tracker still relays an opaque `a=p2p-blob:` line
of the same shape → **zero protocol change to the tracker, no wire-format tell.** The matchmaker
mechanics (persistent conns, offer retention ~120 s, answer-back) are untouched.

This is the channel that **works in the browser** (no DHT). So the sealed-blob-over-trackers path is
the **interop-safe baseline** that covers every client; encrypted BEP44 is the TUI's additional
ownerless rung.

### 4.4 The `rid` in invite mode

In invite mode the rid is derived from `K_inv`, not `S`:
`rid_inv_ch = HKDF(K_inv, "p2p-rvk-<ch>-v1", epoch, ridLen)`. Consequence beyond confidentiality:
**a non-holder of `K_inv` cannot even locate the record** (they can't compute the rid), whereas in
public-`S` mode any S-holder can. So invite mode hides *both* the location and the content — a
strictly larger privacy win than "encrypt the payload" alone.

---

## 5. Composition with Noise `IK` — PSK mixing (`IKpsk2`)

The owner's "resign themselves so a true secure connection is kept through all passes" is, precisely,
**mixing `K_inv` into the handshake as a PSK** so it strengthens the connection rather than only
hiding the IP.

- **Pattern:** `Noise_IKpsk2_25519_ChaChaPoly_SHA256`. IK is `→ e, es, s, ss` / `← e, ee, se`;
  the `psk2` suffix appends a `psk` token to the **end of message 2** — spec §9.4 verbatim: *"The
  modifiers psk1, psk2, etc., place a `"psk"` token at the end of the first, second, etc., handshake
  message,"* giving `IKpsk2 = … / ← e, ee, se, psk` (Noise rev-34, https://noiseprotocol.org/noise.html).
  `MixKeyAndHash(psk)` (§5.2 / §9.1: *"mix the PSK into both the encryption keys and the h value"*)
  folds the psk into **both** the chaining key `ck` (all transport keys depend on it) **and** the
  transcript hash `h` (any tamper detected) → wrong/absent psk ⇒ different `ck` ⇒ the next AEAD tag
  fails ⇒ handshake aborts. §9.3's rule *"a party may not send any encrypted data after it processes
  a `"psk"` token unless it has previously sent an ephemeral"* is satisfied — both ephemerals precede
  the psk in msg2.
- **Additive safety is spec-explicit.** §9.4: *"any of these PSK modifiers can be safely applied to
  any previously named pattern"* — so `IKpsk2` preserves IK's existing `es`/`ss`/`se` authentication
  and forward secrecy and only *adds* the psk gate; it cannot weaken the base pattern when §9.3 is
  honored (which it is).
- **What it buys, additively (strictly ≥ current IK):**
  1. **Handshake fails without `K_inv`.** Even if the cheap commitment gate (`src/node.js` HELLO
     gate, D4 — explicitly "not auth") were bypassed, an attacker without `K_inv` derives a different
     `ck`/`h` → the AEAD verification of the first transport message fails → connection refused.
  2. **Initiator direction upgrades from TOFU to cryptographic.** The single-string case leaves the
     *initiator* direction TOFU (`crypto-firstcontact.md` §4.2, §10.5). In invite mode, only the one
     invitee holds `K_inv`; a successful `IKpsk2` therefore proves *the initiator is that invitee* —
     closing the one honest gap, with no second string exchanged. This is exactly the owner's "true
     secure connection kept through all passes."
- **Entropy — a DOCUMENTED DEVIATION, not compliance (Noise §14).** The spec states a hard MUST:
  *"Pre-shared symmetric keys must be secret values with 256 bits of entropy,"* with the §15.1
  rationale that the fixed length is *"to deter users from mistakenly using low-entropy passwords as
  pre-shared keys."* Our `psk = HKDF(K_inv)` is a 32-byte value (length-compliant) but HKDF cannot
  manufacture entropy beyond its input, so a 128-bit `K_inv` yields a psk with **~128 bits of
  entropy — length-compliant, entropy NON-compliant with §14's MUST.** State this as a deviation;
  do not claim §14 compliance. 128 bits is still infeasible to brute-force offline for symmetric
  crypto (this is a rendezvous-hardening PSK, not the sole auth — IK's pinned-static DH auth stands
  underneath it), and no quantified security loss for a sub-256-bit psk exists in the spec text
  (UNVERIFIED that it weakens the composed protocol beyond the conformance point). **Clean fix if
  strict conformance is wanted: make `K_inv` 256-bit** (a 52-char base32 tail, or a raw/QR token) —
  then the psk is fully §14-compliant at the cost of a longer share string. **Default recommendation:
  128-bit `K_inv` with this deviation documented; offer 256-bit as the "strict" option.**
  (Same caveat `crypto-firstcontact.md` §2.3 records for an S-derived psk.)
- **Prologue binding (optional hardening).** Bind rendezvous context into the Noise `prologue`
  (`src/noise.js` already mixes `prologue` via MixHash at handshake start): e.g.
  `prologue = "p2p-inv-v1" ‖ rid_inv ‖ epoch`. It's authenticated (tamper-detected) but not secret —
  it cryptographically ties the handshake to the exact rendezvous it came in on, so a blob relayed
  under one rid can't be spliced into a handshake claiming another.
- **Interop:** invite mode = `IKpsk2`; reusable mode = plain `IK` (today). The 5-bit version/flags
  field selects which (D2 cipher/pattern agility). TUI↔TUI, TUI↔browser, browser↔browser all agree
  because the pattern is chosen by the invite flag, not the transport.

---

## 6. Fingerprint resistance — does anything say "p2p user"?

The owner's point 4: even seeing *someone attempts a p2p connection*, a sniffer must not extract IPs
or recognize the pattern. Channel by channel:

| Surface | What an observer sees | Distinguisher? |
|---|---|---|
| **rid / infohash / BEP44 target** | 20 random-looking bytes | **No.** HKDF/SHA1 output; identical shape to any BitTorrent infohash or BEP44 target. Blends into the largest P2P network on earth. |
| **Sealed candidate blob** | high-entropy ciphertext (`nonce ‖ AEAD`) | **No content leak.** Looks like any encrypted BEP44 value / opaque SDP payload. |
| **Tracker SDP** | `a=p2p-blob:<base64>` in an otherwise-normal WebTorrent offer | Shape matches WebTorrent. The literal token name `p2p-blob` **is** a tell → **rename to a neutral/rotating attribute** (e.g. reuse a standard `a=`-line or a per-epoch pseudorandom key). *Recommend fixing this in v1.* |
| **Announce cadence / timing** | periodic announces | Match trystero defaults (10 s active / 2 min idle, `rendezvous.md` §3) so timing is WebTorrent-shaped, not distinctive. |
| **Blob length** | ciphertext size | **Pad to a fixed length** (e.g. always 256 B of plaintext before sealing) so the number of candidates / presence of IPv6 / LAN hints doesn't leak from size. |
| **BEP44 vs plain torrents** | mutable-item traffic | BEP44 mutable items are *less common* than plain torrents, so a very sophisticated DHT crawler could bucket "this target is a mutable-item app." It **cannot** tell p2p from any other BEP44 dApp, and **cannot** extract an IP. Honest residual, noted in §8. |

**Two concrete v1 fixes fall out of this table:** (1) drop the literal `p2p-blob` SDP attribute name
for a neutral/rotating one; (2) pad the sealed plaintext to a constant length. Both are trivial and
belong in the v1 encrypted-payload change.

**What stays visible (unavoidable, §2 residual):** the fact that *an* opaque encrypted announce
exists under *some* rid, and your *connection* source IP to the one tracker/DHT node you contacted.
Removing the latter requires §9 (onion). Content and identity stay hidden throughout.

---

## 7. Single-use / burn — and the honest limit of "decrypt once"

### 7.1 ESCALATION — "decryptable only once" is cryptographically impossible for a stored blob

**Precise statement:** an AEAD ciphertext sitting on a tracker or in the DHT is a static byte string.
Anyone holding `k_ip` can decrypt it **arbitrarily many times**; a passive blob has no way to
"consume" itself on first read. There is **no cryptographic mechanism** that makes a *stored,
independently-fetchable* value decryptable exactly once without an online, stateful party enforcing
it (an oblivious-transfer / one-time-retrieval server) — which contradicts the project's
no-server-of-ours invariant. **So "decrypt only once" as literally stated is not achievable at the
crypto layer.**

**Closest achievable (recommended), decomposed into what each half really guarantees:**

1. **Confidentiality to exactly one party — cryptographic, fully achieved.** Because `K_inv` is
   handed to a single invitee and to no one else, only that invitee ever holds `k_ip`. A passive
   observer, the infra, and every other S-holder can *never* decrypt — not once, not ever. This is
   the strong, real half of the owner's requirement.
2. **Single-use — operational, by burn.** Enforce "used once then gone" by convention:
   - **Stop-republish-after-first-connect.** The publisher stops re-`put`/re-announcing the record
     the moment the Noise handshake completes. On the DHT the item then expires (~2 h TTL,
     `rendezvous.md` §2); on the tracker the offer ages out (~120 s). The route disappears.
   - **Short TTL + epoch rotation.** `rid_inv` rotates per epoch (§3.2). Tighten the epoch for invite
     mode (minutes, not the UTC-day the public mode uses) so the window a blob is even *locatable* is
     small.
   - **Retire `K_inv` after connect.** Once contact succeeds, both sides swap+pin long-term keys over
     the now-authenticated channel (`crypto-firstcontact.md` §4.3) and **destroy `K_inv`**. Future
     presence/roaming uses the established identity keys (D7's P2 re-entry: authenticated BEP44 with
     real keys among established friends).

### 7.2 The residual, stated exactly

**An observer who captured the sealed blob *before* burn, AND who *also* obtains `K_inv`, can decrypt
it.** But `K_inv` is given only to the invitee out-of-band → a passive capturer never has `K_inv` →
the captured blob is useless to them. The only way the residual bites is if the **invitee themselves**
is the adversary (a rogue holder) — and a rogue *invitee* learning the IP they were invited to
connect to is inherent to any rendezvous (you can't invite someone to connect and hide the connection
point from them; §9 onion hides your *real* IP even from them, but not the fact of a route).

**Forward secrecy of metadata (owner's point 6, "even if a record is later decrypted, the route is
gone").** Because `K_inv` is per-invite and destroyed after connect, a *later* compromise of your
long-term identity key reveals **nothing** about past invite routes (they were sealed under an
independent, discarded `K_inv`). And once burned, the record has expired from the infra — there is no
live route to replay. So a sophisticated actor who compromises you tomorrow cannot reconstruct where
you connected from yesterday. This is the "burn-after-connect, no trail" property, achieved.

**Summary of the honest answer to point 3:** *only-one-party* = **yes, cryptographic**; *exactly-once*
= **no (impossible for a stored blob); closest = single-use-by-burn + forward-secret metadata**, which
delivers the *intent* (no lingering, replayable, later-decryptable route) even though it can't make a
byte string self-destruct on read.

---

## 8. Threat table

Adversary capabilities against the **v1 (encrypted-payload + `K_inv`) invite mode** unless a row says
otherwise. "IP" = your advertised candidate ip:ports.

| # | Adversary / event | Sees | Can they get the IP? | Can they impersonate / MITM? | Residual |
|---|---|---|---|---|---|
| 1 | **Passive DHT observer / crawler** (no `K_inv`) | opaque BEP44 target + high-entropy `v` | **No** — can't even compute `rid_inv` without `K_inv`; `v` is ciphertext | No (no key) | Learns a mutable-item target exists; no IP, no identity, no linkage |
| 2 | **Malicious tracker** (relays the SDP) | opaque infohash + ciphertext blob + **your WSS source IP** | **Advertised candidates: No.** But sees the **IP you connect to it *from*** (transport source) | No (Noise+PSK; tracker is a dumb relay) | Your *connection* IP to the tracker leaks (unavoidable pre-onion); advertised candidate set stays sealed |
| 3 | **Key-holder-but-not-this-invite** (has `S`, not this `K_inv`) | can't compute `rid_inv`; can't derive `k_ip` | **No** | No — `IKpsk2` fails without `K_inv`; commitment binds owner | Can still reach you via *public* `S` mode if you also run it; invite record invisible to them |
| 4 | **Global passive adversary** (sees all channels) | all opaque rids + all ciphertext + traffic timing | **No** (content) | No | **Traffic analysis:** can see *that* encrypted announces happen and correlate timing/volume; padding+cadence (§6) blunt it; only Tor (§9) hides the endpoints |
| 5 | **Post-hoc blob capture** (records ciphertext, tries later) | stored ciphertext | **No, unless they also get `K_inv`** | No | If `K_inv` is *later* leaked AND the blob was captured pre-burn → decryptable. `K_inv` retire + FS (§7) bound this; long-term-key compromise reveals nothing |
| 6 | **Rogue invitee** (the one you invited) | everything you sent them | **Yes — by design** (you invited them to connect) | No (can't impersonate *you* to a third party — commitment binds your key) | Inherent to rendezvous; §9 onion hides your *real* IP even from them, not the fact of a route |
| 7 | **Active MITM without `K_inv` or your private key** | full read/drop/inject on rendezvous | **No** | **No** — Noise `IKpsk2`: needs the pinned static private key *and* `K_inv`; impersonation ≤ `max(2^-110, 2^-128)` and additionally gated by 128-bit `K_inv` | Unchanged from the existing IK claim, strengthened by PSK |

**The one row every honest reader must keep:** rows 2 & 6. The tracker/DHT node you *contact* sees
your connection source IP, and the peer you *connect to* learns your IP. Payload encryption removes
the *advertised* IP from every public channel; it does **not** remove your IP from the party you
directly speak to. That is the boundary between v1/v2 (metadata privacy) and v3 (IP-hidden-from-peer).

---

## 9. Phased plan

### v1 — Encrypted payload + one-time invite keys *(this design; build target)*

- Per-invite `K_inv`; share string `S-INV`; `rid_inv`/`k_ip`/`psk`/`bep_seed` derivations (§3).
- **Sealed candidate blob over trackers** (browser + TUI) — the interop-safe baseline (§4.1, §4.3).
- **Encrypted BEP44 over the DHT** for the TUI (§4.2) — revives D7 under the one-time key.
- **`Noise_IKpsk2`** in invite mode (§5).
- Fingerprint fixes: neutral SDP attribute name + fixed-length padding + trystero cadence (§6).
- **Earns:** IP never plaintext on any public channel; decryptable only by the one invitee;
  location itself hidden from non-holders; initiator-direction auth upgraded. Reusable `S` mode stays
  available (documented as the less-private option).
- **Est. cost:** small. AEAD seal/open (both primitives already in the tree), the `-INV`
  parse/derive glue, `packSdp`/`unpackSdp` swap, one Noise pattern variant, BEP44 put/get (~100–150
  LOC, `rendezvous.md` §11). No new dependency.

### v2 — Burn / rotate *(forward-secret metadata)*

- Stop-republish-after-first-connect; tighten invite epoch (minutes); retire `K_inv` post-connect;
  swap+pin long-term keys over the authenticated channel (§7).
- **Fast-changing virtual IPs (owner's point 6):** because candidates are re-sealed and re-announced
  on `netchange` (`race.js` already fires this) and the epoch rotates, a VPN-style rotating IP is
  naturally accommodated — each announce seals the *current* candidate set under the current rid; old
  ones expire with no trail.
- **Channel upgrade after contact:** once the Noise session exists, migrate presence/roaming to
  authenticated BEP44 with the real identity keys (D7 P2 re-entry) — friends no longer need `K_inv`.
- **Earns:** the "single connection then the route is gone, no trail, later-decryption reveals a dead
  route" property (§7.2).

### v3 — Onion / IP-hidden-from-peer *(the hard residual, rows 2 & 6)*

- **Tor v3 onion service as rendezvous + transport.** The v3 onion address **is** an Ed25519 public
  key: `onion_address = base32(PUBKEY ‖ CHECKSUM ‖ VERSION) + ".onion"`, `CHECKSUM =
  H(".onion checksum" ‖ PUBKEY ‖ VERSION)[:2]`, VERSION=0x03 (rend-spec-v3 §6,
  https://spec.torproject.org/rend-spec-v3). Derive the onion keypair from `K_inv`
  (`onion_seed = HKDF(K_inv,"p2p-onion-v1")`) → **the onion address is the derived rendezvous ID**
  (deterministic, no registration/CA), and connecting to it hides the server's real IP *from the
  client itself* — client and service each build 3-hop circuits to a rendezvous point neither
  controls end-to-end, so *"IP addresses are not even meaningful"* to the connection (Tor community
  overview) — closing rows 2 **and** 6. HSDir descriptors self-refresh while online and are signed
  with **blinded per-time-period keys** derivable only from the service credential
  (`credential=H("credential"‖identity-pubkey)`), so a passive HSDir operator *"cannot derive the
  blinded signing key lacking that credential"* → enumeration-resistant. Fuses dead-drop + transport
  into one mechanism on free volunteer infra. Prior art for "hide the metadata layer while infra
  still sees delivery+timing" is Signal **sealed sender** (https://signal.org/blog/sealed-sender/),
  which hides the sender from the server but, by Signal's own admission, leaves *"traffic correlation
  via timing attacks and IP addresses"* as open problems — the same residual boundary this file draws.
- **Costs (honest, from `rendezvous.md` §7b):** heavy dependency (bundle `tor`/`arti`), 3–10 s
  circuit build, and Tor is blocked/throttled in some networks (needs obfs4/snowflake pluggable
  transports, https://tb-manual.torproject.org/circumvention/). Gate behind a config flag.
- **Alternatives (one line each):** relay-through-a-mutual-trusted-peer (a friend acts as a TURN-like
  blind relay — the peer sees the relay's IP, not yours; no anonymity network, but no heavy dep);
  I2P (garlic-routed eepsites — comparable anonymity, heavier/Java-centric, smaller network,
  `rendezvous.md` §7c AVOID for this project); Reticulum (mentioned by the owner — a
  delay-tolerant/mesh option, **UNVERIFIED** fit, worth a future look).
- **Earns:** IP hidden even from the connecting peer. This is the *only* phase that removes rows 2 &
  6; v1/v2 explicitly do not claim it.

---

## 10. The recommended scheme — message by message + the exact claim earned

**Setup (out of band).** Alice generates identity `(edPub,xPub,S)` once, and per invite a fresh
`K_inv`. She hands Bob the string `S-base32(K_inv)`.

**Publish (Alice, going online for this invite).**
```
rid_dht    = HKDF(K_inv,"p2p-rvk-dht-v1",   epoch, 20)     // TUI
rid_trk    = HKDF(K_inv,"p2p-rvk-tracker-v1",epoch, 20)     // TUI + browser
k_ip       = HKDF(K_inv,"p2p-ip-v1")
C          = nonce ‖ AEAD_seal(k_ip, nonce, ad=rid‖epoch, PAD(candidates))     // padded, fixed length
DHT (TUI): (bep_sk,bep_pk)=Ed25519(HKDF(K_inv,"p2p-bep44-v1")); put v=C signed@bep_pk‖salt   // encrypted BEP44, NOT announce_peer
Tracker  : announce offers whose SDP carries C in a neutral a=-line                           // sealed, browser-reachable
```
An observer of either channel sees: an opaque rid/target + a high-entropy fixed-length ciphertext.
No IP. No identity. (Alice's *connection* IP to the node is seen by that node — row 2.)

**Discover (Bob).**
```
Bob derives rid_dht/rid_trk + k_ip from K_inv (only he can) → fetches C → AEAD-opens with k_ip → gets candidates
```
Bob is the only party on earth (besides Alice) who can locate *and* open the record.

**Connect (unchanged security core + PSK).**
```
Bob punches to the decrypted candidates → Alice sends HELLO(edPub,xPub) →
Bob GATES it against S's commitment (cheap prefilter, D4) →
Noise IKpsk2 (psk=HKDF(K_inv,"psk"), prologue="p2p-inv-v1"‖rid‖epoch):
  msg1  Bob   -> Alice :  e, es, s, ss   [+ ts/nonce]
  msg2  Alice -> Bob   :  e, ee, se, psk [+ first-ack]        // decrypts ONLY IF Alice holds a_A AND K_inv
  transport: Split() → ChaCha20-Poly1305 keys
Handshake success == first ack == MITM ruled out AND initiator proven to be the invitee.
Burn: stop republishing C; retire K_inv; swap+pin long-term keys over the channel (v2).
```

### The exact privacy claim this earns

> **IP-never-plaintext.** On every *public* rendezvous channel (DHT, trackers, and their operators
> and any passive observer), the candidate ip:ports are transmitted **only** as an AEAD ciphertext
> under `k_ip = HKDF(K_inv,"ip")`. `K_inv` is disclosed out-of-band to exactly one invitee.
> Therefore no infra operator, no passive network observer, and no other holder of the reusable
> identity string `S` can recover the IP — the probability of doing so without `K_inv` is bounded by
> the AEAD's confidentiality (≈ `2^-128` given a 128-bit `K_inv`). In invite mode they additionally
> cannot even **locate** the record, since `rid_inv` is also `HKDF(K_inv,…)`.
>
> **Not-fingerprintable (content + identity).** Every value on the wire — `rid`, BEP44 target,
> sealed blob — is pseudorandom and shape-identical to ordinary BitTorrent/BEP44/WebTorrent traffic;
> with fixed-length padding and WebTorrent-matched cadence, nothing in format, size, or timing marks
> the user as a "p2p user" or leaks the candidate count. A sniffer cannot extract an IP or an
> identity at any point.
>
> **Honest boundary.** Two things remain visible and are **not** claimed hidden in v1/v2: (a) the
> single infra node you *contact* sees your connection source IP at the transport layer, and (b) the
> peer you *connect to* learns your IP. Both are the "you spoke to it from your real IP" residual;
> only **v3 (Tor v3 onion)** removes them. A global passive adversary can still observe *that*
> encrypted rendezvous traffic exists and do timing correlation (padding/cadence blunt, don't
> erase). "Decrypt exactly once" is impossible for a stored blob (§7); we deliver only-one-party
> (cryptographic) + single-use-by-burn + forward-secret metadata (operational) instead.

---

## 11. Does it make sense + fit? (summary judgment)

**Yes, with the escalations above stated honestly.** The scheme:
- **Fits the existing system** — `S`, the commitment gate, and the Noise `IK` bytes are untouched;
  this is a pure rendezvous-layer addition (a share-string tail + a payload seal + a Noise-pattern
  variant selected by a flag bit that `crypto-firstcontact.md`/`DIVERGENCES.md` already reserved).
- **Works for both clients** — the sealed-blob-over-trackers path is browser-reachable (no DHT) and
  is the interop baseline; encrypted BEP44 is the TUI's extra ownerless rung.
- **Reuses primitives already in the tree** — HKDF, Ed25519, ChaCha20-Poly1305 (vendored for the
  browser), the KRPC DHT client. No new dependency for v1/v2; only v3 (Tor) is heavy.
- **Delivers the owner's intent** where the literal requirement is impossible, and says so precisely
  (§7 exactly-once; §8 rows 2/6 IP-to-contacted-party; §9 v3 for the rest).

---

## 12. Open questions / hand-offs

- **XChaCha20 (24-byte nonce) availability** in the vendored browser AEAD — confirm; else use
  12-byte-nonce ChaCha20-Poly1305 with random nonces (fine at invite-scale publish volume). (§4.1)
- **Invite-mode epoch length** — minutes vs the UTC-day used in public mode (§7). Tighter = smaller
  locatable window but more clock-skew tolerance needed; a rendezvous-lane tuning knob.
- **Reticulum** as a v3 alternative — owner mentioned it; fit **UNVERIFIED**, worth a scoped look.
- **DoS in invite mode** — only the one invitee can even find `rid_inv`, so the S-holder dial-DoS
  surface (`crypto-firstcontact.md` §3 DoS note, DESIGN D6) **shrinks to one party** in invite mode —
  a nice side benefit; confirm the race's dial caps still apply unchanged.
- **`K_inv` size** — 128-bit (16 B) vs a 26-char/130-bit base32 token (matches `S`'s UX,
  symmetric-looking `S-INV`) vs **256-bit** (52-char / QR) for strict Noise §14 psk-entropy
  compliance (§5). Recommend the 130-bit token by default (deviation documented); 256-bit as the
  strict option. Note: at 130 bits the psk is still entropy-non-compliant with §14's literal 256 MUST.

---

*End of report. A senior engineer can implement §10's scheme from §3–§6 and defend §10's claim from
§7–§8. Spec citations: BEP44 https://www.bittorrent.org/beps/bep_0044.html · BEP5
https://www.bittorrent.org/beps/bep_0005.html · Noise https://noiseprotocol.org/noise.html · Tor
rend-spec-v3 https://spec.torproject.org/rend-spec-v3 · Signal sealed-sender
https://signal.org/blog/sealed-sender/ · HKDF RFC 5869 · ChaCha20-Poly1305 RFC 8439. UNVERIFIED
items flagged in §4.1, §9, §12.*
