# p2p — v3 Onion Study: Hiding the SOURCE IP from BOTH the Public Surfaces AND the Connecting Peer

> **Research Lane: Onion (v3).** Owner: fire17. Status: **DECISION-GRADE STUDY (design/analysis only — NO `src/` changes; the tree is mid-ship).**
> **Date:** 2026-07-12. **Author:** onion-research lane (opus @ xhigh) + 3 sonnet research subagents; the load-bearing feasibility claim is **EMPIRICALLY WITNESSED against a real `tor` binary** (§3.4), not merely cited.
>
> **Reading contract:** a cryptographically-literate senior engineer reading ONLY this file can decide whether to build v3, holds the exact `K_inv → onion-key` derivation (with a reproducible witness), knows precisely what it costs, and can defend the verdict against the owner's Complexity Adversarial Gate (`surface-hardening.md` §6). Every non-obvious claim carries a primary-source citation or is marked **UNVERIFIED**.
>
> **The residual this lane attacks (and ONLY this):** `metadata-privacy.md` §8 **rows 2 & 6** — *the single infra node you contact sees your connection source IP, and the peer you connect to learns your IP.* `surface-hardening.md` proved cycling+sharding **cannot** touch this (they change *how many* surfaces see your IP, never *whether* the one you touch does). Payload encryption (v1) and burn (v2) also do not touch it. **Onion routing is the only mechanism that removes it.** This file decides whether it is worth it.

---

## 0. TL;DR — verdict in twelve lines

1. **Verdict: WORTH-IT-FLAG-GATED.** Build it as an **optional** `transport: 'onion'` mode that talks to an **already-installed, user-run system `tor` daemon** over its ControlPort+SocksPort (node:net only) — **NOT** a bundled tor binary, **NOT** a (nonexistent) pure-JS Tor. Default OFF. Zero-dep invariant preserved exactly as `werift`/WebRTC is preserved: an optional peer the user supplies, never an npm dependency.
2. **The elegant fit is REAL and WITNESSED.** The Tor v3 onion address *is* an Ed25519 public key. Derive the onion service key from `K_inv` (`onion_seed = HKDF(K_inv,"p2p-onion-v1")`) → **both parties compute the identical `.onion` locally, so the onion address IS the invite rendezvous id — no DHT, no tracker, no lookup at all.** I ran the derivation through real `tor 0.4.9.11`: `ADD_ONION ED25519-V3:<key-from-K_inv>` returned the **exact** 56-char address my pure-`node:crypto` code computed (§3.4). Feasible, deterministic, proven.
3. **The ADD_ONION blob is the 64-byte EXPANDED key, not the 32-byte seed** — the one non-obvious crypto gotcha, resolved empirically (I fed 64 bytes; it worked). `K_inv → HKDF → seed → SHA-512-expand+clamp → base64` is the whole recipe. Reuses `src/invite.js`'s exact `ed25519FromSeed` PKCS8 trick.
4. **Composition with Noise is CLEAN and code-proven.** A tor stream is a TCP stream = the existing `_tcpSocketLike` (2-byte-framed) shape (`src/transport.js`). `Noise_IKpsk2` runs on top **unchanged** — Tor gives IP-hiding + its own layer crypto; Noise gives the commitment-gate MITM proof **independent of Tor's trust** (if every relay colluded, Noise still refuses anyone without `K_inv`). Defense in depth, not redundancy.
5. **Onion mode REPLACES the whole rendezvous+UDP ladder** (DHT/tracker/mDNS/STUN/ICE all gone) — the `.onion` is both the dead-drop and the transport. Smaller moving-part count in onion mode than in the direct path, not larger. Only the **listener** runs the service (`ADD_ONION`); the **dialer** connects via SOCKS to the derived address. Both DERIVE it; one INSTANTIATES it — maps cleanly onto the existing `listen`/`connect` asymmetry (`src/node.js`).
6. **The honest costs (§5):** (a) **latency** — onion circuits are 6 relays (client 3-hop + service 3-hop at a rendezvous point); connect is **seconds**, and the service needs descriptor-publish time before first reachability. (b) **dependency** — `tor` is a large C daemon; there is **no maintained pure-JS Tor** and **Arti has no Node binding**; so the only zero-dep-preserving route is *speak to the user's own tor*. (c) **reliability** — Tor is blocked/throttled in hostile nets → needs obfs4/snowflake bridges (operator config, not our code). (d) **attack surface** — Tor has a real CVE history; the mitigation is the trust-boundary choice in point 1 (talk to a separate-process daemon over a local socket, don't embed it).
7. **CAG result (§7):** passes checks 1 (closes rows 2 & 6 — the ONLY thing that does), 3 (weakest link strictly improved: your IP no longer reaches the peer or any single surface), 5 (degenerate = mode simply unavailable → fall back to direct, never worse), 7 (flag-gated, default-OFF, byte-identical when off). The tension is check 2/8 (attack surface + a simpler option) — **resolved by NOT bundling tor**: the added surface is a local socket to a daemon the user chose to run, and no simpler mechanism closes rows 2 & 6 at all.
8. **Alternatives (§6), steelmanned:** the **lightest thing that meaningfully helps** is **WebRTC forced-relay (`iceTransportPolicy:'relay'`, TURN-only)** — it hides your IP *from the peer* (row 6) at near-zero added complexity in the **browser** client (WebRTC is already there), **but NOT from the TURN operator** (row 2 partially remains) and it depends on a TURN server. Recommended as a **cheap partial win for the browser** *alongside* onion for the TUI. Mutual-peer relay, mixnets (Nym/Loopix), I2P, Reticulum: each analyzed and set aside for a tiny zero-dep JS lib.
9. **This is NOT a MITM-auth change.** The security core (`S`, commitment gate, Noise `IK` bytes) is untouched. Onion is a *transport+rendezvous* swap that adds IP-anonymity beneath the existing crypto. It composes with v1 `K_inv` (same secret) and does not require v1/v2 to change.
10. **Phased minimal viable v3:** **v3.0** — `tor`-daemon detection + `ADD_ONION`-from-`K_inv` listener + SOCKS-to-`.onion` dialer + Noise IKpsk2 over the stream, flag-gated, TUI only. **v3.1** — descriptor client-auth (x25519 from `K_inv`) for defense-in-depth + a browser forced-relay partial mode. **v3.2** — bridge/PT passthrough config for censored nets.
11. **ESCALATION check — cleared.** The `K_inv→onion-key` derivation is **NOT** cryptographically impossible — it is witnessed working against real tor. Tor **CAN** be made optional (system-daemon model). Neither STOP condition fired; proceeding to a recommendation.
12. **Honest residual even with onion:** a **global passive adversary** watching the whole Tor network can still do end-to-end *timing correlation*; Tor does not claim to defeat that, and neither do we. And the two peers still learn they are talking to *each other's onion* (which is the point). Rows 2 & 6 (IP) are closed; traffic-analysis by a global adversary is not — stated, not hidden.

---

## 1. The exact residual, and why nothing before v3 touches it

From `metadata-privacy.md` §8 and `surface-hardening.md` §2, the metadata a rendezvous surface sees today in invite mode:

| Datum | Status after v1 (shipped) + v2 (planned) |
|---|---|
| `rid` / BEP44 target | opaque HKDF/SHA1 output — hidden ✓ |
| sealed candidate blob | 544 B AEAD ciphertext — hidden ✓ |
| **your SOURCE IP at the surface you contact** | **LEAKS (row 2)** — you opened a socket to it from your real IP |
| **your IP as learned by the connecting PEER** | **LEAKS (row 6)** — hole-punching means the peer dials/receives your candidate IPs directly |
| timing/cadence | traffic-analysis handle for a global adversary |

**Why v1/v2/cycling/sharding are all powerless here (the proof, restated):** every prior mechanism operates on the *payload* or on *which channel* carries it. None changes the transport-layer fact that **to speak to a node you send it a packet from your address**, and **to hole-punch to a peer you exchange real IPs**. `surface-hardening.md` §3.4/§4.3 quantified this: cycling → "ZERO effect on the dominant IP residual"; sharding → *increases* IP exposure. The residual is structural to any scheme where you contact infra and peers **directly**. Removing it requires **not contacting them directly** — i.e. routing through an overlay that terminates your IP at an entry relay and the peer's at a rendezvous point. That is exactly what onion routing is.

**The boundary this file draws:** onion closes rows 2 & 6 (IP-from-surface and IP-from-peer). It does **not** close row 4 (global-passive timing correlation) — no low-latency overlay does, Tor included (§5.5).

---

## 2. The mechanism — Tor v3 onion services

### 2.1 Why onion services specifically (not just "use Tor as a proxy")

Two distinct properties are needed and a *client-only* Tor proxy gives only one:

- **Client anonymity (hides YOUR ip from what you contact).** A plain Tor SOCKS proxy already gives this: your traffic exits a Tor exit relay, so a clearnet server sees the exit IP, not yours. Closes row 2 for *outbound* contact.
- **Server-location hiding + no clearnet endpoint at all (hides the LISTENER's IP from the dialer, row 6, AND removes the "connect to an IP" step entirely).** This needs an **onion SERVICE**: the listener publishes a *rendezvous* reachable only through Tor, with **no IP anywhere in the address**. The dialer connects to a name that is a public key; neither side ever learns the other's IP, and neither runs on a knowable clearnet address.

Onion services give both at once **and** hand us the elegant address-is-a-key property (§3). So v3 uses **onion services**, not a plain proxy.

### 2.2 The v3 onion address encoding (cited + independently recomputed)

rend-spec-v3, "Encoding onion addresses" (https://spec.torproject.org/rend-spec-v3/, verbatim):

```
onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
CHECKSUM      = SHA3_256(".onion checksum" | PUBKEY | VERSION)[:2]
VERSION       = one byte, value 0x03
PUBKEY        = the 32-byte ed25519 master identity public key (KP_hs_id)
base32        = RFC 4648 lowercase, no padding  →  56 base32 chars + ".onion"
```

Confirmed exact by WebFetch of the spec page (SHA3-256 not SHA-256; VERSION `\x03`; `KP_hs_id`) **and** by the witness in §3.4 — had I used SHA-256 or the wrong field order, tor's ServiceID would not have matched my locally-computed address byte-for-byte. It did.

### 2.3 Blinded keys → enumeration resistance (cited)

rend-spec-v3 (key-blinding / descriptor sections): the descriptor an HSDir stores is signed with a **blinded** per-time-period key derived from the identity key plus a public period parameter, and the descriptor body is encrypted under a key derived from `credential = H("credential" | KP_hs_id)`. An HSDir holding the descriptor **cannot derive the identity key or the address from it** — it lacks `KP_hs_id`. So a passive HSDir cannot enumerate onion addresses it hosts.

**For us this compounds with secrecy of the address itself:** because our `KP_hs_id` is derived from the secret `K_inv` (known only to the two parties), the address is not merely enumeration-resistant at the HSDir — it is **unguessable to anyone without `K_inv`**. (Exact blinding formula + descriptor two-layer detail: see subagent-A extraction, §9 citations; the enumeration-resistance property is the load-bearing one and is spec-confirmed.)

---

## 3. FEASIBILITY — deriving the onion service key from `K_inv` (the crown finding)

### 3.1 The question, precisely

Can we deterministically derive an Ed25519 onion-service key from `K_inv` such that **both parties compute the same `.onion` address with no coordination**, and feed that key to a real `tor` so it serves that exact address? If yes, the onion address **is** the rendezvous id and the entire lookup layer vanishes in onion mode.

### 3.2 The derivation

```
onion_seed  = HKDF-SHA256(ikm=K_inv, salt="p2p-onion-v1", info="", L=32)     // a new domain-separated job of K_inv
(the ed25519 keypair follows RFC 8032 from onion_seed)
  h         = SHA-512(onion_seed)                     // 64 bytes
  a         = clamp(h[0:32])   (a[0]&=248; a[31]&=127; a[31]|=64)
  RH        = h[32:64]
  KP_hs_id  = a · B            (the 32-byte ed25519 public key = node:crypto's public key from the seed)
  expanded  = a ‖ RH           (the 64-byte "hs_ed25519_secret_key" form)
onion_address = base32(KP_hs_id | SHA3_256(".onion checksum"|KP_hs_id|\x03)[:2] | \x03) + ".onion"
```

- **`onion_seed` is a fifth domain-separated derivation of `K_inv`**, alongside `rid`/`k_ip`/`psk`/`bep_seed` already in `src/invite.js` §3.2. New salt namespace `p2p-onion-v1` — never collides.
- **The public key** is obtained with the identical PKCS8 trick `src/invite.js ed25519FromSeed` already uses (`ED_PKCS8_PREFIX ‖ seed` → node KeyObject → export SPKI → last 32 bytes). No new primitive.
- **The expanded secret** is what `ADD_ONION ED25519-V3` wants (§3.3) — computed with `SHA-512` + clamp, pure `node:crypto`.

### 3.3 The one gotcha: ADD_ONION wants the EXPANDED key, not the seed

Tor's control protocol `ADD_ONION ED25519-V3:<base64>` expects the **64-byte expanded secret key** (`a ‖ RH`, the same bytes tor stores as `hs_ed25519_secret_key`), **not** the 32-byte RFC-8032 seed. This is the classic integration trap (a naive `base64(seed)` yields the wrong address). Tor operates on the expanded key directly because **key blinding multiplies the scalar `a`** per time period — it needs `a` explicitly, which only the expanded form carries.

Confirmed two independent ways:
- **Empirically** (§3.4): I fed tor the 64-byte expanded form; it produced the predicted address. A 32-byte seed blob is a different length.
- **By the design record.** control-spec's `ADD_ONION` grammar only says `KeyBlob = ... String ; serialized private key` (byte length unspecified). Proposal 284 §3.1.3 (https://spec.torproject.org/proposals/284-hsv3-control-port.html): *"With the KeyType == 'ED25519-V3', the 'KeyBlob' should be a base64 encoded ed25519 private key"* — still no length. The resolution is on the tor-dev list (David Goulet, Proposal-284 impl thread, https://archives.seul.org/or/dev/Nov-2017/msg00044.html): *"the approach would be to Base64 the raw bytes of the key (excluding the header) … `tail -c+33 hs_ed25519_secret_key | base64 -w 0`"*. `hs_ed25519_secret_key` = a 32-byte header (`== ed25519v1-secret: type0 ==`) + the **64-byte expanded key**; `tail -c+33` strips the header → the 64 expanded bytes. So the blob is unambiguously the expanded key. (Direct grep of `control_cmd.c`/stem was blocked by a gitlab bot-403 — **UNVERIFIED at the C-source level**, but the dev-list is the actual design decision and the empirical witness settles it.)

### 3.4 THE WITNESS — proven against real tor 0.4.9.11

Not a citation — a run. `scratch/onion-derive.mjs` derives the address from a fixed test `K_inv` in pure `node:crypto`; `scratch/onion-witness.mjs` spawns real `tor` (hermetic: `DisableNetwork 1`, so no bootstrap/publish — `ADD_ONION` returns the ServiceID from pure local key math), authenticates to the ControlPort via cookie, sends `ADD_ONION ED25519-V3:<expanded-from-K_inv>`, and compares tor's `ServiceID` to the locally-computed address:

```
K_inv         : 00112233445566778899aabbccddeeff
onion_seed    : 1bfee7874a74cda0914f58536b759760508b60037914aba66cde78ecb41bf71f   (HKDF(K_inv,"p2p-onion-v1"))
KP_hs_id (pub): 5880ea5f64a1e66c31f3b8fded48b7a05b00bc56fa9dcaca6561645c346e674d
expected ServiceID (local): lcaoux3euhtgymptxd662sfxubnqbpcw7ko4vstfmfsfyndom5gql4yd
tor ServiceID     (real ): lcaoux3euhtgymptxd662sfxubnqbpcw7ko4vstfmfsfyndom5gql4yd
MATCH: ✅ PASS — tor derived the SAME address from our key   (56 b32 chars, VERSION byte 0x03)
```

**Conclusion (empirical, not inferred):** the `K_inv → onion-key → .onion` derivation is deterministic, correct, and accepted by production tor. **Both parties, holding only `K_inv`, compute the identical onion address with zero coordination and zero lookup.** The elegant fit the brief hoped for is real. `tor` binary used: Homebrew `tor 0.4.9.11` (installed in the throwaway env for this test only; not a project dep).

### 3.5 Who runs the service (the role subtlety)

Both parties derive the *same keypair* from `K_inv`. An onion service is a single listener, so exactly one side must `ADD_ONION`:

- **Listener** (the `node.listen({invite})` side) runs `ADD_ONION ED25519-V3:<expanded>` → serves the address, forwards the virtual port to a local TCP port where it runs the **Noise responder**.
- **Dialer** (`node.connect(share)`) derives the *same* `.onion` from `K_inv`, opens a Tor SOCKS5 `CONNECT` to `<addr>.onion:VIRTPORT`, and runs the **Noise initiator** over the returned stream.

Both compute the address (so the dialer needs no lookup); only the listener instantiates it. This is the existing `listen`/`connect` asymmetry (`src/node.js`) — no new concept. (If both sides ever tried to `ADD_ONION` the same key, tor on the second host would simply serve a duplicate descriptor; the convention "listener-only serves" avoids it.)

---

## 4. Composition with Noise `IKpsk2` — clean, and code-proven

**Claim: Tor and Noise compose with zero conflict, and Noise's security does NOT rest on Tor.**

- **Transport shape already matches.** `src/transport.js _tcpSocketLike` wraps a TCP stream as the project's `socketLike` (`{proto,remote,send,onMessage,close}`) with a 2-byte length prefix (wire.js is datagram-oriented). A Tor SOCKS stream **is** a TCP stream → the identical wrapper applies verbatim. Onion mode produces a `socketLike`; everything above the transport is unchanged.
- **Noise runs on top, unmodified.** `src/node.js` `initiatorHandshake`/responder already take `{psk, prologue}` and run `Noise_IKpsk2` over whatever `socketLike` the transport handed them (`src/noise.js` psk path is strictly additive, §5 of metadata-privacy). Onion mode changes *how the socketLike is obtained*, not the handshake.
- **Why it's defense-in-depth, not redundancy.** Tor encrypts each hop and hides IPs; Noise proves *identity* via the pinned-static commitment gate + `IKpsk2`. These are orthogonal: **even if the entire Tor path were adversarial** (every relay colluding, or a malicious rendezvous point), Noise still refuses any party without `K_inv` and pins the responder's static key against `S`'s commitment — the MITM-proof property holds **independent of Tor's trust model**. Conversely Tor hides the IP that Noise (by itself) would expose at the transport. Each covers the other's gap.
- **The `prologue`.** `src/invite.js handshakePrologue()` is already a fixed invite-scoped value derived from `K_inv` alone — unaffected by transport. It still binds the handshake to *this* invite over onion just as over UDP.
- **What onion mode SKIPS:** the whole `rendezvous/*` (DHT/tracker/mDNS) and the STUN/ICE/hole-punch ladder (`src/transport.js` punch). Fewer moving parts on the onion path. The `.onion` address is the rendezvous; the Tor circuit is the NAT traversal (onion services traverse NAT for free — the service reaches out to introduction points, so no inbound port is needed).

No composition blocker. Confirmed from code, not assumed.

---

## 5. The hard costs, honestly (run through the Complexity Adversarial Gate)

### 5.1 Latency — the biggest cost, and it is structural

An onion connection uses **6 relays**: the client builds a 3-hop circuit to a rendezvous point, the service builds a 3-hop circuit to the same point, traffic flows client↔RP↔service (vs 3 hops for ordinary Tor). Far slower than the LAN/direct paths the project prizes ("blazingly fast" mDNS). Measured, primary-sourced:
- **>5× the latency of a direct path** for interactive use. Arora & Garman, "Improving the Performance and Security of Tor's Onion Services," PoPETs 2025(1):531–552 (https://doi.org/10.56553/popets-2025-0029): over 90% of onion connections incur latencies >5× a direct Internet path; the 6-hop one-way delay "often exceeds the acceptable threshold" for VoIP where a 3-hop circuit is marginally OK. Congestion-DoS against onion routers raises median onion download time **+47%** (Jansen et al., cited therein).
- **Historical reliability was poor** (dated, pre-hardening): Mani et al., USENIX Security 2018 (arXiv:1809.08481) — *"more than 90% of attempted connections to onion services fail because the server never completes its side of the connection protocol."* 2018 data, pre-vanguards/later hardening — **flag as dated**, but a sobering baseline.
- The web-search figures "13–20 s average / 7–50 s range" could **not** be confirmed in any primary paper read — **dropped as UNVERIFIED.** OnionPerf publishes live onion-vs-public TTFB medians (https://metrics.torproject.org/onionperf-latencies.html) but the numbers render only in an interactive chart — **exact medians UNVERIFIED**, mechanism/source real.

**Reachability after going online:** the listener must upload its descriptor to the HSDir ring before anyone can connect. Descriptors are re-uploaded every 60–120 min; the blinded pubkey is valid 48 h (Hoeller et al., "On the state of V3 onion services," FOCI'21, https://doi.org/10.1145/3473604.3474565). Practical first-reachability delay ranges from **a few minutes up to ~30 min** (Whonix, https://www.whonix.org/wiki/Onion_Services) — a real cold-start cost that the direct path does not have. This, plus the 6-hop latency, is why onion must be **opt-in**, never the default.

### 5.2 The dependency problem — and why "talk to the user's tor" is the only zero-dep-preserving answer

- **No maintained pure-JS Tor client exists.** Confirmed: `Ayms/node-Tor` (self-described "only … Tor protocol in JS") explicitly does **not** implement directory/consensus validation, its later phases are unfunded/dormant; `rotten-onion-tor` is a from-scratch learning project. None speaks the real protocol end-to-end. A from-scratch JS Tor is a multi-year, security-critical burden — **rejected outright.**
- **Arti** (Rust, gitlab.torproject.org/tpo/core/arti): onion-*service* support is "ready for use, but not all features of C Tor are available" — the relay-parity milestone sits ~39% (mid-2026). Crucially **no Node napi/wasm binding exists**; docs.rs/arti-client itself says the "best current option is to spawn the arti CLI SOCKS proxy as a subprocess." So Arti is not a JS dependency either — it too would be an external process. Not usable today.
- **Bundling a `tor` binary** inside the npm package: violates the zero-dep invariant in spirit and bloats the package by **~18–31 MB compressed** per platform (measured 2026-07-12 against dist.torproject.org Expert Bundle v15.0.17: macOS ~18.4 MB, Windows ~21.3 MB, Linux ~30.7 MB) — and, worst, makes *us* responsible for shipping/patching a security-sensitive C daemon on npm's release cadence.
- **∴ The only design that preserves the zero-dep invariant is: require the user to install and run their own system `tor`, and speak to its ControlPort+SocksPort over `node:net`.** This is exactly how the project already treats `werift`/WebRTC (an optional, user-supplied capability, not an npm dependency) and STUN servers (external infra we *use*, don't *ship*). `tor` is packaged in **Homebrew** (`tor` 0.4.9.11, confirmed live) and **Debian** (trixie, 0.4.9.11, ~5.88 MB installed) — a one-line install the user opts into. If tor is absent, onion mode is simply unavailable and the node falls back to the direct path — **degenerate-safe** (CAG check 5). Default ports: SocksPort **9050**, ControlPort commonly **9051** (off unless enabled). **tor does not require root** on high ports.

### 5.3 Attack surface — the owner's exact worry, accounted

Tor is a large C codebase, but the CVE record needs a careful read. A vendor-tag search shows ~46 CVEs under "torproject" (2012–2026) — but that tag **conflates the little-t tor daemon with Tor Browser (Firefox-based)**. The single High-severity RCE in that list, CVE-2016-9079, is a **Firefox** SVG use-after-free in *Tor Browser* — **not** the daemon. Daemon-specific advisories (TROVE-2021-00x, TROVE-2022-002, the six TROVE-2026-006…011 fixed in 0.4.9.8) are overwhelmingly **DoS / crash / memory-safety (OOB read, NULL-deref, resource exhaustion)** — **no confirmed remote-code-execution against the daemon itself** surfaced in this pass. (The clean daemon-only count could not be extracted — the gitlab TROVE wiki 403'd — so **UNVERIFIED exact number**; the *class* pattern, DoS not RCE, is well-supported.)

The **trust-boundary difference is decisive**:

| | (i) BUNDLE tor in the npm package | (ii) TALK to the user's system tor (recommended) |
|---|---|---|
| Who ships/patches the C binary | **us** (we own every tor CVE, on npm's cadence) | the OS package manager (user's `apt`/`brew`, security cadence) |
| Process boundary | tor's 100k+ LOC C in our supply chain / node_modules | separate process, own uid, distro seccomp/AppArmor-confined |
| Our added attack surface | the whole tor binary + launcher + per-platform provenance | a `node:net` client to `127.0.0.1:9051/9050` + control-protocol string handling |
| Zero-dep invariant | violated (ships a daemon) | **preserved** (optional external peer) |

Design (ii) reduces *our* new attack surface to a local-socket control client. The control protocol is line-based text (`PROTOCOLINFO` → cookie/`SAFECOOKIE` `AUTHENTICATE` → `ADD_ONION`); the parsing surface is small and we drive it — we never parse hostile input from tor beyond well-formed `250` status lines. The residual "the user runs tor, tor has a bug" is the user's tor, patched by the user's OS, exactly like their OpenSSL or libc. **This is the accounting that makes the CAG pass** — and it directly answers the owner's "what NEW attack surface does bundling Tor add": under design (ii), almost none of tor's; under (i), all of it.

### 5.4 Reliability / censorship

Tor is blocked or throttled in some networks. Circumvention needs **pluggable transports** — obfs4, Snowflake, WebTunnel — now unified in a single **lyrebird** binary (successor to obfs4proxy/snowflake-client). Operationally that requires a `Bridge <transport> <ip:port> <fingerprint> …` line + a `ClientTransportPlugin` line + `UseBridges 1` in the user's `torrc`, with bridge lines obtained from bridges.torproject.org — **operator configuration, not our code**. Our design passes SOCKS/Control through to whatever the user's tor is configured with, so bridges "just work" if the user set them up. We document it; we don't implement PT. (Tor support docs: support.torproject.org/little-t-tor/circumvention/.)

### 5.5 The residual onion does NOT remove (stated up front)

- **Global passive adversary / timing correlation.** A watcher of the whole Tor network can correlate the timing/volume at your entry with the rendezvous — Tor explicitly does not defend against a global passive adversary, and neither do we. Padding/cadence blunt, don't erase (same boundary as `metadata-privacy.md` §8 row 4). **Prior art for exactly this boundary:** Signal sealed-sender hides the sender from the server but leaves "traffic correlation via timing attacks and IP addresses" open by its own admission (signal.org/blog/sealed-sender). We inherit the same honest line.
- **The two peers still learn each other's `.onion`.** That is the point of connecting; it reveals no IP.

---

## 6. Alternatives — the lightest thing that meaningfully helps

### 6.1 WebRTC forced-relay (`iceTransportPolicy:'relay'`, TURN-only) — the cheap browser partial win ✅ (recommended alongside onion)

The browser client already uses WebRTC (`src/browser/webrtc.js`). Setting `RTCPeerConnection({iceTransportPolicy:'relay'})` forces ICE to use **only TURN-relayed candidates**. W3C WebRTC (https://www.w3.org/TR/webrtc/#dom-rtcicetransportpolicy), verbatim: `"relay"` → *"The ICE Agent uses only media relay candidates such as candidates passing through a TURN server."* Host and server-reflexive (STUN) candidates are excluded, so **only the TURN server's address reaches the peer** — the remote peer never sees your IP (closes **row 6** for the browser). Near-zero added complexity (one config flag + a TURN URL); real deployments do exactly this for IP-privacy (BigBlueButton/mediasoup force relay-only ICE). **Honest limits:** (a) the **TURN operator sees your IP** — RFC 8656 (TURN): the server relays between peers and sees each peer's reflexive transport address + traffic timing/volume; **row 2 partially remains**, shifted from "any tracker" to "one TURN server you chose" — the same single-hop trust shape as a VPN; (b) it needs a TURN server (free/public TURN is scarce; the user or a friend runs `coturn`); (c) it is *browser-only* (the TUI hole-punches over UDP, not WebRTC). **Verdict: a genuine, cheap, partial win for the browser** — hides IP from the peer, not from the relay. Ship it as the browser's `v3.1` partial mode while onion serves the TUI.

### 6.2 Relay-through-a-mutual-trusted-peer (onion-lite) — steelman, then the limit

A friend's node acts as a blind, layer-encrypted relay (TURN-like but peer-run): you connect to the friend, the friend forwards ciphertext to the listener. **Hides:** your IP from the *listener* (row 6) if the friend doesn't reveal it. **Does NOT hide:** your IP from the **friend** (you connect to them directly), and it requires a mutually-trusted online third party. Structurally it is a single untrusted-friend proxy: one observation point, no path diversity, no cover traffic → trivially defeated by anyone watching the relay, and it leaks the social graph (who relays for whom). Strictly weaker than Tor's 3-hop-each design, which exists precisely because 1–2 hops don't resist a relay-adjacent observer. **Verdict: not worth building** — a trusted-party requirement and a new attack angle (the relay) for a fraction of onion's protection. The honest version of "onion-lite" *is* Tor onion.

### 6.3 Mixnets (Nym/Loopix), I2P, Reticulum — one honest line each

- **Nym / Loopix mixnets:** stronger against timing correlation (deliberate per-hop Poisson delay + cover traffic), but heavier and higher-latency — Nym is a 5-hop Sphinx mixnet, ~498 live mix nodes (Feb 2026), **~500–800 ms** typical e2e; its SDK (`@nymproject/sdk-full-fat`) is a browser/WASM bundle (Sphinx crypto + credentials), a poor fit for a zero-dep Node lib. Loopix is the academic design (USENIX Sec 2017) Nym descends from — never itself an installable library. Future-only.
- **I2P:** garlic-routed, comparable anonymity, but JVM-centric — non-Java apps talk to a local I2P router over SAM/BOB sockets (same "run + talk to a daemon" shape as tor, heavier), and its anonymity set is much smaller than Tor's. `rendezvous.md` §7c already says AVOID; consistent here.
- **Reticulum (RNS):** pure-Python, lightweight, built for resilient/low-bandwidth links (LoRa, packet radio); JS support is a wishlist discussion only, so use-from-Node means shelling out to a Python `rnsd`. Its threat model (resilient addressing) differs from Tor's anonymity-first design and it has had far less adversarial scrutiny. **UNVERIFIED** fit; future scoped look (owner mentioned it).

### 6.4 Onion-lite / few-hop schemes — the standard critique

Even Tor shelved a two-hop-paths proposal (spec.torproject.org/proposals/115), and its "single onion service" one-hop mode is explicitly for **non-anonymous** services, not client anonymity. Academic 2-hop low-latency designs (LAP, Dovetail) keep packet bit-patterns unchanged hop-to-hop → "vulnerable to trivial packet-matching attacks" (HORNET paper, crysp.uwaterloo.ca). The universal law: **fewer hops = smaller anonymity set + easier first-last correlation**; and even Tor's 3 hops do **not** defend a global passive adversary — "against a global adversary … an attacker can perform a first-last traffic-correlation attack" (arXiv:1511.05453). Mixnets answer this with delay + cover traffic — the exact overhead few-hop/lite schemes (and Tor, for latency) skip. **Takeaway: there is no cheap "onion-lite" that closes rows 2 & 6 without either Tor's hop count or a mixnet's cover traffic.**

### 6.5 The escalation answer

**No lighter mechanism closes rows 2 AND 6 the way onion does.** Forced-relay closes row 6 for the browser but leaves row 2 at the TURN operator. Mutual-peer relay closes row 6 only vs the listener and adds a trusted party. Onion is the only thing that closes both against everyone but a global-passive/timing adversary. So the recommendation is **onion for the TUI (full), forced-relay for the browser (cheap partial)** — not "onion or nothing."

---

## 7. Complexity Adversarial Gate accounting (surface-hardening.md §6)

| # | Check | Onion-mode result |
|---|---|---|
| 1 | **Residual-closed (quantified)** | Closes **rows 2 & 6** (IP-from-surface, IP-from-peer) — the ONLY mechanism that does. Does NOT close row 4 (global-passive timing). Net-positive on the dominant residual. **PASS.** |
| 2 | **Attack-surface enumeration** | New parts: (a) `node:net` control client to system tor; (b) SOCKS5 client; (c) `ADD_ONION` from `K_inv`. Each enumerated §5.3. Bounded by NOT bundling tor (talk to user's daemon). **PASS given design (ii).** |
| 3 | **Weakest-link map** | Pre-change weakest link = your source IP at surfaces/peer. Post-change that link is **removed** (IP never leaves the Tor boundary); new weakest link = global-passive timing, which is strictly *harder* to exploit than reading a plaintext IP. **PASS (improves).** |
| 4 | **Reliability proof** | Onion is an *added optional path*, not a change to the existing one. When tor is present, `P(connect)` via onion depends on Tor reachability; when absent, mode is unavailable and direct path is unchanged. Does not *reduce* the existing path's reliability. **PASS (additive).** |
| 5 | **Degenerate-safe** | No tor / tor blocked → onion mode unavailable → fall back to direct rendezvous, **exactly today's behavior, never worse.** **PASS.** |
| 6 | **Monitoring hook** | Leak-monitor assertion (surface-hardening §7): in onion mode, assert **no candidate IP is ever emitted to any rendezvous surface** (there is no rendezvous surface at all) and the SOCKS target is a `.onion`, never an IP. **Add to the battery.** |
| 7 | **Flag-gated + reversible** | `transport:'onion'` opt-in, default OFF; when off, **zero** wire/behavior change. **PASS.** |
| 8 | **Simplicity dominance** | Is there a simpler thing closing rows 2 & 6? **No** — §6 shows nothing else closes both. Forced-relay is simpler but closes only row 6 (browser) and leaves row 2. So onion is not dominated for the TUI; forced-relay is the simpler complement for the browser. **PASS (not dominated).** |

**CAG verdict: passes all 8 under the system-daemon (non-bundled) design.** The check that would fail a *bundled* tor is check 2/8; the non-bundled design is what earns the pass.

---

## 8. Verdict + phased plan

### Verdict: **WORTH-IT-FLAG-GATED**

Onion is the **only** mechanism that closes the dominant IP residual (rows 2 & 6) that v1/v2/cycling/sharding provably cannot. The `K_inv→onion-key` derivation is **witnessed working against real tor**, composes cleanly with the untouched Noise core, and — crucially — can be built **without breaking the zero-dep invariant** by talking to the user's own system tor over `node:net` (the `werift` precedent). The costs (seconds of latency, requires user-installed tor, blocked in hostile nets without bridges) are real and are exactly why it must be **opt-in, default-OFF**, never the primary path. It is worth building as an optional capability for the privacy-critical user; it is NOT worth forcing on the median user who is well served by v1+v2.

**The honest tradeoff in one line:** trade *seconds of latency + a user-installed tor daemon* for *your IP never reaching any surface or the peer* — a trade only the privacy-critical user should be asked to make, hence the flag.

### Minimal viable v3 increment

- **v3.0 (TUI, the core win).** ~1 small module `src/rendezvous/onion.js` (or `src/transport-onion.js`):
  1. detect a reachable system tor: `PROTOCOLINFO` → read `AUTH METHODS`+`COOKIEFILE` → `AUTHENTICATE <hex-cookie>` (or `SAFECOOKIE` challenge; or bare `AUTHENTICATE` if `NULL`) over `node:net` to `127.0.0.1:9051`. If absent → mode unavailable, fall back to direct.
  2. **listener:** derive `expanded` from `K_inv` (reuse `invite.js` primitives; add the `onion_seed` derivation), `ADD_ONION ED25519-V3:<base64-expanded> Port=<vp>,127.0.0.1:<local>` (add `Flags=Detach` only if the service must outlive the control connection); the returned `ServiceID` = the derived address (no `.onion` suffix) — assert it matches, then run the existing Noise responder on `<local>`.
  3. **dialer:** derive the `.onion` from `K_inv`, SOCKS5 `CONNECT` to `<addr>.onion:<vp>` via SocksPort `9050` (ATYP=DOMAINNAME — tor resolves the onion internally, no local DNS), wrap the returned stream as `_tcpSocketLike`, run the existing Noise initiator with `{psk, prologue}`.
  4. flag: `listen({invite, transport:'onion'})` / `connect(share, {transport:'onion'})`. Default off.
  - **Earns:** IP hidden from every surface and from the peer, over the untouched crypto core. Est. ~150–250 LOC, zero npm deps, reuses `invite.js` + `noise.js` + `_tcpSocketLike` wholesale.
- **v3.1 (defense-in-depth + browser partial).** (a) descriptor **client-auth** (Tor "restricted discovery", rend-spec-v3 App. G): derive an x25519 client-auth keypair from `K_inv`; on the service side add the client pubkey (`ADD_ONION … Flags=V3Auth ClientAuthV3=<x25519-pub>` or the on-disk `descriptor:x25519:<base32>` `.auth` file), and on the dialer side `ONION_CLIENT_AUTH_ADD <addr> x25519:<base64-priv>` — so even a party that *learns* the `.onion` cannot fetch/decrypt the descriptor without `K_inv` (belt-and-suspenders beneath the Noise gate). (b) **browser forced-relay** (`iceTransportPolicy:'relay'`) as the cheap row-6 partial win for the WebRTC client.
- **v3.2 (censored nets).** Document + pass through bridge/PT config; no PT code of our own.

### ESCALATION status: **CLEARED — no STOP.**

The brief's two STOP conditions were: (a) `K_inv→onion-key` cryptographically impossible → **FALSE**, witnessed working (§3.4); (b) tor cannot be made optional → **FALSE**, the system-daemon model keeps it optional and zero-dep (§5.2). Neither fired. Recommendation stands.

---

## 9. UNVERIFIED / hand-offs (honest list) + citations

**Load-bearing claims — VERIFIED:**
- **`K_inv→onion-key→.onion` derivation** — **WITNESSED** against real `tor 0.4.9.11` (§3.4, `scratch/onion-{derive,witness}.mjs`), reproducible.
- **ADD_ONION ED25519-V3 wants the 64-byte expanded key** — **WITNESSED** (fed 64 B, accepted, correct address) **and** design-record-confirmed (Proposal 284 + tor-dev list; §3.3).
- **Onion address encoding** (SHA3-256, VERSION `\x03`, RFC4648 base32, 56 chars) — spec-cited (rend-spec-v3) **and** match-confirmed by the witness (a wrong hash/field-order would not have matched tor's ServiceID).
- **Composition with Noise over `_tcpSocketLike`** — code-confirmed (`src/transport.js`, `src/node.js`, `src/noise.js`).
- **`ADD_ONION` grammar; ServiceID = addr without `.onion`; service dies on control-conn close unless `Detach`** — control-spec verbatim (§9 refs).
- **ControlPort auth** (`PROTOCOLINFO`→`AUTHENTICATE`, 32-byte cookie, `SAFECOOKIE`) — control-spec verbatim.
- **`ONION_CLIENT_AUTH_ADD` x25519 + `descriptor:x25519:<base32>` restricted-discovery** — control-spec §3.30 + rend-spec-v3 App. G verbatim.
- **SOCKS: `.onion` passed as the address of a SOCKS4a/SOCKS5 request; tor resolves internally (no local DNS)** — address-spec + socks-extensions. (The ATYP=0x03/DOMAINNAME byte is generic RFC 1928 SOCKS5, **not** a literal torspec sentence — correct but noted.)
- **Default ports SocksPort 9050 / ControlPort 9051-by-convention; no root required** — tor manual (via archived + Debian manpage mirrors; `man.torproject.org` was DNS-unreachable in the research sandbox).
- **No maintained pure-JS Tor; Arti onion-service ~39%/no Node binding; tor binary ~18–31 MB; Homebrew+Debian package tor 0.4.9.11** — subagent-C, sources live-checked 2026-07-12.
- **Latency >5× direct (PoPETs 2025); WebRTC `relay` excludes host/srflx (W3C); TURN sees both IPs (RFC 8656)** — primary-sourced (§5.1, §6.1).

**UNVERIFIED — honest residual:**
- **Exact key-blinding formula + descriptor two-layer-encryption verbatim text** (§2.3) — the *enumeration-resistance property* is spec-confirmed and is the load-bearing claim; the precise blinding math (`blinded_key`, nonce/period params) is **UNVERIFIED here** (subagent-A's verbatim extraction not yet folded in — a documentation nicety, not a decision input).
- **ED25519-V3 = expanded key at the C-source level** — settled empirically + on the dev list; a `grep control_cmd.c` / stem read was blocked by a gitlab bot-403. Confidence high.
- **Exact onion latency medians** — order "seconds / >5×" is firm; precise OnionPerf medians render only in an interactive chart (UNVERIFIED numeric).
- **Descriptor→first-reachable delay** — "minutes to ~30 min" range sourced (Whonix/FOCI'21); no single hard number.
- **The 2018 ">90% onion connection attempts fail" figure is DATED** (pre-hardening); cited as a historical baseline, not current.
- **Clean daemon-only CVE count** — vendor tag conflates Tor Browser; the *class* (DoS/memory-safety, no confirmed daemon RCE) is well-supported, the exact count is not.

**Primary sources:** rend-spec-v3 https://spec.torproject.org/rend-spec-v3/ · Tor control-spec https://spec.torproject.org/control-spec/ · Proposal 284 https://spec.torproject.org/proposals/284-hsv3-control-port.html · tor-dev list https://archives.seul.org/or/dev/Nov-2017/msg00044.html · address-spec https://spec.torproject.org/address-spec.html · socks-extensions https://spec.torproject.org/socks-extensions.html · Tor manual (archived) https://2019.www.torproject.org/docs/tor-manual.html.en · Tor circumvention https://support.torproject.org/little-t-tor/circumvention/ · PoPETs 2025(1):531 https://doi.org/10.56553/popets-2025-0029 · Mani et al. USENIX'18 arXiv:1809.08481 · Hoeller et al. FOCI'21 https://doi.org/10.1145/3473604.3474565 · Whonix https://www.whonix.org/wiki/Onion_Services · W3C WebRTC https://www.w3.org/TR/webrtc/#dom-rtcicetransportpolicy · RFC 8656 (TURN) · HORNET (crysp.uwaterloo.ca) · arXiv:1511.05453 · Signal sealed-sender https://signal.org/blog/sealed-sender/ · RFC 8032 (Ed25519) · RFC 5869 (HKDF). Cross-refs: `research/metadata-privacy.md` §8/§9, `research/surface-hardening.md` §6, `research/rendezvous.md` §7b/§7c, `src/invite.js`, `src/noise.js`, `src/transport.js`.

---

*End of study. Verdict: **WORTH-IT-FLAG-GATED** — build onion as an optional `transport:'onion'` mode over the user's own system `tor` (zero-dep preserved), deriving the service key from `K_inv` so the `.onion` IS the rendezvous id (witnessed against real tor). The only mechanism that closes the IP residual (rows 2 & 6); costs (latency, tor dependency, censorship) make it opt-in, never default. ESCALATION cleared: derivation proven feasible, tor kept optional.*
