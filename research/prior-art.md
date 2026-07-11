# Prior-Art Survey — Minimal Embeddable P2P Chat/Data Framework

> Research Lane A. Decision-grade survey of existing serverless P2P chat/messaging
> systems, so we borrow proven mechanisms instead of reinventing.
> Every load-bearing claim carries a source URL. Claims not confirmed against a primary
> source are marked **UNVERIFIED**. Numbers the surveying lane verified directly against
> primary docs are marked ✅.
> Author: Research Lane A (opus lead + 3 sonnet cluster subagents, all claims re-checked
> against sources by the lead). Date: 2026-07-11.

---

## Our constraint set (what we test prior art against)

1. **Address = a 26-char hashkey** a user generates and shares out-of-band (copy/paste).
   - 26 chars of base32 (5 bits/char) ≈ **130 bits** of entropy → a *high-entropy*
     secret. **Central consequence (see magic-wormhole below): PAKE is unnecessary for
     us.** PAKE exists to bootstrap trust from a *low*-entropy secret (a 16-bit human
     code); 130 bits is already strong. 130 bits fits a **key fingerprint / hash of a
     public key** but NOT a full 32-byte Ed25519 public key (~52 base32 chars). So the
     26-char key is most naturally a **fingerprint of** the identity key, or a 16-byte
     seed that deterministically derives the keypair — a protocol-lane choice, flagged
     here wherever prior art bears on it.
2. **Anyone holding the key can find + message the owner** (rendezvous by key).
3. **E2E encrypted, MITM-proof first contact.**
4. **NAT traversal with NO coordinator server of our own** — free/public infra only.
5. **Tiny, embeddable, zero-dependency, fast, realtime. Friends + groups.**

---

## Systems surveyed (13)

### iroh (n0) — QUIC + relay, dial-by-key ✅ (lead-verified)

1. **Discovery/rendezvous.** Peers are dialed by `EndpointID`/`NodeId` (a public key),
   resolved to addresses via pluggable discovery: **DNS/Pkarr** (default — publishes
   signed records, resolved as `_iroh.<z32-id>.<origin> TXT` against `dns.iroh.link`
   run by n0), optional **mDNS-like** local, optional **BitTorrent Mainline DHT** signed
   records. (https://docs.iroh.computer/concepts/discovery)
2. **NAT traversal.** QUIC over a relay that doubles as a STUN-like coordinator; peers
   hole-punch then upgrade to direct. **~9/10 connections go direct** ("roughly 9 out of
   10 connections go direct; the relay is only a stepping stone"); **~95% of data volume
   flows over direct paths.** **Multipath** (1.0) probes several routes per connection
   and hot-swaps without dropping. Four **free public relays** run by n0 (2 US, 1 EU, 1
   Asia), explicitly *"free to use for development and testing."*
   (https://docs.iroh.computer/about/faq, https://www.iroh.computer/blog/v1)
   ⚠️ "development and testing" wording = production reliance on n0's free relays is not
   contractually guaranteed.
3. **Crypto/identity.** `EndpointID` = **Ed25519 public key** ✅; connection = **QUIC +
   TLS 1.3**. Address *is* the identity → dialing a key authenticates the peer, so there
   is no first-contact MITM window. (https://docs.iroh.computer/about/faq)
4. **Footprint.** Rust core; **stable bindings for Python, Node.js, Swift, Kotlin** as of
   1.0 (2026-06-15) with a stable wire protocol. Full QUIC stack — capable, not "tiny."
   Stateless relays (forward encrypted packets, no session state) = cheap.
   (https://www.iroh.computer/blog/v1)
5. **License.** Dual **Apache-2.0 / MIT**. (https://www.iroh.computer/blog/v1)
6. **THE STEAL.**
   - **Address = Ed25519 public key** → identity and address are one object; first-contact
     MITM is structurally impossible.
   - **Stateless relay as STUN + last-resort transport** — cheap, never sees plaintext.
   - **Signed DNS/DHT records for key→address mapping** (Pkarr) — reuse free DNS + Mainline
     DHT rather than our own coordinator.
   - **200M+ endpoints created in 30 days** through n0's relays = production-proven at scale.
     (https://www.iroh.computer/blog/v1)
   - *Mistake to avoid:* treating one vendor's "free for dev/testing" relays as permanent
     production infra. Real-world hole-punch varies badly on carrier-grade mobile NAT
     (iroh issue #2317 has anecdotes of it underperforming Tailscale there — the ~90% is
     an aggregate, not a per-network guarantee). (https://github.com/n0-computer/iroh/issues/2317)

### hyperswarm / HyperDHT (Holepunch / Pear) — Keet's transport ✅ (lead-verified)

1. **Discovery/rendezvous.** **HyperDHT**, Kademlia-style, keyed by **32-byte topics**.
   `announce(topic, keyPair)` / `lookup(topic)`. Bootstrap nodes *"publicly served on
   behalf of the [Pear] commons"* — free, community-run. (https://github.com/holepunchto/hyperdht)
2. **NAT traversal.** *"A series of holepunching techniques"* over UDP; DHT nodes act as
   introducers. Success % not published — **UNVERIFIED** exact rate.
3. **Crypto/identity.** **Ed25519 keypair**; **public key = connection address = identity** ✅.
   Connections wrapped in a **Noise** handshake (`NoiseSecretStream`) → E2E + MITM-safe if
   key shared out-of-band. (https://github.com/holepunchto/hyperdht)
4. **Footprint.** JavaScript/Node (also Holepunch's minimal **Bare** runtime). Modular:
   hyperswarm + hyperdht + hypercore. Pure-JS, embeddable. (https://github.com/holepunchto/hyperswarm)
5. **License.** MIT. (https://github.com/holepunchto/hyperswarm)
6. **THE STEAL.**
   - **DHT topic = 32-byte key; announce/lookup IS the whole rendezvous API** — maps 1:1
     onto "share a key, the other side finds you."
   - **Mutable/immutable DHT records** — Keet stores small signed **mutable records** for
     presence/signaling ("serverless calls"): a cheap coordinator-free signaling channel.
   - Proven at product scale: **Keet** (chat/video) runs entirely on this stack.
   - *Mistake to avoid:* sole reliance on Holepunch's one bootstrap set (same single-operator
     risk as everyone else — see Gaps).

### magic-wormhole — PAKE first-contact (the reference for short-secret pairing) ✅ (lead-verified, deep)

1. **Discovery/rendezvous.** A **mailbox/rendezvous server** (`relay.magic-wormhole.io`,
   author-run, free) does store-and-forward of small control messages. Primitives:
   **nameplate** (short numeric claim-ticket → a mailbox) + **mailbox** (message queue).
   Server only ever relays opaque blobs — never sees the code or plaintext.
   (https://magic-wormhole.readthedocs.io/en/latest/welcome.html,
   https://github.com/magic-wormhole/magic-wormhole-protocols/blob/main/server-protocol.md)
2. **NAT traversal.** Direct connection attempted first (peers exchange IPs inside encrypted
   messages); falls back to a separate **transit relay** (`transit.magic-wormhole.io`, TURN-like)
   that *"glues together two inbound TCP connections."* All bytes already E2E encrypted.
3. **Crypto/identity — the crux for us.** A code like `7-crane-flatfoot` = channel number +
   words, **default 16-bit entropy**. **SPAKE2** (a PAKE) *"uses a short low-entropy password
   to establish a strong high-entropy shared key."* Both sides feed the same weak code into
   SPAKE2, exchange one blinded DH message each over the mailbox, and derive a strong session
   key neither had before. **The server cannot MITM** — it forwards opaque SPAKE2 blobs and
   never learns the code, so it can't compute the key. **One-guess-per-online-attempt:** an
   active attacker must guess the code during the single live connection; a wrong guess is
   revealed only by the *other side's* handshake failing to match — no offline brute force,
   no oracle. At 16 bits that's 1-in-65,536 per attempt. **Key confirmation** = the first
   post-PAKE `version` message is encrypted with the derived key (HKDF-SHA256 → NaCl
   SecretBox); successful decryption *is* the proof both sides share the key.
   (https://magic-wormhole.readthedocs.io/en/latest/welcome.html,
   https://github.com/magic-wormhole/magic-wormhole-protocols/blob/main/client-protocol.md)
4. **Footprint.** Reference impl Python (3.10+); Rust reimpl (docs.rs/magic-wormhole) and Go
   server reimpl exist — protocol is simple enough to re-implement. Not itself an embed target.
5. **License.** MIT. (https://github.com/magic-wormhole/magic-wormhole)
6. **THE STEAL.**
   - **Key-confirmation-by-decryption-success** (the `version`-message trick) detects
     wrong-key/MITM with zero extra round trips — steal this exact pattern regardless of
     whether we use PAKE.
   - **Rendezvous server that only relays ciphertext** — the minimal "mailbox" pattern for
     first contact when a DHT isn't available; untrusted/free infra is fine because it learns
     nothing.
   - **Direct-relevance verdict: our 26-char key is HIGH entropy (~130 bits), so we do NOT
     need SPAKE2.** We can treat the key as (or as a fingerprint of) the identity key and get
     MITM resistance directly. PAKE would be over-engineering.
   - *Mistake to avoid:* wormhole codes are **single-use**; their "one guess" safety assumes
     the code is burned after one pairing. A **long-lived, reused 26-char key** hands an
     attacker *many independent guesses over time* unless we add **rate-limiting / rotation**.
     This is a gap no surveyed system closes for our exact model (see Gaps).

### trystero — serverless WebRTC via borrowed public infra (browser) ✅ (lead-verified)

1. **Discovery/rendezvous.** No dedicated signaling server; WebRTC signaling is smuggled over
   one of **7 pluggable "strategy" backends: BitTorrent (WebTorrent trackers), Nostr relays
   (default, "hundreds active"), MQTT, IPFS, Supabase, Firebase, or a self-hosted WS relay.**
   *"Your app's data never touches the strategy medium and is sent directly peer-to-peer."*
   Now split into scoped packages (`@trystero-p2p/{nostr,mqtt,torrent,…}`) so you bundle only
   the strategy you use. (https://github.com/dmotz/trystero)
2. **NAT traversal.** Standard **WebRTC ICE** (STUN + optional user-supplied TURN). Inherits
   the browser's mature traversal. General WebRTC field stats: ~70–80% succeed via STUN
   direct, ~20–30% need TURN, TURN pushes success to ~99%. (https://webrtc.ventures/2022/04/ice-in-webrtc/)
3. **Crypto/identity.** `selfId` + `appId` + `roomId`. Signaling (SDP) encrypted **AES-GCM**,
   key derived from appId+roomId; data channel is E2E between peers. ⚠️ *Without* a shared
   `password`, *"a relay strategy operator can reverse engineer the key using the room and app
   IDs"* → **no first-contact MITM protection unless a real shared secret is added.**
   (https://github.com/dmotz/trystero)
4. **Footprint.** TypeScript, MIT, browser-first, small (scoped packages trim bundle). Exact
   KB not published — **UNVERIFIED** (the commonly-cited "~11kb" is not confirmed in-repo).
5. **License.** MIT. (https://github.com/dmotz/trystero)
6. **THE STEAL.**
   - **"Borrow existing free public networks as your signaling channel"** (BitTorrent trackers /
     Nostr relays / MQTT brokers) = zero infra of our own. The single most transferable idea
     for constraint #4.
   - **Pluggable rendezvous strategy** — never marry one channel; abstract it so a dead backend
     swaps out.
   - *Mistake to avoid:* trystero's default room-key is derived from *public* app/room ids →
     MITM-able. Our high-entropy 26-char key must be the *actual secret* feeding key derivation,
     never a public identifier.

### nostr — pubkey identity + free relay fan-out (messaging pattern) ✅ (lead-verified)

1. **Discovery/rendezvous.** Clients pub/sub to **relays** (WebSocket; hundreds public + free).
   Identity is a pubkey; relay-list discovery via NIP-65. (https://github.com/nostr-protocol/nips/blob/master/01.md)
2. **NAT traversal.** None — client↔relay store-and-forward, not P2P transport. Solves
   *rendezvous/mailbox*, not *direct transport*.
3. **Crypto/identity.** Identity = **secp256k1 pubkey** ("npub", NIP-19 bech32 for display).
   Modern DMs (**NIP-17**): a kind-14 chat event, **NIP-44 encrypted** (ChaCha20 + HMAC),
   **sealed** (kind 13), then **gift-wrapped** (**NIP-59**, kind 1059) with a **fresh disposable
   keypair per message** so relays can't see the sender (recipient still visible via `p` tag).
   Old **NIP-04** deprecated (leaked full metadata/social graph). **NIP-EE** = group E2E over
   the **MLS** protocol. (https://nips.nostr.com/17, https://nips.nostr.com/44, https://nips.nostr.com/ee)
4. **Footprint.** Protocol, not a lib; a client is tiny (WebSocket + secp256k1 + ChaCha20).
   Extremely embeddable as a *rendezvous* layer.
5. **License.** NIPs are CC0-style public spec; impls mostly MIT. (https://github.com/nostr-protocol/nips)
6. **THE STEAL.**
   - **Pubkey = identity, free public relays = rendezvous/mailbox** — a running, robust,
     censorship-resistant free network usable exactly like trystero uses it.
   - **Gift-wrap (NIP-59) metadata hiding** — disposable per-message keypair hides the sender;
     cheap and proven. Use it over any relay hop so operators never see our real traffic graph.
   - **NIP-EE / MLS for groups** — the serious answer to *group* E2E (forward secrecy,
     post-compromise security) instead of hand-rolling group crypto.
   - *Mistake to avoid:* NIP-04's "encrypt content, leak everyone's metadata." Hide
     sender/recipient/timing from v1.

### libp2p (IPFS) — the big modular stack + the honest NAT numbers ✅ (lead-verified)

1. **Discovery/rendezvous.** Kademlia **DHT**, mDNS, bootstrap lists, and a **rendezvous**
   protocol (register a signed peer record under an app namespace at *any* node running the
   protocol; discover via namespace query with a cursor). No mandated free public rendezvous
   default. (https://github.com/libp2p/specs/blob/master/rendezvous/README.md)
2. **NAT traversal — the load-bearing independent number.** **DCUtR** (Direct Connection
   Upgrade through Relay): coordinate via a **circuit-relay-v2** relay, exchange observed
   addresses, then **simultaneous-connect** hole-punch. A 2025/26 large-scale academic
   measurement (**4.4M attempts, 85k+ networks, 167 countries**) found a **70% ± 7.1%**
   hole-punch success rate, **97.6% of successes on the first attempt**, and **empirically
   refuted** the belief that UDP/QUIC beats TCP (statistically indistinguishable; success
   independent of RTT). (https://arxiv.org/html/2510.27500v1, https://arxiv.org/abs/2604.12484)
   → Reality check on iroh's self-reported ~90%: independent measurement of a comparable
   technique in the wild lands nearer **70%**. **Plan for a relay fallback; ~30% of pairs will
   never hole-punch.** Circuit-relay-v2 is deliberately **resource-capped** (time + byte limits)
   to force the DCUtR upgrade and prevent free-relay abuse. (https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md)
3. **Crypto/identity.** **PeerID = multihash of a public key** (Ed25519/secp256k1/RSA);
   transport encryption via **Noise** or TLS 1.3; MITM-safe via PeerID pinning if held
   out-of-band. (https://github.com/libp2p/specs)
4. **Footprint.** Large, modular (Go, Rust, JS) — the antithesis of "tiny/zero-dep." Five
   separate protocols (DHT + rendezvous + AutoNAT + relay-v2 + DCUtR). (https://github.com/libp2p/rust-libp2p)
5. **License.** MIT / Apache-2.0. (https://github.com/libp2p/rust-libp2p)
6. **THE STEAL.**
   - **DCUtR relay-coordinated simultaneous-connect** = the canonical hole-punch recipe —
     copy the *technique*, not the framework.
   - **The 70% / 97.6%-first-try numbers are our planning baseline**: relay fallback is
     mandatory; if a punch doesn't land fast, retrying rarely helps — take a different path.
   - **Resource-capped relay** (time+bytes) is the correct model for leaning on donated free
     relay infra.
   - *Mistake to avoid:* adopting libp2p wholesale (violates "tiny" + brings its own infra
     assumptions) and replicating its 5-protocol fragmentation.

### Jami + OpenDHT ✅ (lead cross-checked)

1. **Discovery/rendezvous.** **OpenDHT** (Kademlia-derived, C++) stores encrypted peer
   announcements; contact discovery = DHT lookup by Jami ID. Default bootstrap
   `bootstrap.jami.net:4222`, run by Savoir-faire Linux (free, single-org). (https://docs.jami.net/en_US/user/jami-distributed-network.html)
2. **NAT traversal.** ICE (STUN/TURN) + DHT-distributed encrypted connectivity announcements.
   No published success % — **UNVERIFIED**.
3. **Crypto/identity.** **X.509 cert + 4096-bit RSA** per account; per-device sub-certs; **Jami
   ID = fingerprint of pubkey** ("as long as you have the correct Jami ID, nobody can
   impersonate them"). Transport **DTLS** with mandatory PFS (ECDHE-AES-GCM). (https://github.com/savoirfairelinux/opendht)
4. **Footprint.** OpenDHT = C++17 (msgpack, GnuTLS, Nettle, fmt); C/Rust/Python3 bindings;
   *"lightweight and scalable… large networks AND small devices."* — the closest thing to an
   **embeddable standalone DHT primitive** here. (https://github.com/savoirfairelinux/opendht)
5. **License.** **OpenDHT = MIT**; **Jami app = GPLv3.** (https://github.com/savoirfairelinux/opendht)
6. **THE STEAL.**
   - **OpenDHT as a reusable MIT DHT primitive** (small-device-targeted, multi-lang bindings) —
     a clean "DHT you can embed," separate from the GPLv3 chat app.
   - **Jami ID = fingerprint = first-contact anchor** — the *third* system converging on
     pubkey/hash-as-address+identity+MITM-anchor. Validates our 26-char-hashkey-as-identity as
     the industry-standard pattern, not a risky novelty.
   - *Mistake to avoid:* 4096-bit RSA + X.509 is heavy; Ed25519 (iroh/hyperswarm) is the lean pick.

### Tox / toxcore ✅ (lead cross-checked)

1. **Discovery/rendezvous.** Kademlia DHT keyed on pubkeys, with an **onion-routing** layer over
   lookups so the network can't easily link "who is searching for whom." Community-run public
   bootstrap node list, free, no central authority. (https://wiki.tox.chat/users/techfaq)
2. **NAT traversal.** UDP direct + hole-punch after friends exchange IPs via DHT; **volunteer-run
   TCP relays** as fallback. No Tox-specific % — **UNVERIFIED**.
3. **Crypto/identity.** **Tox ID = 32-byte Curve25519 pubkey + 4-byte nospam + 2-byte checksum**
   (76 hex chars). NaCl/libsodium: Curve25519 ECDH, XSalsa20, Poly1305; forward secrecy
   mandatory. No PAKE/short-code — the ID *is* the pubkey; MITM-safe only if the ID is shared
   over a trusted channel. (https://wiki.tox.chat/users/techfaq)
4. **Footprint.** C (+ optional C++ AV); dep: libsodium (opus/libvpx for A/V). Modular. (https://github.com/TokTok/c-toxcore)
5. **License.** ⛔ **GPL-3.0** (copyleft — poison pill for permissive embedding). (https://github.com/TokTok/c-toxcore/blob/master/LICENSE)
6. **THE STEAL.** Identity-as-pubkey + zero-server + **onion-wrapped DHT queries for
   who-searches-whom privacy** (good pattern if metadata privacy matters). Volunteer TCP-relay
   fallback = viable free last-resort model. *Avoid:* **GPLv3**; a long-lived unrotatable ID with
   no PAKE step means a leaked/mistyped ID has no safety net.

### Briar ✅ (lead cross-checked)

1. **Discovery/rendezvous.** No DHT/server by design — syncs device-to-device over **Bluetooth,
   Wi-Fi, or Tor hidden services**; optional self-hostable **Briar Mailbox** for async delivery.
   (https://briarproject.org/how-it-works/)
2. **NAT traversal.** **Tor hidden services sidestep NAT entirely** (each peer has a hidden-service
   address); local mesh needs none. Trade-off: Tor path is slow/high-latency. **UNVERIFIED** perf #s.
3. **Crypto/identity.** Bramble protocol suite: **BHP** (authenticated key agreement from
   pre-shared long-term pubkeys) + **BQP** (QR-code in-person pairing whose commitment lets each
   side verify the network-received key matches the physically-scanned one → MITM-proof). Also
   link-sharing for remote adds. (https://code.briarproject.org/briar/briar-spec) — BQP wire
   format **UNVERIFIED** (fetched via secondary summary).
4. **Footprint.** Java/Android-centric client; heavy (bundles Tor). **UNVERIFIED** exact size.
5. **License.** ⛔ **GPLv3.** (https://code.briarproject.org/briar/briar)
6. **THE STEAL.** **Transport-agnostic sync** (same message log over BT/Wi-Fi/Tor) = strong
   resilience pattern. **QR-code-commitment pairing (BQP)** = proven MITM-proof UX for the
   in-person case (could complement our copy-paste key for the remote case). *Avoid:* Tor
   dependency (latency + footprint); GPLv3.

### Waku (Status messaging layer) ✅ (lead cross-checked)

1. **Discovery/rendezvous.** On libp2p. Discovery = modified **Ethereum Discovery v5** (Kademlia
   DHT over UDP) + DNS-based discovery + libp2p peer-exchange. Default bootstrap = **Status-run
   "fleet" nodes** (free but centrally-run-in-practice; project intends to decentralize further).
   (https://docs.waku.org/learn/concepts/protocols/)
2. **NAT traversal.** Inherits libp2p transport; Waku-specific NAT docs not found — **UNVERIFIED**.
3. **Crypto/identity.** Relay = a **GossipSub** pub/sub extension for encrypted, censorship-resistant
   message flooding. App-level E2E (Status layers its own) — exact Waku identity/E2E model
   **UNVERIFIED** from fetched pages.
4. **Footprint.** nwaku (Nim), go-waku (Go), js-waku (JS/TS). **js-waku ≈ 7.55 MB** — heavy for
   "tiny." (https://www.npmjs.com/package/js-waku)
5. **License.** **MIT OR Apache-2.0** (permissive). (https://github.com/waku-org/js-waku)
6. **THE STEAL.** **GossipSub flood/pubsub** = battle-tested pattern for **group/broadcast**
   messaging without a coordinator. Permissive multi-impl core shows a portable path. *Avoid:*
   its "decentralized" story is currently a **centralized Status-run fleet**; ~7.5 MB bundle.

### Reticulum (RNS) ✅ (lead cross-checked)

1. **Discovery/rendezvous.** Coordination-less **"announce"** propagation across any attached
   interface (LoRa, packet radio, Wi-Fi, IP tunnels); self-healing multi-hop where a transport
   node knows only the **next hop, never the full path**. (https://reticulum.network/manual/whatis.html)
2. **NAT traversal.** Tunnels over existing IP; no explicit NAT-punch mechanism found — likely
   outbound-only interfaces sidestep NAT. **UNVERIFIED**.
3. **Crypto/identity.** **512-bit EC keyset = X25519 (ECDH) + Ed25519 (sign)**; ephemeral
   per-packet/per-link keys → forward secrecy; **no source addresses** → initiator anonymity;
   full encrypted+verified link setup in **3 packets / 297 bytes**. No PAKE/short-code layer.
   (https://reticulum.network/manual/whatis.html) — numbers **UNVERIFIED** (single primary source).
4. **Footprint.** Pure userland **Python 3**, no kernel deps; runs on Pi Zero-class hardware.
5. **License.** Custom **"Reticulum License"** (reference impl) + protocol public-domain since 2016
   — read exact terms before embedding. **UNVERIFIED** restrictions.
6. **THE STEAL.** **Next-hop-only routing + no source addresses** = anonymity-by-construction.
   **3-packet / 297-byte link setup** = a lean handshake efficiency target. *Avoid:* no MITM-proof
   short-code first-contact; custom license needs legal review.

### p2panda ✅ (lead-verified: confirmed built on iroh)

1. **Discovery/rendezvous.** `p2panda-net` **confidential topic discovery**: a **random-walk**
   algorithm finds nodes with **no centralized registry**; **Private Set Intersection** keeps a
   topic-of-interest from leaking to non-members. Gossip layer broadcasts to topic peers.
   (https://docs.rs/p2panda-net)
2. **NAT traversal.** **Built on iroh** — *"Most of the lower-level Internet Protocol networking
   of p2panda-net is made possible by the work of iroh"* ✅: **QUIC + self-cert TLS 1.3 + QUIC
   Address Discovery (QAD, STUN-like) + TURN relay fallback.** (https://docs.rs/p2panda-net)
3. **Crypto/identity.** BLAKE3 hashing, Ed25519 signing, CBOR, TLS/QUIC transport (data-type
   agnostic, any CRDT). No short-code PAKE first-contact — **UNVERIFIED** MITM-pairing story.
4. **Footprint.** Rust, modular crates (`p2panda-net`/`-discovery`/`-sync`), feature-flagged,
   ~20 direct deps. (https://crates.io/crates/p2panda-net)
5. **License.** **MIT OR Apache-2.0.** (https://crates.io/crates/p2panda-net)
6. **THE STEAL.** **Riding iroh instead of hand-rolling NAT traversal** — the single
   highest-leverage infra steal: a maintained, modern, permissively-licensed QUIC+relay stack we
   can depend on rather than reimplement the measured-70% hole-punch problem. **Confidential
   random-walk + PSI topic discovery** if we ever want "find peers interested in X" without
   leaking X. *Avoid:* still no human-code pairing — bring our own identity/first-contact layer on top.

### simple-peer + WebRTC signaling ecosystem ✅ (lead cross-checked)

1. **Discovery/rendezvous.** **Out of scope by design** — "responsibility of the app developer to
   get [SDP] to the other peer." Ecosystem fills it: PeerJS (hosted), WebTorrent trackers (P2PT),
   **p2pcf** (serverless signaling on **Cloudflare Workers + R2**, HTTP-poll with backoff, free
   tier). (https://github.com/feross/simple-peer, https://github.com/gfodor/p2pcf)
2. **NAT traversal.** Thin wrapper over native `RTCPeerConnection`: ICE server list (default Google
   + Twilio public STUN), trickle-ICE; **TURN must be supplied by the developer**. Free TURN
   exists: **Open Relay** (20 GB/mo free, ports 80/443/TURNS), **Cloudflare Realtime TURN**.
   (https://github.com/feross/simple-peer, https://www.metered.ca/tools/openrelay/, https://developers.cloudflare.com/realtime/turn/)
3. **Crypto/identity.** **None** — pure transport wrapper. Whatever SDP channel you pick is the
   MITM-exposed leg unless the app encrypts SDP itself.
4. **Footprint.** Pure JS, minimal deps, Node-stream API. Exact size **UNVERIFIED**.
5. **License.** MIT. (https://github.com/feross/simple-peer)
6. **THE STEAL.** **Signaling as a swappable transport concern, decoupled from the crypto core** —
   keep our hashkey-discovery layer pluggable across free-tier backends (tracker / Nostr /
   Cloudflare Worker). **p2pcf's serverless-on-free-cloud-primitives** is a cheap zero-maintenance
   fallback. *Avoid:* simple-peer offers nothing for identity/MITM — we must bake E2E into
   signaling, never leave it "developer's problem."

### croc — PAKE relay file transfer ✅ (lead cross-checked)

1. **Discovery/rendezvous.** Rendezvous *is* the shared code phrase — both sides dial the same
   relay and find each other by the phrase. (https://github.com/schollz/croc)
2. **NAT traversal.** **Relay-always** — even when a direct path exists, peers connect via the
   relay, which staples the two TCP connections. No STUN/ICE direct-connect upgrade. Self-hostable
   `--relay`. (https://redrocket.club/posts/croc/)
3. **Crypto/identity.** Identity = the ephemeral code phrase (no persistent pubkey). **SPAKE2**
   derives the shared key from the phrase without transmitting it → MITM-proof if the phrase went
   over a truly out-of-band channel. ⚠️ **CVE-2021-31603**: its SPAKE2 didn't validate curve points
   were on-curve → a rogue receiver could force weak points; patched. Secret passed via env var,
   not argv (avoids `ps` leak). (https://github.com/schollz/croc, https://github.com/schollz/pake)
4. **Footprint.** **Go, single static binary, no runtime deps** — the cleanest embeddability model
   here. (https://github.com/schollz/croc)
5. **License.** MIT. (https://github.com/schollz/croc)
6. **THE STEAL.** **PAKE-over-a-dumb-relay = identity + rendezvous + encryption in one step**, the
   closest prior-art *shape* to our shared-key model (though we skip PAKE — high entropy). **Go
   single-static-binary** distribution. **Env-var-not-argv secret hygiene.** *Avoid:* croc's
   **always-relay** (never attempts direct) burns relay bandwidth forever — we want direct-first,
   relay-fallback. And **validate curve points** from day one (don't repeat CVE-2021-31603).

---

## Comparison table

| System | Rendezvous | NAT traversal (measured) | Address/identity | E2E + first-contact MITM | Footprint | License |
|---|---|---|---|---|---|---|
| **iroh** | signed DNS/Pkarr + opt. Mainline DHT | QUIC relay hole-punch, **~90% direct** (self-rep.), free n0 relays | Ed25519 pubkey = address | QUIC/TLS1.3; MITM-proof (key=id) | Rust core, Py/Node/Swift/Kotlin bindings | Apache/MIT |
| **hyperswarm/HyperDHT** | Kademlia DHT, 32-byte topics, public bootstrap | UDP hole-punch (% UNVERIFIED) | Ed25519 pubkey = address | Noise; MITM-proof (key=id) | JS/Bare, modular | MIT |
| **magic-wormhole** | mailbox server (ciphertext relay) | direct-first, TCP transit relay | short code → SPAKE2 key | PAKE; MITM = 1 online guess/attempt | Python; simple to reimpl | MIT |
| **trystero** | borrowed infra: BitTorrent/Nostr/MQTT/IPFS/… | WebRTC ICE (~70–80% STUN, TURN→99%) | selfId + app/room id | AES-GCM; **MITM-able w/o shared secret** | TS, small, browser | MIT |
| **nostr** | free public relays (WebSocket) | n/a (client↔relay) | secp256k1 pubkey | NIP-44 + gift-wrap; MITM-proof if key known | protocol, tiny client | CC0/MIT |
| **libp2p** | Kademlia DHT + rendezvous | DCUtR, **70%±7.1% (4.4M-attempt study)** | PeerID = hash(pubkey) | Noise/TLS; MITM-proof (key=id) | Go/Rust/JS, large | MIT/Apache |
| **Jami/OpenDHT** | OpenDHT lookup by Jami ID, SFL bootstrap | ICE STUN/TURN (% UNVERIFIED) | RSA-4096 X.509, ID = fingerprint | DTLS+PFS; MITM-proof (ID=fingerprint) | OpenDHT C++ (embeddable); Jami Java | OpenDHT **MIT** / Jami **GPLv3** |
| **Tox** | onion-wrapped Kademlia DHT, public bootstrap | UDP hole-punch + volunteer TCP relay | Curve25519 pubkey (Tox ID) | NaCl, FS mandatory; MITM-safe if ID trusted | C + libsodium | ⛔ **GPLv3** |
| **Briar** | device-to-device (BT/Wi-Fi/Tor), Mailbox | Tor hidden services sidestep NAT | pre-shared pubkey; QR (BQP) pairing | Bramble; MITM-proof via QR commitment | Java/Android, bundles Tor | ⛔ **GPLv3** |
| **Waku** | libp2p DiscV5 + DNS + Status fleet | libp2p transport (UNVERIFIED) | app-layer (UNVERIFIED) | GossipSub relay; app E2E | Nim/Go/JS, **~7.5MB** | MIT/Apache |
| **Reticulum** | coordination-less announce, multi-hop | tunnels over IP (UNVERIFIED) | X25519+Ed25519 keyset | per-link FS; no PAKE pairing | pure Python, tiny HW | custom + PD |
| **p2panda** | random-walk + PSI confidential topics | **iroh** (QUIC+QAD+TURN) | Ed25519 + BLAKE3 | TLS/QUIC; pairing UNVERIFIED | Rust crates, ~20 deps | MIT/Apache |
| **simple-peer** | app's problem (p2pcf/PeerJS/trackers) | WebRTC ICE, dev-supplied TURN | none | none (app must add) | pure JS, minimal | MIT |
| **croc** | shared code phrase via relay | **relay-always** (no direct) | ephemeral code phrase | SPAKE2; MITM-proof if code OOB | Go static binary | MIT |

---

## Ranked "steal list" — proven mechanisms mapped to our constraints

1. **Address = the key itself (Ed25519 pubkey, or a fingerprint of it).** Converged on by
   iroh, hyperswarm, libp2p, Tox, Jami. Identity = address = MITM anchor in one object; no PKI/CA.
   Our 130-bit key → make it a **fingerprint of** the Ed25519 identity key (a full pubkey needs
   ~52 base32 chars, more than 26). → **Constraints #1, #2, #3.**
2. **Borrow existing free public networks as the rendezvous channel, behind a pluggable
   strategy** (trystero: Nostr relays / BitTorrent trackers / MQTT; nostr relays; hyperswarm's
   public DHT). Ship **multiple independent backends + a fallback chain** so no single operator's
   goodwill is load-bearing. → **Constraint #4** (the one nobody solves cleanly — see Gaps).
3. **Direct-first, capped-relay-fallback for NAT traversal — budget ~30% needing relay.**
   Ground truth: libp2p DCUtR **70%±7.1%** (independent, 4.4M attempts); iroh **~90%** (self-rep.,
   its own relay+DNS+QUIC). Copy the **DCUtR technique** (relay-coordinated simultaneous-connect)
   and **circuit-relay-v2 resource caps** (time+bytes) so donated relays can't be abused. Never
   copy croc's always-relay. → **Constraint #4.**
4. **Key-confirmation-by-decryption-success** (magic-wormhole `version` message): the first
   encrypted message *is* the MITM/wrong-key check — zero extra round trips. → **Constraint #3.**
5. **Metadata-hiding from v1** (nostr NIP-17 gift-wrap: disposable per-message keypair hides the
   sender over the relay hop). Design the message envelope like NIP-17, never like the deprecated
   metadata-leaking NIP-04. → privacy hardening of **#2/#3.**

*Runners-up worth keeping in view:* **MLS (nostr NIP-EE)** or **GossipSub (Waku)** for the
**groups** requirement (the least-solved part); **OpenDHT** as an MIT embeddable DHT primitive if
we want our own DHT; **Keet's mutable-DHT-records** as a coordinator-free presence/signaling channel;
Reticulum's **next-hop-only + no-source-address** routing for a future anonymity story.

---

## Recommendation: implementation language / runtime

**The honest framing (ponytail lens):** the framework's real value-add is the *26-char-hashkey
identity + rendezvous + group UX*. **NAT traversal is a commodity, and a measured-70%-hard research
problem** — hand-rolling it is where "tiny zero-dep" projects go to die. Decide by target surface:

- **If browser support is required (copy-paste key in a web app):** there is no raw UDP in the
  browser, so **WebRTC is the only P2P transport** → follow the **trystero pattern**: WebRTC data
  channels + borrowed free infra (Nostr/BitTorrent) for signaling. Do the identity/E2E layer with
  **WebCrypto** (X25519 + AES-GCM; or bundle a small **libsodium** for XChaCha20-Poly1305). **Node's
  built-in `crypto`/`webcrypto` has X25519 + ChaCha20-Poly1305**, so the same JS/TS core runs in
  Node and browser — one small codebase, genuinely embeddable. *This is the recommended path if the
  product is web-first.*
- **If native/CLI/desktop and you want the smallest self-contained artifact:** **Go** — `crypto/ecdh`
  (X25519) in stdlib + `golang.org/x/crypto/chacha20poly1305`, compiles to a **single static binary,
  no runtime deps** (croc is the exact precedent: Go, MIT, PAKE, one binary). Cost: you inherit
  hand-rolling hole-punch (the hard 70% part).
- **If you want the best NAT traversal for the least work and can accept one dependency:** **build the
  thin identity/rendezvous/group layer on top of iroh** (Rust core; **stable Python/Node/Swift/Kotlin
  bindings**; ~90% direct; free relays; Ed25519 dial-by-key already *is* our address model).
  **p2panda proves this composition works** (it is "made possible by the work of iroh"). "Zero-dep"
  becomes "one dep — but the right one," and we skip reimplementing QUIC + relay + hole-punch.
- **Avoid GPLv3 stacks** (Tox, Briar, Jami-app) if the framework must be permissively embeddable —
  they are copyleft poison pills. Permissive precedent: iroh, hyperswarm, magic-wormhole, trystero,
  nostr, OpenDHT, Waku, p2panda, croc (all MIT/Apache/CC0).

**Python is a poor fit** for the core: its stdlib lacks modern AEAD/ECDH (you'd depend on
`cryptography`/`PyNaCl` anyway, killing "zero-dep"), and it's neither browser-capable nor a lean
single-binary target. Fine only for a reference/prototype.

**Bottom line:** pick by whether **browser reach** is a hard requirement. If yes → **JS/TS on
WebCrypto + WebRTC + borrowed-infra signaling (trystero pattern)**. If no and NAT-traversal quality
matters more than dependency purity → **thin layer over iroh**. If a single tiny native binary is the
priority → **Go**. In all three, **the 26-char key = fingerprint of an Ed25519 identity key**, and we
**do not implement PAKE** (our secret is already high-entropy).

---

## Gaps — where NO prior art solves our full constraint set

1. **No single system combines all of:** high-entropy copy-paste key **+** truly no-owned-infra **+**
   browser-capable **+** tiny/zero-dep **+** groups. Each surveyed system solves a *subset*; our
   framework's novelty is the *combination*, and it must be assembled, not adopted.
2. **Durable rendezvous on multi-operator free infra.** Every system leans on **one operator's**
   goodwill: n0's relays/DNS, Holepunch's bootstrap, wormhole's author-run relay, Status's fleet,
   Jami's SFL bootstrap. The closest to a hedge is **trystero's borrow-multiple-networks**, but each
   backend (Nostr relay, BitTorrent tracker) is still someone's donated service. **A resilient
   multi-operator fallback chain for our key→address rendezvous is unbuilt — we must build it.**
3. **Long-lived reusable key + MITM safety.** magic-wormhole's "one guess per attempt" safety
   *depends on single-use codes*. A **long-lived, repeatedly-shared 26-char key** gives an attacker
   many independent guesses over time. Since we (correctly) skip PAKE, the analogous risk is a
   **leaked/observed key** — but **key rotation, revocation, and rendezvous rate-limiting** for a
   long-lived shared key is **not provided by any surveyed system** and is ours to design.
4. **Serverless group discovery + group E2E in a tiny package.** Building blocks exist (nostr
   **NIP-EE/MLS**, Waku **GossipSub**) but **not** in a small zero-dep form; groups (forward secrecy,
   membership changes, post-compromise security) are the **least-solved** requirement.
5. **Browser ↔ native interop in one tiny lib.** Browser P2P = WebRTC; native P2P = QUIC/raw UDP.
   No small library bridges both transports without heavy deps. If the product needs both a web app
   and native peers talking *to each other*, that bridge is an open build problem (likely a shared
   relay/gateway speaking both).
6. **Confidential rendezvous (hide *which key* is being looked up).** Only Tox (onion-wrapped DHT
   queries) and p2panda (PSI topic discovery) address "don't reveal who searches for whom," and
   neither is a drop-in for our model. If rendezvous-metadata privacy is a goal, this is largely
   greenfield for us.

---

## Sources (primary, load-bearing)

- iroh: https://docs.iroh.computer/concepts/discovery · https://docs.iroh.computer/about/faq · https://www.iroh.computer/blog/v1 · https://github.com/n0-computer/iroh/issues/2317
- hyperswarm/HyperDHT: https://github.com/holepunchto/hyperswarm · https://github.com/holepunchto/hyperdht
- magic-wormhole: https://magic-wormhole.readthedocs.io/en/latest/welcome.html · https://github.com/magic-wormhole/magic-wormhole-protocols/blob/main/client-protocol.md · https://github.com/magic-wormhole/magic-wormhole-protocols/blob/main/server-protocol.md
- trystero: https://github.com/dmotz/trystero · https://webrtc.ventures/2022/04/ice-in-webrtc/
- nostr: https://github.com/nostr-protocol/nips/blob/master/01.md · https://nips.nostr.com/17 · https://nips.nostr.com/44 · https://nips.nostr.com/ee · https://github.com/nostr-protocol/nips/blob/master/04.md
- libp2p: https://arxiv.org/html/2510.27500v1 · https://arxiv.org/abs/2604.12484 · https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md · https://github.com/libp2p/specs/blob/master/rendezvous/README.md · https://github.com/libp2p/rust-libp2p
- Jami/OpenDHT: https://github.com/savoirfairelinux/opendht · https://docs.jami.net/en_US/user/jami-distributed-network.html
- Tox: https://github.com/TokTok/c-toxcore/blob/master/LICENSE · https://wiki.tox.chat/users/techfaq
- Briar: https://briarproject.org/how-it-works/ · https://code.briarproject.org/briar/briar-spec
- Waku: https://docs.waku.org/learn/concepts/protocols/ · https://github.com/waku-org/js-waku · https://www.npmjs.com/package/js-waku
- Reticulum: https://reticulum.network/manual/whatis.html
- p2panda: https://docs.rs/p2panda-net · https://crates.io/crates/p2panda-net
- simple-peer/ecosystem: https://github.com/feross/simple-peer · https://github.com/gfodor/p2pcf · https://www.metered.ca/tools/openrelay/ · https://developers.cloudflare.com/realtime/turn/
- croc: https://github.com/schollz/croc · https://github.com/schollz/pake · https://redrocket.club/posts/croc/
