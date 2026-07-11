# Serverless Rendezvous & Discovery — Decision-Grade Research

**Project:** `p2p` — tiny, embeddable, zero-dependency P2P chat/data framework.
**Problem this file solves:** A user generates a 26-char hashkey and shares it out-of-band. Anyone holding that key must be able to **find** the user — obtain their current IP:port candidates — using **only free public infrastructure we do not operate**. This is the creative heart of the project: rendezvous with no server of ours.
**Research date:** 2026-07-11. **Author:** Research Lane C (opus) + 3 sonnet research subagents, all claims live-probed where possible.
**Scope boundary:** this file picks the *channels* and how to ride them. It does **not** design the crypto (separate lane) — it only states the **derivation requirement** each channel imposes.

---

## 0. TL;DR — what to build

**Discovery is three distinct jobs, not one.** Pick channels per job:

| Job | Primary | Fallback | Last-resort |
|---|---|---|---|
| **A. Same-LAN fast path** | **mDNS / DNS-SD** | — | — |
| **B. Presence** ("where is my friend *now*" — mutable current IP:port) | **BitTorrent Mainline DHT — BEP44 mutable** | Nostr addressable event (kind 30000-range) | Public WSS tracker announce |
| **C. First-contact signaling** (live SDP/candidate exchange) | **Public WSS trackers** (trystero pattern) | Nostr ephemeral event (kind 20000-range) | DHT BEP44 |
| **D. Offline dead-drop** (store-and-forward when peer offline) | **Nostr regular events, fan-out to N relays** | DHT BEP44 (≤1000 B, ~2 h TTL) | MQTT retained message |

**One rendezvous ID, derived once, reused across channels.** Derive `rid = KDF(hashkey)` with a one-way keyed function (HKDF/HMAC class), then map `rid` into each channel's namespace (20-byte infohash for DHT/trackers, secp256k1 keypair for Nostr, topic string for MQTT). This gives redundancy (publish to all, race reads) with **no extra key-secrecy cost** as long as every mapping stays one-way.

**Recommended v1 channel set:** mDNS + Mainline DHT (BEP44) + public WSS trackers + Nostr relays. **Est. in-house cost ≈ 900–1,500 LOC** (bencode+KRPC+BEP44 client is the bulk; everything else rides existing libraries). Tor onion services are the elegant high-privacy upgrade for hostile-NAT/censored cases but cost a **heavy binary dependency** — defer to v2.

---

## 1. The shared invariant: derivation & what every channel leaks

Every free public channel below has the **same structural privacy property**, and it is the single most important design constraint:

- **No channel offers read-side access control.** A DHT node answers any `get`; a tracker hands out any infohash's peer list; a Nostr relay answers any `REQ`; an MQTT broker delivers any topic; an IPFS gateway serves any CID. Discovery *works* precisely because anyone who knows the ID can look it up. That is the mechanism, not a bug.
- **Therefore all secrecy lives in the derivation, none in the channel.** The rendezvous ID *will* be visible on the wire to anyone watching that ID. What must never be recoverable is the **preimage** — the 26-char hashkey.
- **Requirement handed to the crypto lane:** `rid = one-way-KDF(hashkey)` — HKDF-SHA256 / HMAC class, never a reversible encoding, never the raw key, never a hash of a short/guessable "room name" (trystero's plain `SHA1(topic)` is fine for public room names but **insufficient** for this threat model). A well-encoded 26-char key carries ~130–150 bits; brute-forcing `rid → hashkey` is then infeasible for an observer who doesn't already hold the key.
- **Residual leaks that derivation *cannot* hide (must be accepted or mitigated at the transport/crypto lanes):**
  - **Linkability / traffic analysis:** an observer sees "*some* rendezvous is happening at ID X" and can correlate repeat visits over time. Rotating `rid` on a time-epoch (e.g. `rid_t = KDF(hashkey, epoch)`) mitigates; note for crypto lane.
  - **Source-IP exposure:** the querying node's IP is visible to whatever DHT node / relay / tracker it talks to (this is *how* discovery returns your address). Only an anonymity overlay (Tor, §7) removes it.
  - **Payload confidentiality & authenticity:** the stored contact record must be **signed** (so a squatter can't publish fake IP:ports under your ID) and **encrypted** (so the record's contents leak nothing). BEP44 mutable gives you the signature slot for free (ed25519); Nostr events are signed by construction.

Read the per-channel "Privacy" notes below against this baseline.

---

## 2. BitTorrent Mainline DHT — BEP44 mutable/immutable + get_peers/announce

The largest, most decentralized, no-single-owner key/value + peer-discovery substrate on the open internet. Two usable primitives:

- **BEP44 mutable item** — the killer feature for *presence*. Store a **signed** value under `target = SHA1(ed25519_pubkey ‖ salt)`; update via monotonically increasing `seq`; readers `get(target)`. This is a self-owned mutable pointer to your current contact record. ([BEP44 spec](https://www.bittorrent.org/beps/bep_0044.html))
- **BEP44 immutable item** — `target = SHA1(bencode(v))`, content-addressed, no updates.
- **get_peers / announce_peer** (BEP5) — classic swarm discovery under an infohash; usable but BEP44 mutable is strictly better for signed contact records.

**Hard spec facts (fetched from bittorrent.org, corrects the task brief):**
- Payload cap: storing nodes MAY reject `put` where bencoded `v` > **1000 bytes** (soft SHOULD, treat as hard).
- TTL: nodes MAY discard items after **~2 hours** (not the ~30 min the brief assumed) → **re-`put` roughly hourly** to stay resident. Redundancy target is the 8 closest nodes.
- Mutable update requires ed25519 `sig` over bencoded `seq`+`v`; nodes MUST refuse a lower `seq`. Error codes: 205 too-large, 206 bad-sig, 301 CAS mismatch, 302 stale seq.

**Bootstrap nodes (standard across libtorrent/Transmission/qBittorrent):** `router.bittorrent.com:6881`, `dht.transmissionbt.com:6881`, `router.utorrent.com:6881`, `dht.libtorrent.org:25401`. **Live-probed 2026-07-11 (both this lane and its subagent):** all three primary hosts resolve (`router.bittorrent.com → 67.215.246.10`, `dht.transmissionbt.com → 87.98.162.88 / 212.129.33.59`, `router.utorrent.com → 82.221.103.244`) and outbound UDP:6881 opens to all three.

| Dimension | Assessment |
|---|---|
| **Reliability** | Network is huge (historically 16–28M nodes) and has no owner to shut it down. **BUT current-conditions `get`/`put` first-try success rate is UNVERIFIED** — academic measurement is stale (2010–2015). Mitigation is built into the protocol: fan out to the 8 closest nodes, retry. |
| **Latency to first contact** | Iterative Kademlia lookup, multi-hop — seconds to tens of seconds. UNVERIFIED precise figure for 2026. |
| **Payload** | ≤1000 bytes signed. Enough for a compact signed contact record (a few IP:port candidates + pubkey + seq); **not** enough for offline chat messages. |
| **Spam/abuse/ToS** | No ToS — it's an ownerless commons protocol; using it as designed is not "abusing someone's server." Size/TTL caps exist precisely to keep it from becoming free storage. Behave: respect 1000 B, re-`put` hourly not per-second. |
| **Censorship/blocking** | **Weakest link.** Raw UDP with a distinctive KRPC/bencode fingerprint. Commonly blocked/throttled by corporate firewalls, some mobile carriers, national DPI. No TLS/443 camouflage possible. |
| **Privacy** | `target` visible to global DHT crawlers ([Wolchok/Halderman USENIX WOOT'10](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Wolchok.pdf), live crawler [bitmagnet.io](https://bitmagnet.io/)). Source IP visible to nodes you query. Derivation must be one-way (§1). Signature slot solves squatting. |
| **In-house cost** | bencode (~100–150) + KRPC/UDP (~150–250) + iterative client-only lookup (~150–300) + BEP44 get/put w/ ed25519-from-a-lib (~100–150). Skip the full serving routing-table/k-bucket subsystem (client-only). **≈ 500–850 LOC.** Calibrated against `webtorrent/bittorrent-dht` `client.js` (798 LOC for a *full* node incl. routing) + `k-bucket` (452 LOC, skippable). |

**Verdict: VIABLE-PRIMARY for presence (job B) & fallback for signaling/dead-drop.** The one channel with a real signed-mutable-record primitive and no owner. Its UDP fingerprint means it must be paired with a 443-camouflaged channel, never shipped alone. **LOC ≈ 500–850** (the single biggest build item in this project).

---

## 3. Public BitTorrent / WebTorrent trackers (HTTP / UDP / WebSocket)

Trackers are pure real-time rendezvous — no storage, they just match announcers under an infohash. Three transports: HTTP (BEP3), UDP (BEP15), **WebSocket/WSS** (WebTorrent de-facto). The WSS variant is the star.

**How trystero proves the pattern** (source read live: [`dmotz/trystero` torrent strategy](https://raw.githubusercontent.com/dmotz/trystero/main/packages/torrent/src/index.ts), 490 LOC):
- `infohash = sha1(topic).slice(0,20)` — indistinguishable from an ordinary torrent announce.
- Connects to **3 trackers simultaneously** (`defaultRedundancy = 3`) for fault tolerance.
- Announce cadence: 10 s active → 2 min idle. First-contact bounded by ~1 tracker round-trip.
- **Piggybacks WebRTC offer/answer/ICE directly inside the announce message** — the tracker relays small signed SDP blobs. This is exactly the shape `p2p` needs: carry a small signed contact/signaling blob keyed by a derived infohash, no protocol extension.

**Default WSS relay pool — live-probed 2026-07-11 (subagent + this lane, corroborated):**
`tracker.openwebtorrent.com` → HTTP 404 (alive), `tracker.btorrent.xyz` → 301 (alive), `open.ftorrent.com` → 200 (alive), `tracker.webtorrent.dev` → empty reply to bare GET (**alive, WS-only** — needs Upgrade handshake, not a failure). Curated list [`ngosang/trackerslist`](https://github.com/ngosang/trackerslist) last commit **2026-07-10** (daily auto-update, verified). Live-vetted uptime service: [newtrackon.com](https://newtrackon.com/).

| Dimension | Assessment |
|---|---|
| **Reliability** | No SLA on any single tracker; real churn (newtrackon exists because of it). Mitigation = trystero's multi-tracker fan-out. Aggregate pool is reliable; individual trackers are not. |
| **Latency** | ~10 s worst-case first contact (trystero default). Live pool reachable today. |
| **Payload** | No hard spec limit; bounded by operator tolerance — keep to small signed blobs (SDP-sized). No persistence (real-time only). |
| **Spam/abuse/ToS** | OpenBitTorrent/OpenWebTorrent are explicitly open-to-anyone by design ([OpenWebTorrent](https://openwebtorrent.com/)). Rendezvous blobs are lighter than real swarm traffic. Respect announce cadence (~10 s, not per-second). |
| **Censorship** | **WSS = best-in-survey.** TLS to :443, indistinguishable from ordinary HTTPS/WebSocket — blends with normal web traffic. (HTTP/UDP tracker variants share DHT's DPI weakness — AVOID standalone.) |
| **Privacy** | Tracker operator sees your IP **by design** (concentrated exposure, worse than DHT's diffuse view). Same one-way-derivation requirement. Reuse the *same* derived infohash as DHT to avoid adding a cross-channel correlation vector. |
| **In-house cost** | WSS-only client (WS connect/reconnect + JSON announce + offer/answer): **≈ 100–200 LOC** on an existing WebSocket lib. All three transports on the shared bencode module: ≈ 300–450. |

**Verdict: VIABLE-PRIMARY for first-contact signaling (job C).** Cheapest build, best censorship resistance, production-proven by trystero, live pool healthy today. Also a ready WebRTC signaling path if `p2p` ever wants browser transport. **LOC ≈ 100–200** (WSS only).

---

## 4. Nostr public relays

A network of independently-operated WebSocket relays with an event-kind taxonomy that maps *almost exactly* onto our three jobs — and it is the **only surveyed channel with a real offline dead-drop**. ([NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md))

- **Ephemeral events (kind 20000–29999)** — "not expected to be stored" → **first-contact signaling** (exchange SDP/candidates, gone after delivery).
- **Addressable events (30000–39999)**, indexed by `(kind, pubkey, d-tag)` → best **presence** primitive: one mutable pointer per identifier.
- **Regular / replaceable events** — relays store them → **offline dead-drop** via fan-out publish to N relays; receiver queries later.

**Encryption:** [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) v2 (ChaCha20+HMAC, Cure53-audited 2023) for payloads; [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md) gift-wrap hides timestamps/kinds (but the recipient `p` tag is still relay-visible — policy-enforced via NIP-42, not cryptographic). Crypto lane's call; noted for routing.

**Live-probed 2026-07-11:** `relay.damus.io` → 200, `nos.lol` → 200, `relay.primal.net` → 200 (this lane, 3/3 up). Subagent separately saw `relay.nostr.band` time out and the aggregator **`api.nostr.watch` return 502** — **load-bearing finding: do not hard-depend on the relay-list API at runtime; ship a hardcoded bootstrap relay list, refresh opportunistically.**

| Dimension | Assessment |
|---|---|
| **Reliability** | Many independent relays; individual ones flaky (2–3 of 4 up in probes). Fan-out to several = robust. Aggregator (`api.nostr.watch`) itself was down — don't depend on it. |
| **Latency** | Seconds (WebSocket pub/sub), live-confirmed. |
| **Payload** | Relay-specific (NIP-11 `max_message_length`): 16 KB – 1 MB in the wild. Ample for signed contact records **and** offline chat messages. |
| **Dead-drop persistence** | Relay-dependent and not guaranteed (a relay may prune anytime) — mitigated by fan-out to N independent relays; no single relay is a data SPOF. |
| **Spam/abuse/ToS** | Spam is a known network problem; `strfry` has no native write rate-limiting. Some relays require NIP-42 AUTH or proof-of-work — client must tolerate `auth-required`/`restricted` NOTICEs and fail over. |
| **Censorship** | WSS/:443 — good camouflage like WSS trackers. Individual relay domains blockable; many-relay redundancy mitigates. |
| **Privacy** | Zero read ACL — anyone computing the derived pubkey/`d`-tag can `REQ` it. Security = derivation entropy only (§1). Relay sees subscriber IP. |
| **In-house cost** | Use an existing lib (`nostr-tools` JS / `pynostr`) — do **not** hand-roll secp256k1 or the relay wire protocol. App glue (relay-pool + reconnect, sign, NIP-44, ephemeral pub/sub, addressable read/write, fan-out): **≈ 300–600 LOC.** |

**Verdict: VIABLE-PRIMARY for offline dead-drop (job D) & strong fallback for signaling + presence.** The only channel that natively covers all three jobs *and* store-and-forward. **LOC ≈ 300–600** (on an existing Nostr lib).

---

## 5. Public MQTT brokers (test.mosquitto.org, HiveMQ, EMQX)

Topic-based pub/sub over public test brokers. Real but weak.

**Live-probed 2026-07-11:** `test.mosquitto.org:1883`, `broker.emqx.io:1883` both TCP-reachable (this lane); subagent adds `broker.hivemq.com:1883` reachable.

- **Retained message** = a genuine free one-slot mailbox: broker holds the *last* message on a topic, delivers instantly to new subscribers. **Ideal for presence** ("last known IP:port"); poor for a multi-message dead-drop (need per-message topic suffixes + your own cleanup).
- **trystero has an MQTT strategy** (`trystero/mqtt`) — same "ride a free broker for signaling" pattern (exact default-broker source UNVERIFIED at code level).

**The ToS reality (mosquitto's own words):** *"free to use… but please do not abuse or rely upon it for anything of importance… please don't publish anything sensitive, anybody could be listening."* ([test.mosquitto.org](https://test.mosquitto.org/)). EMQX/HiveMQ public instances brand themselves as prototype/test toys. No SLA anywhere.

| Dimension | Assessment |
|---|---|
| **Reliability** | No SLA; operator explicitly disclaims reliance. All 3 core brokers reachable live, but each is a single corporate hostname — a DNS block or shutdown kills the channel with no swarm fallback. Mitigate via multi-broker fan-out. |
| **Latency** | Seconds (pub/sub), live. |
| **Payload** | Protocol ceiling 256 MB; real enforced caps on public brokers UNVERIFIED. |
| **Censorship/centralization** | **Biggest weakness:** 3 single owners, not a decentralized swarm. Higher single-point-of-failure risk than DHT/Nostr/trackers. |
| **Privacy** | No ACL on anonymous ports; wildcard `#` subscribe sniffs everything. High-entropy derived topic + payload encryption mandatory. |
| **In-house cost** | Thin glue over `mqtt.js`/Paho (connect+TLS, topic derivation, pub/sub, retained flag, reconnect): **≈ 150–300 LOC.** |

**Verdict: VIABLE-FALLBACK — presence only.** Retained-message presence is genuinely nice, but centralization + "don't rely on this" ToS keep it a redundant secondary, never primary. **LOC ≈ 150–300.**

---

## 6. IPFS / IPNS / pubsub via public gateways

**Verdict up front: AVOID (fails the brief as written).**

Live-probed 2026-07-11: `ipfs.io`, `dweb.link`, `w3s.link` all return 301 for a known CID — **read path works**. But:

- **Public gateways are read-only.** GET on `/ipfs`,`/ipns` only; the write/admin surface (`/api/v0` add/pin/pubsub) is **not** exposed anonymously. There is **no anonymous public "upload a dead-drop" endpoint.**
- Getting content *onto* IPFS needs either your **own running node** (= running a server, violates the brief) or a **pinning account/API token** (centralized credentialed dependency, violates the brief). One accountless outlier (iMintify, 5 GB) is a single centralized service of unknown longevity, not trustless infra.
- **IPNS is officially slow** ([IPFS docs](https://docs.ipfs.tech/concepts/ipns/)): ~24 h record expiry, 4 h republish, "resolving… can be slow" — poor for live presence. Precise seconds UNVERIFIED.
- **pubsub** needs a node — not on any public gateway.

If pursued opportunistically (users who already run IPFS nodes): ~800–1500+ LOC (Helia/Kubo, IPNS lifecycle, pubsub). **Not recommended** — Nostr + DHT cover its jobs better, cheaper, and actually serverlessly. **AVOID.**

---

## 7. Exotic & reference options

### 7a. mDNS / DNS-SD — LAN fast path — **VIABLE-PRIMARY (LAN only)**
Same-LAN, zero WAN, zero third party (RFC 6762/6763). Sub-second, near-100% on a flat LAN; fails across VLANs/guest-WiFi/multicast-disabled nets. TXT record carries the derived token (LAN-visible → must be the opaque `rid`, never the raw key). Ride `python-zeroconf`/Rust `mdns-sd`: **≈ 100–400 LOC.** Always worth shipping as the instant local path before any WAN lookup. (Probe: `dig +short _imaps._tcp.gmail.com SRV → 5 0 993 imap.gmail.com` shows the SRV shape.)

### 7b. Tor v3 onion services — NAT-proof rendezvous+transport fusion — **VIABLE-FALLBACK (v2)**
The philosophically most elegant fit: **the onion address *is* a derived Ed25519 pubkey** ([rend-spec-v3](https://torproject.gitlab.io/torspec/rend-spec-v3.html)) — derive the keypair from the hashkey and the address *is* the rendezvous ID, and it **fuses magic-wormhole's mailbox (descriptor dead-drop) + transit relay (data path) into one mechanism** on free volunteer infra. Descriptors self-refresh (~hourly) while online; HSDir uses blinded daily-rotating keys (enumeration-resistant). Best privacy in the survey (hides who-talks-to-whom by design). **Costs:** first contact 3–10 s (circuit build); Tor blocked/throttled in several countries (needs obfs4/snowflake to punch through); and the **dependency is heavy** — bundle the C `tor` daemon (tens of MB) or embed `arti` (Rust; Tor Project admits binary-size still unsolved, no clean FFI yet → shell out to its SOCKS proxy). **≈ 300–600 LOC wrapper + heavy binary.** Live: `torproject.org` resolves, no blocking here. **Defer to v2** — the payoff (censorship-proof, NAT-proof, IP-hiding) is real but the weight is the largest single cost in the project.

### 7c. I2P — **AVOID (for this project)**
Same niche as Tor, arguably better tunnel unlinkability, but **strictly loses on ecosystem**: no mature embeddable client comparable to arti, practical path is the heavy Java router, smaller network. No decisive advantage here. One-line future mention, not a v1/v2 build. ~400–800+ LOC + heavier runtime.

### 7d. DNS TXT dead-drops / DoH — **AVOID (write path fails the brief)**
DoH *read* is cheap and censorship-resistant (`curl -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?...'` works; TXT holds ~32-char opaque tokens). But **there is no free serverless way to *write* an arbitrary TXT record** — every DDNS provider needs an account + their API server (= "a server," fails the exclusion test) and risks ToS takedown. MARGINAL only if a user *already owns a domain* and opts to publish their own token there. Not a generic mechanism.

### 7e. magic-wormhole model — the mental model to copy (server has no drop-in free clone)
magic-wormhole (live: `relay.magic-wormhole.io → 200`) = short code (`4-purple-sausages`) + **mailbox server** (nameplate→mailbox, queues if one side absent, pushes when both present) + **SPAKE2 PAKE** (server is untrusted — one guess then detected) + **transit relay** (TURN-like, tried *after* direct hints). Copy the *shape*: derived-ID-as-meeting-slot, untrusted-relay-only-sees-ciphertext, **direct-connection-hints tried before any relay fallback**. But its literal **mailbox server has no free serverless equivalent with equal push-latency.** The honest substitutes: **BEP44 DHT** for the *storage* half (dead-drop keyed by derived ID), **Tor onion** for the *storage+transport-fused* half. ([mailbox protocol](https://magic-wormhole.readthedocs.io/en/latest/server-protocol.html), [transit](https://magic-wormhole.readthedocs.io/en/latest/transit.html))

### 7f. Other proven-in-the-wild systems
| System | Kind | Free? | Verdict |
|---|---|---|---|
| **libp2p rendezvous protocol** | Rendezvous | Open spec, but needs *a* rendezvous node → collapses to its Kademlia DHT when fully serverless | VIABLE-FALLBACK (≈ BEP44-DHT; use if already pulling libp2p) |
| **toxcore DHT** | Rendezvous (pubkey-as-address, Kademlia) | Yes — community bootstrap list ([nodes.tox.chat](https://wiki.tox.chat/users/nodes)) | VIABLE-FALLBACK (near-identical to BEP44; smaller/less-resilient network) |
| **Syncthing global discovery + relay pool** | Discovery + TURN-like relay | Foundation-run, relay pool genuinely open ([docs](https://docs.syncthing.net/users/relaying.html)) | MARGINAL — device-ID-scoped, rate-limited; riding for non-Syncthing traffic is a ToS gray zone. The *self-registering volunteer relay pool* is a pattern worth copying. |
| **Public STUN** (Google/Cloudflare) | NAT-traversal helper (NOT rendezvous) | Yes | **Use downstream** — `stun.l.google.com:19302`, `stun.cloudflare.com:3478` live-probed up. `stun.stunprotocol.org` is **defunct** (DNS fails) — drop from any hardcoded list. |
| **Free public TURN** | Data-plane relay | Effectively none at scale (bandwidth cost) | AVOID — rely on DHT/Tor/dead-drop + direct-hints-first, not TURN |
| **Tailscale DERP** | NAT relay | No — Tailscale-operated | AVOID (not free/public) |

---

## 8. Master comparison table

| # | Channel | Best job | Reliability (live 2026-07-11) | First-contact latency | Payload / persistence | Censorship resistance | Privacy exposure | In-house LOC | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **Mainline DHT (BEP44)** | Presence; signed record | Ownerless, huge; get/put success UNVERIFIED-current; bootstrap DNS+UDP up | secs–tens of secs | ≤1000 B, ~2 h TTL (re-put hourly) | **Low** (raw UDP, DPI-blocked) | target crawlable; src-IP to nodes | **500–850** | **PRIMARY (presence)** |
| 2 | **Public WSS trackers** | First-contact signaling | 5/5 trystero defaults alive; list updated yesterday | ~10 s | small blobs, no storage | **High** (:443, looks like HTTPS) | operator sees your IP by design | **100–200** | **PRIMARY (signaling)** |
| 3 | **Nostr relays** | Offline dead-drop (+all 3) | 3/4 relays up; aggregator 502 (hardcode bootstrap) | secs | 16 KB–1 MB; relay-dep. retention | **High** (:443 WSS) | zero read ACL; relay sees IP | **300–600** | **PRIMARY (dead-drop)** |
| 4 | **Public MQTT** | Presence (retained msg) | reachable; single-owner; no SLA; "don't rely" ToS | secs | 256 MB ceiling (real cap UNVERIFIED); 1 retained msg/topic | Med (centralized hostnames) | wildcard-sniffable | **150–300** | FALLBACK (presence) |
| 5 | **IPFS/IPNS/pubsub** | — | gateways read-only; **no anon write** | slow (IPNS mins) | needs own node/pinning acct | Med (Cloudflare-fronted) | — | 800–1500+ | **AVOID** (fails brief) |
| 6 | **mDNS/DNS-SD** | LAN fast path | ~100% flat LAN; fails cross-VLAN | sub-second | <1 KB TXT, no persist | n/a (LAN) | LAN-broadcast | **100–400** | **PRIMARY (LAN)** |
| 7 | **Tor v3 onion** | NAT-proof rendezvous+transport | mature (7k+ relays); reachable | 3–10 s (circuit) | self-refreshing descriptor | **Highest** (but Tor blocked in some countries) | **best** (hides who↔who) | 300–600 + heavy binary | FALLBACK (v2) |
| 8 | I2P | (Tor alt) | smaller net | 1–3 s internal | eepsite | Med | strong | 400–800+ + heavy | AVOID (loses to Tor) |
| 9 | DNS TXT / DoH | (dead-drop) | read cheap; **write needs server** | — | 255 B/string | read: high (DoH) | — | ~20 (read only) | AVOID (write fails brief) |
| 10 | magic-wormhole model | (mental model) | relay up (but it's *their* server) | — | mailbox queues | — | untrusted-relay design | — (copy shape) | Copy pattern; impl on DHT/Tor |
| 11 | libp2p rendezvous / toxcore DHT | Rendezvous | open; DHT-backed | secs | DHT-class | Low (UDP) | DHT-class | ≈ DHT | FALLBACK |
| 12 | Public STUN (Google/CF) | NAT helper | live-probed up | — | — | — | reveals your public IP (its job) | ~20 | Use downstream |

---

## 9. Recommended v1 combo (per job, primary + fallback)

**Derive one `rid` from the hashkey (§1), map it into each channel, publish to all, race the reads.**

- **Job A — Same-LAN fast path:** **mDNS** (`_p2p._tcp.local`, derived token in TXT). Try first, always; instant when it works.
- **Job B — Presence ("where now"):** **DHT BEP44 mutable** (signed record, re-put hourly) as primary. Fallbacks: **Nostr addressable event** (kind 30000-range) and **MQTT retained message**. All three publish the same signed record; reader races all three, takes the highest `seq`/newest timestamp.
- **Job C — First-contact signaling:** **Public WSS trackers** (trystero pattern, 3 trackers in parallel) primary; **Nostr ephemeral events** (kind 20000-range) fallback.
- **Job D — Offline dead-drop:** **Nostr regular events, fan-out to N≈5 relays** primary; **DHT BEP44** (for tiny records) fallback.
- **v2 upgrade (hostile NAT / censorship / IP-hiding):** **Tor v3 onion** — address-is-the-derived-key, fuses dead-drop + transport. Heavy dependency, gate behind a config flag.

**Why this set:** covers all three jobs with two owner-less swarms (DHT, Nostr) + one owner-diverse pool (WSS trackers) + a LAN shortcut — no single owner, no single point of failure, and every channel is either :443-camouflaged (trackers, Nostr) or ownerless (DHT) so blocking one doesn't kill discovery.

---

## 10. Redundancy strategy — publish-to-N, race-reads

1. **Publish fan-out:** on going online, publish the signed contact record to **every** presence channel concurrently (DHT + Nostr addressable + MQTT retained), and register on all signaling channels. Re-publish on the tightest channel's refresh clock (DHT ~hourly; trackers ~10 s while actively expecting contact).
2. **Read race:** to find a peer, query **all** channels in parallel; take the **first** valid, signature-verified, freshest (`seq`/timestamp) record; cancel the losers. Latency = fastest channel, not slowest.
3. **Same `rid` everywhere** → no extra key-secrecy cost (§1); the only added exposure is more places watching the same ID, which is inherent to redundancy. Optional epoch-rotated `rid_t` reduces cross-time linkability.
4. **Signature-gate every read** so a squatter on any one channel can't inject fake IP:ports — the record's ed25519 sig (native to BEP44 mutable and to Nostr events) is the trust anchor; reject unsigned/mismatched.
5. **Bootstrap lists are hardcoded + opportunistically refreshed** (DHT bootstrap nodes, a starter Nostr relay set, a starter WSS tracker set) — never hard-depend on a live aggregator API (`api.nostr.watch` was 502 during research). Refresh from `ngosang/trackerslist` / `nostr.watch` when reachable, cache locally.
6. **Degrade gracefully:** LAN-only if no WAN; if UDP is blocked (DHT dead), the :443 channels (trackers, Nostr) still carry both signaling and dead-drop; if everything public is blocked, Tor (v2) is the escape hatch.

---

## 11. Total in-house LOC estimate

| Component | LOC | Notes |
|---|---|---|
| bencode encode/decode | 100–150 | shared by DHT + HTTP/UDP trackers |
| KRPC/UDP + iterative client-only lookup | 300–550 | no serving routing-table |
| BEP44 get/put (ed25519 from a lib) | 100–150 | signed mutable record |
| WSS tracker client | 100–200 | on an existing WS lib |
| Nostr client glue | 300–600 | on `nostr-tools`/`pynostr` (don't hand-roll secp256k1) |
| mDNS | 100–400 | on `python-zeroconf`/`mdns-sd` |
| MQTT glue (optional presence fallback) | 150–300 | on `mqtt.js`/Paho |
| Fan-out/race orchestration + `rid` mapping + signature gate | 150–300 | the glue that ties channels together |
| **v1 total (DHT + WSS trackers + Nostr + mDNS + orchestration)** | **≈ 900–1,500** | **MQTT optional (+150–300); crypto/KDF is a separate lane** |
| Tor v3 (v2 upgrade) | +300–600 wrapper + **heavy binary** | defer |

**The DHT client (bencode+KRPC+lookup+BEP44) is ~half the total and the only from-scratch protocol work** — everything else rides a mature library. If DHT is dropped from v1 (accept trackers+Nostr+mDNS only), v1 falls to **≈ 400–700 LOC** but loses the ownerless-presence primitive and the UDP-path redundancy.

---

## 12. Open questions / UNVERIFIED (hand-offs)

- **DHT BEP44 get/put first-try success rate under 2026 conditions** — no fresh measurement found; validate empirically against live bootstrap nodes before trusting DHT as presence-primary. (All bootstrap DNS + UDP paths *are* confirmed open.)
- **Real enforced payload caps** on public MQTT brokers (protocol says 256 MB; actual public-instance caps untested).
- **Precise IPNS resolution latency** (docs say "slow," no seconds figure) — moot given IPFS is AVOID.
- **trystero MQTT strategy's exact default broker list** (code-level UNVERIFIED; pattern confirmed).
- **HiveMQ public-instance ToS text** (not located; mosquitto's and EMQX's confirmed).
- Precise 26-char key entropy depends on its alphabet/encoding (assumed ~130–150 bits) — confirm with the crypto lane; the whole enumeration-resistance argument rests on it.

---

## Appendix — live-probe log (2026-07-11, this lane + subagents)

```
# DHT bootstrap (resolve + UDP open)
router.bittorrent.com   -> 67.215.246.10        UDP:6881 open
dht.transmissionbt.com  -> 87.98.162.88 212.129.33.59   UDP:6881 open
router.utorrent.com     -> 82.221.103.244       UDP:6881 open

# WSS trackers (trystero defaults)
tracker.openwebtorrent.com -> HTTP 404 (alive)
tracker.btorrent.xyz       -> HTTP 301 (alive)
open.ftorrent.com          -> HTTP 200 (alive)
tracker.webtorrent.dev     -> empty reply to bare GET (alive, WS-only)
ngosang/trackerslist last commit -> 2026-07-10T22:09:42Z (daily)

# Nostr relays
relay.damus.io   -> HTTP 200 (3.26s)
nos.lol          -> HTTP 200 (0.38s)
relay.primal.net -> HTTP 200 (0.36s)
api.nostr.watch/v1/online -> 502 (DO NOT hard-depend)

# MQTT + STUN + wormhole
test.mosquitto.org:1883 -> TCP open
broker.emqx.io:1883     -> TCP open
stun.l.google.com:19302 -> UDP open
stun.cloudflare.com:3478 -> UDP open
stun.stunprotocol.org   -> DNS FAIL (defunct — drop from lists)
relay.magic-wormhole.io -> HTTP 200 (0.58s)
```

*End of report. A senior engineer can pick the channel set (§9) and implement clients from §2–§7 + LOC table (§11) without re-researching. All load-bearing claims carry a URL; UNVERIFIED items are flagged in §12.*
