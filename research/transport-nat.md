# Transport & NAT Traversal — Decision-Grade Report (Lane B)

**Project:** `p2p` — tiny, embeddable, zero-dependency P2P chat/data framework.
**Constraint lens:** everything implementable in-house in a small library (Node.js `dgram`/`net` or Go stdlib), **zero external deps**, **no own server infrastructure** (free public infra only).
**Scope of this file:** how to *get* and *keep* direct peer connections through real-world NATs. Crypto and rendezvous/discovery are other lanes — referenced only where the transport touches them.
**Status:** all load-bearing numbers cited to primary sources with URLs. Items marked **UNVERIFIED** could not be traced to a primary source this session.

---

## 0. TL;DR — Recommended v1 transport stack

Try candidates in parallel (ICE-style "throw everything, pick best that works"), but the *preference ladder* for which connection to keep is:

| Rank | Path | When it wins | In-house cost |
|------|------|--------------|---------------|
| 1 | **IPv6 direct** | Both peers have global IPv6 (~50% of users, rising) | ~0 — just try to connect; still need a firewall-open packet |
| 2 | **LAN fast-path** (mDNS / UDP broadcast) | Peers on same network | ~150–200 LOC |
| 3 | **UDP hole punch** (STUN-learned reflexive candidates + rendezvous signaling) | At least one side EIM (non-symmetric) — the common case | ~100–150 LOC STUN client + punch loop |
| 4 | **TCP simultaneous-open** | UDP fully blocked (some corp/mobile nets) | ~80–120 LOC |
| 5 | **Symmetric-NAT birthday punch** (port prediction + multi-socket spray) | One side symmetric | ~100 LOC on top of #3 |
| 6 | **Peer-relay through a mutual online peer** (E2E, so relay is blind) | Both symmetric, or all direct paths fail | ~150 LOC (reuses our own wire protocol) |
| 7 | **Public-infra relay of last resort** | No mutual peer available | thin — see §3.3, mostly a documented escape hatch |

**Keepalive:** UDP mapping refresh every **15–25 s** (safe under the RFC 4787 2-minute floor); back off / widen on mobile when idle. **Skip for v1:** full WebRTC stack, QUIC, and running our own STUN/TURN — all justified in §9.

---

## 1. UDP hole punching — mechanics & success rates

### 1.1 How it works
A stateful NAT/firewall "allows an inbound UDP packet if it previously saw a matching outbound packet." So each peer sends a UDP packet *toward the other's public `ip:port`*; that outbound packet creates the local NAT mapping and primes the firewall to accept the reply. Both peers must fire **at roughly the same time** "so that all the intermediate firewalls open up," and must "expect some of these packets to get lost" (the first ones usually are — it's a race). Source: Tailscale, *How NAT traversal works* — https://tailscale.com/blog/how-nat-traversal-works

To know your own public `ip:port`, you ask a **STUN** server: "your machine sends a 'what's my endpoint from your point of view?' request… the server sees the public `ip:port` that your NAT device created for you" (ibid). That reflexive candidate is then handed to the peer via the out-of-band rendezvous channel (other lane).

The robust pattern is **ICE**: "try everything at once, and pick the best thing that works" — enumerate candidates (IPv6, LAN IPv4, STUN-learned WAN, port-mapped via UPnP/PCP), race them, keep the best (ibid).

### 1.2 NAT types — the only distinction that matters
Classic RFC 3489 taxonomy: Full-Cone, Restricted-Cone, Port-Restricted-Cone, Symmetric. Modern framing (RFC 4787 behavioral terms) collapses it: **"the major distinction we care about is Symmetric versus anything else — whether a NAT device is EIM or EDM."** (Tailscale, ibid)

- **EIM (Endpoint-Independent Mapping):** same external port regardless of destination → the STUN-learned port equals the port the peer will see → **hole punching works.**
- **EDM / Symmetric (Endpoint-Dependent Mapping):** "a completely different NAT mapping for every different destination" → the STUN-learned port ≠ the port used toward the peer → naive punching fails.

Rule of thumb (industry-standard, corroborated across sources): **EIM↔EIM and EIM↔EDM are punchable; EDM↔EDM (symmetric-vs-symmetric) is the hard case** needing port prediction or relay.

### 1.3 Real success rates (hard numbers)

| Source | Metric | Number |
|--------|--------|--------|
| Tailscale (blog, above) | Direct connect with a basic-but-complete impl | **"over 90% of the time"**, relays cover the rest |
| Ford/Kegel/Srisuresh, USENIX 2005 (primary academic) | NATs supporting **UDP** hole punching | **82%** (310/380 data points) |
| — same paper | NATs supporting **TCP** hole punching | **64%** (184/286) |
| — same paper | Hairpin/NAT-loopback support | UDP **24%**, TCP **13%** |
| libp2p DCUtR, arXiv 2510.27500v1 (large-scale IPFS measurement: 4.4M attempts, 85k+ networks, 167 countries — primary) | Hole-punch stage success | **70% ± 7.1%** |
| — same study | End-to-end lower because relay-reservation + public-addr discovery **fail ~29%** before punch | full pipeline **< 70%** |
| — same study | Latency payoff once direct | 50% of peers drop to **≤70% of original RTT** |

Sources: https://bford.info/pub/net/p2pnat/index.html · https://arxiv.org/html/2510.27500v1

**Design takeaway:** a complete-but-simple UDP-punch + relay-fallback realistically lands ~70–90% *direct*, ~100% *connected*. Do not chase 100% direct — the relay fallback (§3) is what guarantees connectivity.

---

## 2. STUN — protocol basics & minimal in-house client

### 2.1 RFCs
- **RFC 3489** — original STUN (obsolete; had the full-cone/symmetric NAT-classification machinery — don't implement it).
- **RFC 5389** — STUN redefined as a tool (obsoletes 3489). https://datatracker.ietf.org/doc/html/rfc5389
- **RFC 8489** — current STUN (obsoletes 5389). https://datatracker.ietf.org/doc/html/rfc8489

### 2.2 Wire format (what a Binding client must produce/parse) — verified against RFC 8489
- **20-byte header** — RFC 8489: *"All STUN messages comprise a 20-byte header followed by zero or more attributes."* Fields: Message Type (16 bit), Message Length (16 bit), **Magic Cookie (32 bit) = `0x2112A442`** (network byte order), Transaction ID (96 bit).
- **Message types** — RFC 8489: Binding Request first 16 bits = **`0x0001`** (class request `0b00`, method Binding `0x001`); Binding Success Response = **`0x0101`**.
- **Attribute we need:** **XOR-MAPPED-ADDRESS** (type `0x0020`, RFC 8489 §14.2) in the response.

RFC: https://www.rfc-editor.org/rfc/rfc8489.html (obsoletes 5389, which obsoletes 3489).

### 2.3 XOR-MAPPED-ADDRESS — why XOR, how to decode (RFC 8489 §14.2, verified)
Exact spec: *"X-Port is computed by XOR'ing the mapped port with the most significant 16 bits of the magic cookie. If the IP address family is IPv4, X-Address is computed by XOR'ing the mapped IP address with the magic cookie. If the IP address family is IPv6, X-Address is computed by XOR'ing the mapped IP address with the concatenation of the magic cookie and the 96-bit transaction ID."*
Rationale (RFC 8489 §2): a NAT ALG/middlebox pattern-matches and rewrites raw addresses it finds in payloads; XOR keeps *"the transport address in the XOR-MAPPED-ADDRESS attribute… untouched"* as the packet crosses the NAT. (The old plaintext MAPPED-ADDRESS attribute got mangled by such NATs.)
Decode: `port = xport XOR 0x2112`; `ipv4 = xip XOR 0x2112A442`; IPv6 XORs against cookie ‖ transaction-ID.

### 2.4 How tiny is a minimal STUN Binding client?
Very. It sends **one 20-byte packet** (header only — no attributes required for a Binding Request; the server echoes the transaction ID and ignores unknowns) to a STUN server over UDP:3478, then reads one datagram and pulls the XOR-MAPPED-ADDRESS. No auth, no TLS, no message-integrity needed for basic reflexive discovery.

**LOC estimate: ~50–100 LOC** from scratch in Node.js `dgram` or Go `net` (build header, random 96-bit txid, send, parse TLV attributes, XOR-decode). Anchor: `pion/stun`'s `cmd/stun-client` is **55 lines** (uses a lib for message building; raw from-scratch sits in the same ballpark). https://github.com/pion/stun — zero-dep Node reference (a *server*, RFC 5389 §13): `noahlevenson/ministun` https://github.com/noahlevenson/ministun. This is the single cheapest, highest-value piece to own outright — no dependency justified.

### 2.5 Free public STUN servers
STUN is stateless and read-only for our use, so riding free public servers is fine (no own infra needed).

- `stun.l.google.com:19302` (plus alt hosts `stun1..stun4.l.google.com:19302`) — ubiquitous but **unmaintained / no SLA** (community reports it can be flaky); never depend on a single one.
- `stun.cloudflare.com:3478`
- `global.stun.twilio.com:3478?transport=udp`
- From the live-checked list (90 live at fetch time): `stun.nextcloud.com:3478` (also `:443`), `stun.threema.ch:3478`, `stun.freeswitch.org:3478`, `stun.hot-chilli.net:3478`, `stun.antisip.com:3478`, `stun.voipgate.com:3478`.
- **Maintained live list (recommended):** `pradt2/always-online-stun` — refreshed hourly, publishes `valid_hosts.txt` / `valid_ipv4s.txt` / `valid_ipv6s.txt` (use the IP files to skip DNS). https://github.com/pradt2/always-online-stun (raw: `https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_hosts.txt`)
- Other curated gists: https://gist.github.com/mondain/b0ec1cf5f60ae726202e

**Design rule:** ship a small hard-coded fallback list, query **2–3 in parallel**, take the first valid response, and treat any single server as unreliable.

---

## 3. Symmetric-NAT strategies & relay fallback WITHOUT own TURN

### 3.1 Port prediction / birthday-paradox punching
When one side is symmetric, its per-destination port is unknown ahead of time. Two tactics:

**Port prediction (cheap first try):** many symmetric NATs "pick external ports sequentially, making it possible to establish a conversation through guessing nearby ports" (Wikipedia, *UDP hole punching* — https://en.wikipedia.org/wiki/UDP_hole_punching). Do a **double-STUN query** (two Binding requests → observe how the external port increments) to estimate stride, then aim at predicted `port±N`. *(The double-STUN / delta method is patented as a concept but the technique is standard; UNVERIFIED whether any patent blocks a from-scratch impl — treat as informational.)*

**Birthday-paradox spray (the real workhorse):** open **256 sockets** on the hard side (256 external ports), have the easy side probe random target ports. Verified probabilities (Tailscale, ibid):

| Random probes from easy side | Success chance |
|---|---|
| 174 | **50%** |
| 256 | **64%** |
| 1024 | **98%** |
| 2048 | **99.9%** |

"50% of the time we'll get through in under 2 seconds." **Both sides symmetric is the wall:** after 20 s chance is ~0.01%; reaching 99.9% needs ~**170,000 probes ≈ 28 minutes** at 100 packets/s — not viable, **go to relay** (Tailscale, ibid).

> Note: the brief's "~256 or ~700 packets" figure was not found verbatim in Tailscale/Ford/Wikipedia. The verified equivalents are the 174/256/1024/2048-probe table above.

### 3.2 Relay through mutual peers — no own TURN
This is the zero-infra fallback. The pattern is proven by **libp2p circuit-relay-v2** (https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md):
- Any ordinary node with a reachable address can *opt in* as a relay — **no dedicated TURN server.**
- Client sends `RESERVE` to a relay → gets a reservation voucher (kept alive). To connect, client `CONNECT`s via the relay's `hop` stream → relay opens a `stop` stream to the destination → the two streams splice: `client ↔ relay ↔ dest`.

For `p2p`: **relay is just our own wire protocol forwarded blindly.** Because payloads are E2E encrypted (crypto lane), the relaying peer is a dumb pipe — it cannot read content. A mutual online peer (a shared contact, or any node that already holds the 26-char hashkey / is reachable) forwards ciphertext. This is Tailscale's DERP model minus the dedicated servers: "a general purpose packet relaying protocol… relays encrypted payloads based on the destination's public key" (Tailscale, ibid).

### 3.3 Riding free public infra as last resort
- **Tailscale DERP** fleet is free-to-use but tied to Tailscale's coordination — not a clean drop-in for an unrelated app; treat as inspiration, not infra.
- **OpenRelayProject** offers a free public **TURN** (ports 80/443, TCP) — usable as an emergency relay, but it's someone else's goodwill and rate-limited; document it as an optional escape hatch, don't architect on it.
- **Recommended:** v1's true last resort is **peer-relay (§3.2)**; a public TURN is an optional, clearly-labeled fallback flag — not a dependency.

---

## 4. TCP fallbacks

- **TCP simultaneous open:** both peers `connect()` outbound to each other's known/predicted endpoint at the same time; each outbound SYN opens the NAT mapping just like a UDP packet, and most kernel TCP stacks complete a simultaneous-open handshake per RFC 793 without either side listening. Success **64%** of NATs (Ford 2005, above) vs 82% for UDP.
- **Use it when UDP is fully blocked** (some corporate/mobile networks drop all non-TCP/443). Try over port 443 to look like HTTPS.
- **Upgrade path:** start relayed/TCP for instant connectivity, then attempt UDP punch in the background and *transparently upgrade* to the direct path when it succeeds (DERP's "start relayed, upgrade to direct" model — Tailscale, ibid).
- **Gap:** no large-scale TCP-punch measurement newer than Ford 2005 was found — treat 64% as the standard-cited (dated) figure.

---

## 5. QUIC & WebRTC data channels — buy vs cost

### 5.1 WebRTC data channels
- Full stack = **ICE (RFC 8445) + DTLS + SCTP-over-DTLS (RFC 8261) + DCEP (RFC 8832)** per the RFC 8831 architecture. RFC 8261: *"This encapsulation of SCTP over DTLS over UDP or ICE/UDP can provide a NAT traversal solution."*
- **Size:** `libwebrtc` compiles to a **~50 MB static library** and needs a **~20 GB Chromium toolchain** to build; `PeerConnectionFactory` requires manually-managed signalling/networking/worker threads (webrtchacks — secondary, UNVERIFIED against a primary Google figure but directionally certain). **Flatly incompatible with "zero-dependency, tiny."**
- **The one reason to care:** browsers. A browser peer can *only* do P2P via WebRTC data channels (no raw UDP sockets in JS). If browser embedding is a v1 requirement, there is no way around a WebRTC-capable path.
- **Recommendation:** **skip for v1** (Node/Go native peers). If browser support is needed later, add it as an *optional adapter*, not the core.
- RFCs: https://www.rfc-editor.org/rfc/rfc8261.html · https://datatracker.ietf.org/doc/html/rfc8831

### 5.2 QUIC
- QUIC's **connection migration** (RFC 9000 §9) lets a session survive an IP/port change — attractive for mobile/NAT-rebind persistence. Exact spec: *"The use of a connection ID allows connections to survive changes to endpoint addresses (IP address and port), such as those caused by an endpoint migrating to a new network"* … *"such as might be caused by NAT rebinding."* Caveat: *"Only clients are able to migrate in this version of QUIC."* https://datatracker.ietf.org/doc/html/rfc9000
- There is a **QUIC NAT-traversal draft** (`draft-seemann-quic-nat-traversal`): either non-QUIC STUN packets on the same UDP socket, or a QUIC extension that coordinates path-validation to open bindings then migrates onto the direct path. Individual draft, **not an RFC / WG-adoption status UNVERIFIED**. https://datatracker.ietf.org/doc/draft-seemann-quic-nat-traversal/
- **But zero-dep fails:** Go **stdlib has no QUIC** (needs `github.com/quic-go/quic-go` or the separate `golang.org/x/net/quic` module); Node ships `node:quic` only from **v24 behind `--experimental-quic`**. Implementing QUIC from scratch dwarfs our whole transport budget.
- **Recommendation:** **skip for v1.** Re-create the *useful idea* cheaply: a small **connection-ID in our own header** so a session can be re-bound after a NAT change without a full re-handshake (see §6.3).

---

## 6. Keepalive, persistence, reconnect/resume

### 6.1 Mapping lifetime (verified)
RFC 4787 **REQ-5**: a NAT UDP mapping timer **"MUST NOT expire in less than two minutes"**, and **"a default value of five minutes or more… is RECOMMENDED."** https://datatracker.ietf.org/doc/html/rfc4787
Reality is messier — many consumer/mobile NATs use **30–60 s** UDP timeouts. So design to the aggressive end.

### 6.2 Keepalive intervals (all cited)
- **UDP: send a tiny keepalive every 15–25 s.** Comfortably under the 2-min floor and covers aggressive real-world NATs (mobile CGNAT UDP timeouts run ~20–60 s). Corroborating anchors:
  - **RFC 8445 (ICE)** keepalive floor: *"agents MUST NOT use a keepalive interval value smaller than 15 seconds"* (STUN Binding Indication on the selected pair, no response needed). https://www.rfc-editor.org/rfc/rfc8445.html
  - **RFC 7675 (consent freshness):** check every ~4–6 s (default 5 s, MUST NOT go below 4 s), **30 s consent expiry** — this is the liveness/"is the peer still there" signal, distinct from the mapping-keepalive. https://www.rfc-editor.org/rfc/rfc7675.html
  - **WireGuard** production default `PersistentKeepalive = 25 s` — the best-tested real-world value (~32-byte packet, negligible battery). Use **25 s** as the default.
- **TCP:** NAT/gateway idle timeouts are far longer — AWS NAT Gateway **350 s**, Azure NAT default **4 min** (up to 120), GCP Cloud NAT **20 min** (RFC 5382 recommends ≥ 2 h 4 min). App-level ping every **~60–120 s** is plenty.
- **Mobile/battery:** frequent UDP keepalives block radio sleep and drain battery (though at 25 s the cost is fractions of a %/hr). Mitigations: (a) widen interval toward the NAT's real limit when the app is backgrounded/idle; (b) coalesce keepalive with real traffic; (c) let the connection lapse when truly idle and rely on fast reconnect (§6.3) on next activity. Do **not** hard-code a sub-15 s interval for mobile.

### 6.3 Reconnect / resume design
- **Session key = the 26-char hashkey + a per-session connection-ID** in our header. On keepalive-timeout or NAT rebind, don't tear down state: re-run the rendezvous → punch sequence and resume the *same* logical session by connection-ID (the QUIC-migration idea, done cheaply).
- Keep a **sequence number + short replay buffer** so a resumed link continues mid-stream without loss.
- Maintain a **relay path warm in the background** while direct is up (DERP model): if direct drops, traffic instantly falls to relay, then re-upgrades — no user-visible disconnect.

---

## 7. IPv6 — how often it removes the problem

- IPv6 has **no NAT** — every host gets a global address, so "traversal" reduces to opening the stateful firewall (one outbound packet), not port-mapping. Massive simplification when available.
- **Adoption crossed 50% for the first time on 2026-03-28 (50.10% of Google users native IPv6).** Sources: https://blog.apnic.net/2026/04/28/google-hits-50-ipv6/ · https://pulse.internetsociety.org/en/blog/2026/04/18-years-later-ipv6-reaches-majority/ · live graph https://www.google.com/intl/en/ipv6/statistics.html
- Regional: France ~86% (Feb 2026); India/Germany/Vietnam among leaders.
- **Caveat:** *both* peers need IPv6 for a v6 direct path, so the joint probability is lower than 50%, and firewalls still need the same simultaneous-open packet. But it's the cheapest possible win — **always try IPv6 candidates first.**

---

## 8. LAN fast-path — local discovery

- **mDNS (RFC 6762) + DNS-SD (RFC 6763):** RFC 6762 — *"Any DNS query for a name ending with '.local.' MUST be sent to the mDNS IPv4 link-local multicast address 224.0.0.251"* on UDP port **5353**; IPv6 equivalent **`FF02::FB`**. DNS-SD enumerates services via a PTR query `_services._dns-sd._udp.<Domain>`. No internet, no server. https://www.rfc-editor.org/rfc/rfc6762.html · https://www.rfc-editor.org/rfc/rfc6763.html
- **Even simpler:** raw **UDP broadcast** to `255.255.255.255:<port>` (or subnet-directed broadcast) carrying the hashkey fingerprint — trivially small, works on a flat LAN.
- **LOC:** a minimal mDNS responder/browser ≈ **150–200 LOC**; a bare UDP-broadcast beacon ≈ **40–60 LOC**. Both are pure stdlib (`dgram` / Go `net`).
- **Design:** on startup, broadcast + listen on the LAN; if a peer with the matching hashkey answers, connect directly on the LAN and skip all NAT machinery. Huge latency win, zero infra.

---

## 9. What to skip in v1 (and why)

| Skip | Reason |
|------|--------|
| **Own STUN server** | STUN is read-only & stateless — ride free public servers (§2.5) + a maintained list. |
| **Own TURN server** | Violates zero-infra. Peer-relay (§3.2) covers the fallback; optional public TURN as labeled escape hatch. |
| **Full WebRTC stack** | ICE+DTLS+SCTP + `libwebrtc` = millions of LOC — antithesis of tiny. Only needed for browsers; add as optional adapter later (§5.1). |
| **QUIC** | Not in Node/Go stdlib; from-scratch impl dwarfs the whole transport. Steal only its connection-ID/migration idea cheaply (§6.3). |
| **RFC 3489 NAT classification** | Obsolete; the EIM-vs-EDM behavioral distinction (§1.2) is all we act on. |
| **Chasing 100% direct** | Diminishing returns (double-symmetric = 28 min). Relay guarantees connectivity; direct is an upgrade. |
| **Aggressive fixed mobile keepalive** | Battery cost; adapt interval + fast-reconnect instead (§6.2/§6.3). |

---

## 10. Implementer's build order & LOC budget

1. **STUN binding client** (~100–150 LOC) — learn reflexive candidate.
2. **LAN beacon** (UDP broadcast ~40–60 LOC, or mDNS ~150–200) — local fast-path.
3. **UDP hole-punch loop** — race candidates, simultaneous send, expect loss, retransmit (~120 LOC + rendezvous glue from other lane).
4. **Keepalive + liveness** (~50 LOC) — 15–25 s UDP ping, consent tracking.
5. **Reconnect/resume** — connection-ID header + re-punch on timeout (~80 LOC).
6. **Symmetric birthday-punch** — 256-socket spray + optional port prediction (~100 LOC).
7. **TCP simultaneous-open fallback** (~80–120 LOC).
8. **Peer-relay forwarder** — blind ciphertext forward over our own wire protocol (~150 LOC).

**Total core transport ≈ 700–1000 LOC, zero external deps.** IPv6 is "free" (just attempt v6 candidates in step 3).

---

## 11. Verification log

**Independently verified by me (Lane B owner) via direct WebFetch of the primary source:**
- Tailscale hole-punch mechanics, EIM/EDM, >90% direct, DERP, birthday table (174/256/1024/2048 probes; 170k double-symmetric) — https://tailscale.com/blog/how-nat-traversal-works
- RFC 4787 REQ-5 (2-min floor / 5-min recommended) — https://datatracker.ietf.org/doc/html/rfc4787
- IPv6 >50% (50.10%, 2026-03-28) — APNIC + ISOC Pulse

**Verified by source-gathering subagents, sources checked & quoted:**
- Ford 2005 (82% UDP / 64% TCP) — https://bford.info/pub/net/p2pnat/index.html; libp2p DCUtR arXiv (70%±7.1%) — https://arxiv.org/html/2510.27500v1
- STUN wire format + XOR-MAPPED-ADDRESS §14.2 + XOR rationale — RFC 8489 https://www.rfc-editor.org/rfc/rfc8489.html; `pion/stun` client = 55 LOC (verified via curl+wc); `pradt2/always-online-stun` live list (90 hosts live at fetch)
- RFC 8445 15 s ICE keepalive floor; RFC 7675 4–6 s check / 30 s consent; WireGuard 25 s default; AWS 350 s / Azure 4 min / GCP 20 min TCP NAT timeouts
- RFC 9000 §9 connection migration exact quote; `draft-seemann-quic-nat-traversal`; Go stdlib has no QUIC; Node `node:quic` v24 experimental
- RFC 6762 mDNS (224.0.0.251 / FF02::FB / 5353) + RFC 6763 DNS-SD exact quotes; RFC 8261/8831 WebRTC stack

**UNVERIFIED / flagged (not relied on for recommendations):**
- WebRTC "75–80% direct / 30% need TURN / 94% host-candidate" figures — secondary blogs only, not traced to a primary Google/W3C dataset.
- `libwebrtc` 50 MB / 20 GB-toolchain figure — webrtchacks blog, not a primary Google doc (directionally certain).
- No modern (post-2010) TCP-hole-punch measurement found; Ford 2005 (64%) remains the cited figure.
- Double-STUN port-prediction patents exist; whether they block a clean-room impl is UNVERIFIED (informational only).
- `draft-seemann-quic-nat-traversal` current WG-adoption status; mDNS TTL=255 clause; minimal mDNS/broadcast responder exact LOC (est. from protocol structure, not a citation).
- Whether IPv6 still needs an explicit firewall-open packet — asserted from stateful-firewall behavior (same as NAT mapping), no dedicated RFC quote pulled.
