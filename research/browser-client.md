# Browser-Only Client — Decision-Grade Design Study

**Project:** `p2p` — tiny, embeddable, zero-dependency P2P chat/data framework.
**Problem this file solves:** ship a client that runs **entirely in a browser tab, with no backend
of ours**, that is **interoperable** with the existing TUI/CLI (same 26-char key, same Noise IK
handshake + commitment gate, same message semantics), connects **frontend↔frontend across
different NATs** and **frontend↔TUI**, supports **groups > 2 seamlessly**, and is **at least as
secure as the TUI** — nothing readable, decodable, or monitorable outside the authorized clients.
**Research date:** 2026-07-12. **Author:** browser-research lane (opus) + 3 sonnet research
subagents; every load-bearing claim carries a URL, UNVERIFIED items are flagged in §12.
**Scope:** research + design only. No implementation. Nothing in `src/` is touched.

---

## 0. TL;DR — the verdict up front

| Question | Verdict |
|---|---|
| **Does a browser client fit the current system cleanly?** | **YES, WITH ONE CAVEAT.** Identity (`key.js`), rendezvous-id derivation (`deriveRid`), the commitment gate, the Noise IK handshake and the app-message semantics port to the browser **unchanged and byte-identical**. The one thing that cannot port is the **transport**: browsers have no raw UDP, so `transport.js` (STUN + hole-punch) is replaced by a **WebRTC DataChannel** transport behind the *same* endpoint seam (`ep.punch()` / `ep.onConnection()`). Everything above the transport is shared. |
| **Is the browser client ≥ TUI security?** | **YES — provably equal, by construction.** We run **our own Noise IK + commitment gate over the DataChannel**, exactly as the TUI runs it over UDP. Security therefore rests on X25519 + ChaCha20-Poly1305 + the 110-bit commitment — **not** on WebRTC's DTLS, not on the trackers, not on STUN/TURN. Every one of those is treated as a hostile, untrusted pipe. The browser additionally gets DTLS as a *redundant* outer layer the TUI does not have (defense-in-depth, never relied upon). |
| **browser ↔ browser?** | **YES, zero new infra.** Signaling reuses our **existing WSS tracker matchmaker** (`src/rendezvous/tracker.js`) under the same `rid = HKDF(S, "p2p-rv-tracker-v1", epoch, 20)`. ICE does the NAT traversal. |
| **browser ↔ TUI?** | **YES, but it costs something — this is the honest gap.** A browser cannot speak the TUI's UDP transport (no raw sockets, ever). So one of two things must give: the **TUI gains a WebRTC DataChannel transport** (only pure-JS option is `werift` — a real npm dependency, breaking strict zero-dep for that *optional* adapter), **or** both sides fall back to a **zero-dep Noise-over-public-WSS relay** data plane (blind relay, works everywhere, costs latency + rides someone's free infra). Recommendation: **ship both** — WebRTC as the fast path (optional dep, dynamic-imported, core stays zero-dep), WSS-relay as the universal zero-dep floor. Full analysis in §6. |
| **Groups > 2?** | **YES — upgrade `group.js` (pairwise fan-out) to sender keys + a signed membership hash-chain + causal DAG ordering**, all riding the pairwise Noise links we already have. One encryption per message instead of n, per-sender Ed25519 authentication (no member can impersonate another), cryptographic removal via key rotation, and blind peer-relay for members who can't connect directly. Group content stays E2E — the infra sees only an opaque group rid and ciphertext. **MLS rejected for v1**: it wants a Delivery Service to order commits (we have no server) and wins nothing at n≤30 (§7). |
| **Do we need TURN?** | **Not for most pairs, and never as a trust dependency.** ~85–90% of WebRTC pairs connect direct via STUN alone. Symmetric↔symmetric browser pairs are the wall — and unlike the TUI, a **browser cannot birthday-punch its way out** (no raw sockets, ICE gives no port control). We do **not** run TURN. We cover that residual with the §6 WSS-relay (or an optional user-supplied TURN). A TURN relay sees only ciphertext anyway (§8). |

---

## 1. What ports unchanged, what must be replaced

The existing stack, read from disk (`src/*.js`, 2026-07-12):

| Layer | Module | Browser status |
|---|---|---|
| Identity, 26-char key, commitment gate, `deriveRid` | `src/key.js` | **PORTS AS-IS** (WebCrypto: SHA-256 + HKDF + X25519 + Ed25519 — §3) |
| Noise IK + Split() | `src/noise.js` | **PORTS AS-IS**, except ChaCha20-Poly1305 must be **vendored** (§3.4). Same protocol name, same nonces, same wire bytes. |
| App message semantics (`[1B kind][4B seq][payload]`, MSG/ACK, outbox, restart-instance nonce) | `src/node.js` | **PORTS AS-IS** — pure JS, no Node API beyond `randomBytes` (→ `crypto.getRandomValues`) |
| Rendezvous — WSS trackers | `src/rendezvous/tracker.js` | **PORTS AS-IS** — it already uses the **global `WebSocket`**, which is browser-native. Same `infoHashFor(rid)`. |
| Rendezvous — DHT, mDNS | `src/rendezvous/dht.js`, `mdns.js` | **CANNOT PORT.** Both need raw UDP. Browser discovery = **trackers only** (§4.3). |
| Framing + ARQ (seq/ack, resend, keepalive) | `src/wire.js` | **NOT NEEDED over WebRTC** (a DataChannel is already reliable+ordered over SCTP). Kept only for the WSS-relay path. See §5.3 — this is a real interop seam, handled explicitly. |
| UDP core, STUN client, hole punch, TCP fallback | `src/transport.js` | **REPLACED** by `transport-webrtc.js` behind the identical seam. |

**The seam already exists and is clean.** `src/node.js` takes `createEndpoint` via `opts.deps` /
`opts.endpoint` and only ever calls `ep.punch(candidates, {token})` → a socket-like with
`.send()` / `.onMessage` / `.close()`, plus `ep.onConnection(cb)` for inbound. A WebRTC endpoint
that satisfies that contract drops in with **zero changes to `node.js`**. This is the single most
important structural finding of this study: *the browser client is a transport swap, not a rewrite.*

---

## 2. Recommended architecture

```
                      ┌──────────────────── BROWSER TAB (no backend of ours) ────────────────────┐
                      │                                                                          │
  26-char key S ─────▶│  key.js (WebCrypto)          identity: Ed25519 + X25519                  │
                      │    ├─ decode + checksum (offline, no network on a typo)                  │
                      │    ├─ commitment = first110( SHA256("p2p-id-v1"‖ed‖x) )                   │
                      │    └─ rid = HKDF(S, "p2p-rv-tracker-v1", epoch, 20)   ◀── SAME AS TUI    │
                      │                                                                          │
                      │  noise.js (WebCrypto X25519/SHA256/HMAC + vendored ChaCha20-Poly1305)    │
                      │    Noise_IK_25519_ChaChaPoly_SHA256  ◀── BYTE-IDENTICAL TO TUI           │
                      │                                                                          │
                      │  node.js  (unchanged: HELLO → GATE → IK → MSG/ACK outbox)                │
                      │                                                                          │
                      │  transport-webrtc.js   ── the ONLY new module ──                         │
                      │    RTCPeerConnection + RTCDataChannel (reliable, ordered)                │
                      └───────┬───────────────────────────────────────────────┬──────────────────┘
                              │                                               │
              ┌───────────────▼────────────────┐              ┌───────────────▼────────────────┐
              │  SIGNALING (offer/answer)      │              │  NAT TRAVERSAL                 │
              │  our EXISTING WSS trackers,    │              │  ICE + free public STUN        │
              │  keyed by rid → infoHashFor()  │              │  (stun.l.google.com, cloudflare│
              │  tracker.openwebtorrent.com    │              │   — the SAME servers transport │
              │  tracker.webtorrent.dev        │              │   .js already uses)            │
              │  tracker.btorrent.xyz          │              │  no TURN of ours               │
              │  ── ZERO NEW INFRA ──          │              │  ── ZERO NEW INFRA ──          │
              └────────────────────────────────┘              └────────────────────────────────┘
                              │                                               │
                              │   both are UNTRUSTED. They carry opaque rids  │
                              │   and ciphertext. Noise runs ON TOP.          │
                              ▼                                               ▼
        ╔═══════════════════════════════════════════════════════════════════════════════════╗
        ║   DataChannel (DTLS)  ──▶  [ Noise IK + commitment gate ]  ──▶  plaintext          ║
        ║   ▲ WebRTC's own crypto — treated as a hostile pipe, NEVER relied on               ║
        ║   ▲ the security boundary is the Noise layer, identical to the TUI's over UDP      ║
        ╚═══════════════════════════════════════════════════════════════════════════════════╝
```

**One sentence:** *the browser client is the existing p2p stack with `transport.js` swapped for a
WebRTC DataChannel, signaled over the trackers we already use, with our Noise layer running on top
of WebRTC exactly as it runs on top of UDP — so WebRTC, the trackers, STUN and any TURN are all
untrusted plumbing that never sees a plaintext byte.*

---

## 3. Crypto in the browser — can we run OUR Noise, byte-identical?

**Answer: yes, with exactly one vendored primitive.** Status verified 2026-07 (this lane's
subagent, cross-checked against the project's own `research/crypto-firstcontact.md` §7.3, which
reached the same conclusion in 2026-07-11).

### 3.1 What WebCrypto gives us natively

| Primitive | Noise/p2p use | Browser status |
|---|---|---|
| **SHA-256** | `MixHash`, commitment, checksum | Universal, ancient. ✅ |
| **HMAC-SHA256** | Noise's `HKDF` (`hkdf2()` in `noise.js` is raw HMAC) | Universal. ✅ |
| **HKDF** | `deriveRid` (`key.js`) | Universal, Baseline since Jan 2020. ✅ ([MDN deriveBits](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveBits)) |
| **X25519** | every Noise DH token (`es`/`ss`/`ee`/`se`) | **Shipped in all three engines.** Chrome/Edge 133 ([chromestatus 6291245926973440](https://chromestatus.com/feature/6291245926973440)), Firefox 130 ([bug 1904836](https://bugzilla.mozilla.org/show_bug.cgi?id=1904836)), Safari 18.4 ([WebKit 18.4 notes](https://webkit.org/blog/16574/webkit-features-in-safari-18-4/)). ✅ |
| **Ed25519** | signing stored records (P2); not used at first contact (D4) | Chrome 137 ([chromestatus 4913922408710144](https://chromestatus.com/feature/4913922408710144)), Firefox 129, Safari 17.x. ✅ |
| **CSPRNG** | ephemerals, instance nonce | `crypto.getRandomValues`. ✅ |
| **ChaCha20-Poly1305** | **every AEAD op in the handshake and transport** | ❌ **NOT IN ANY BROWSER.** |

Spec caveat, unchanged from our earlier research: X25519/Ed25519 live in the **WICG "Secure Curves
in WebCrypto"** incubation doc (https://wicg.github.io/webcrypto-secure-curves/), *not* W3C
standards-track. Shipped everywhere, but **feature-detect and fail loudly** (or fall back to a
vendored X25519) rather than assume.

### 3.2 Raw key import — the DER trick (already solved in our codebase)

WebCrypto `importKey` will not take a raw 32-byte **private** scalar; it wants PKCS8 DER. The
wrapper is a fixed prefix — and it is **the exact same constant already sitting in `src/noise.js`**:

```
X25519 PKCS8:  302e020100300506032b656e04220420 ‖ raw32     (OID 1.3.101.110)   ← noise.js:45, verbatim
X25519 SPKI:   302a300506032b656e032100         ‖ raw32                          ← noise.js:44, verbatim
Ed25519 PKCS8: 302e020100300506032b657004220420 ‖ raw32     (OID 1.3.101.112)
```

So the browser port of `noise.js` reuses our own DER constants unmodified. (MDN
[importKey](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey); RFC 8410
structure.) Public keys import as `raw`/`spki` and export as `raw` — which is what the wire needs.

**Low-order-point hardening survives:** `noise.js` rejects an all-zero X25519 shared secret. The
WebCrypto X25519 spec mandates the same (`deriveBits` throws `OperationError` on the all-zero
result), so the browser port keeps the check *and* gets it enforced by the engine. Fail-closed on
both sides.

### 3.3 HKDF/HMAC mapping is 1:1

`deriveRid` is literally `hkdfSync('sha256', ikm=ASCII(S), salt='p2p-rv-<channel>-v1',
info=epochStr, len)` → WebCrypto `deriveBits({name:'HKDF', hash:'SHA-256', salt, info}, key, len*8)`.
Same ikm, same salt, same info, same L. **A browser derives the identical rid as the TUI.** That is
the whole basis of shared rendezvous (§4). Gotcha: an HKDF key handle must be imported
non-extractable, and the ECDH/X25519 secret must always be run *through* HKDF, never used raw
([w3c/webcrypto#193](https://github.com/w3c/webcrypto/issues/193)) — which is exactly what Noise does.

### 3.4 ChaCha20-Poly1305: the one thing we must vendor

Not in WebCrypto. Not in any browser. Tracked in
[w3c/webcrypto#223](https://github.com/w3c/webcrypto/issues/223) — **open since 2019, no implementor
interest**. It only exists in the WICG "Modern Algorithms" draft
(https://wicg.github.io/webcrypto-modern-algos/), which is incubation-only with zero shipping status.

Options:

| Option | Size | Audit | Verdict |
|---|---|---|---|
| **`@noble/ciphers` (chacha only, inlined)** | **~3 KB gzipped** tree-shaken (~11 KB full lib) | **Cure53 audit at v1.0.0 (Sept 2024)**, OpenSats-funded. Zero deps, MIT. ([noble-ciphers](https://github.com/paulmillr/noble-ciphers)) | ✅ **RECOMMENDED — vendor it** (single-file, in-tree, pinned + hash-checked; "inhouse" per the owner's rule, same precedent as D11's vendored noble-secp256k1) |
| Hand-rolled single-file RFC 8439 | ~200–300 LOC | none — all risk ours | ❌ We already buy one hand-rolled-crypto risk with the Noise state machine (D5). Don't buy a second when an audited 3 KB file exists. |
| `libsodium.js` (WASM) | 188 KB+ min+gzip | libsodium's audit history; **genuinely constant-time** (compiled C) | ⚠️ Fallback only. 60× the bytes; WASM load complexity for a static page. Reach for it only if the timing threat model demands it. |
| **AES-GCM (native WebCrypto)** | 0 KB | native, constant-time | ❌ **REJECT for the default path.** It changes the Noise suite to `Noise_IK_25519_AESGCM_SHA256` — a **different protocol with a different nonce encoding** (AESGCM = big-endian counter; ChaChaPoly = little-endian — [Noise spec](https://noiseprotocol.org/noise.html), and `noise.js:141` already writes `writeBigUInt64LE`). **This breaks TUI interop at the wire level.** Keep it only as a *documented, version-bit-gated* cipher-agility escape hatch (D2's 5 version bits exist for exactly this) — never as the browser default. |

**Decision (BC-3): vendor ChaCha20-Poly1305 (`@noble/ciphers`, chacha subset, in-tree, pinned) so
the browser speaks the byte-identical `Noise_IK_25519_ChaChaPoly_SHA256` as the TUI.** One wire
format, one protocol name, interop preserved. This is precisely the recommendation
`research/crypto-firstcontact.md` §7.3/§12 already made ("vendor ChaCha20-Poly1305 everywhere, keep
ONE wire format") — this study **closes that open question in favor of the recommendation**.

**Honest cost:** pure-JS ChaCha20 is **not formally constant-time** — noble's own maintainers say a
JIT+GC language cannot guarantee it. Residual risk assessed as **low for this threat model**: the
attacker would need a fine-grained timing oracle on the victim's own browser process (a malicious
extension or a co-resident side-channel), and such an attacker has far more direct paths to the
plaintext (it's *in the tab*). ChaCha20 is ARX-only with no secret-dependent table lookups (unlike
noble's AES T-table path), which is the better-behaved case. **Documented, not hidden.** If the
threat model ever includes in-browser side channels, swap to the libsodium WASM build.

### 3.5 Secure context

`crypto.subtle` is **undefined outside a secure context** (HTTPS or `localhost`) —
([MDN Crypto.subtle](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle)). The client
**must** be served over HTTPS (GitHub Pages / `p2p.akeyo.io` already is) and must feature-detect and
**hard-fail with a clear error** rather than silently degrade. Non-negotiable, trivially satisfied.

---

## 4. Signaling — the browser reuses our existing rendezvous, with zero new infra

### 4.1 The claim, and why it holds

WebRTC needs an offer/answer exchange over *some* channel. **We already built exactly that channel.**
`src/rendezvous/tracker.js` is a live WSS-tracker matchmaker that:

- derives `infoHash = infoHashFor(rid)` where `rid = deriveRid(S, 'tracker', epoch, 20)`;
- holds persistent WSS connections and **answers incoming offers** (listener side);
- sends `{action:'announce', info_hash, peer_id, offers:[{offer_id, offer:{type:'offer', sdp}}]}`
  and reads back `{offer|answer, offer_id, peer_id}` — **the WebTorrent tracker's native
  offer/answer relay** ([bittorrent-tracker](https://github.com/webtorrent/bittorrent-tracker));
- uses the **global `WebSocket`** constructor, already injectable via `opts.WebSocket`.

The delicious part: the current implementation ships a **fake** SDP (`a=p2p-blob:<base64>`) because
the TUI has no WebRTC — it abuses the SDP field as an envelope for UDP candidates. **The browser
puts a REAL SDP there.** Same trackers, same infohash, same message shape, same code path. The
tracker cannot tell the difference and does not care — it is an opaque relay.

**Therefore: browser↔browser signaling reuses our existing rendezvous with ZERO new infrastructure,
and the browser's tracker client is our own `tracker.js` with `Buffer` swapped for `Uint8Array`.**
Verified structurally against the source; not yet run in a browser (§12).

### 4.2 Can the browser reach the DHT or mDNS? No.

- **Mainline DHT: impossible.** It is raw UDP; browsers have no raw UDP socket, only ICE-mediated
  UDP inside `RTCPeerConnection`. WebTorrent's own browser client does not support DHT or `udp://`
  trackers for exactly this reason
  ([webtorrent#288](https://github.com/webtorrent/webtorrent/issues/288),
  [webtorrent#1467](https://github.com/webtorrent/webtorrent/issues/1467)).
- **mDNS: impossible.** Multicast UDP on 5353. Same reason. (Note: browsers *do* use mDNS internally
  to obfuscate host ICE candidates — but that is the ICE agent's business, not an API we can call.)

**Consequence — an honest asymmetry:** the TUI publishes to **three** channels (mDNS + DHT +
trackers) and races them; the **browser has one** (trackers). Implications:

1. **The tracker channel becomes load-bearing for any connection involving a browser.** The existing
   3-tracker fan-out (`TRACKERS[]`) + reconnect is the redundancy story. Mitigate further by widening
   the pool from [ngosang/trackerslist](https://github.com/ngosang/trackerslist) /
   [newtrackon.com](https://newtrackon.com/) and by adding a second *browser-reachable* signaling
   channel later (nostr relays over WSS — trystero-proven; costs a vendored secp256k1, so P2).
2. **A TUI peer must keep announcing on trackers** (it already does) for a browser to find it.
3. **Same-LAN browser↔browser gets no mDNS fast path.** It still works — ICE host candidates connect
   instantly on a LAN — it just resolves via the tracker rather than mDNS. Not a functional loss.

### 4.3 Tracker constraints to respect

Public trackers are best-effort, no SLA, undocumented rate limits (UNVERIFIED — no published numbers).
Keep the existing ~10 s announce cadence (offers expire ~120 s), keep the 3-tracker fan-out, and treat
tracker failure as expected, not exceptional. Browsers connect to `wss://` trackers directly — no CORS
preflight applies to WebSocket — but the page must be HTTPS and the tracker must present a valid CA
cert (both true of the current pool).

---

## 5. Transport — WebRTC DataChannel

### 5.1 Why WebRTC is the only option

A browser cannot: open a UDP socket, send a STUN binding request itself, hole-punch, port-predict,
birthday-spray, listen on a port, or accept an inbound connection of any kind. `WebTransport` is
**client-only** — a browser can never be the server
([MDN WebTransport](https://developer.mozilla.org/en-US/docs/Web/API/WebTransport_API)). WebSocket is
client-only too. **The only peer-to-peer primitive a browser has is `RTCPeerConnection` +
`RTCDataChannel`.** That is not a preference; it is the entire option space.

This is also precisely what `research/transport-nat.md` §5.1 already concluded ("A browser peer can
*only* do P2P via WebRTC data channels… If browser embedding is a v1 requirement, there is no way
around a WebRTC-capable path") and what `DESIGN.md` §6 deferred ("browser adapter study", P2). **This
document is that study.**

### 5.2 What we get, and what it costs

`RTCDataChannel` in default mode is **reliable + ordered** (SCTP over DTLS — RFC 8831/8832) — i.e. it
gives us for free what `wire.js` hand-builds over UDP (ARQ, seq/ack, resend, ordering). ICE gives us
NAT traversal (host + srflx via STUN + optional relay candidates), which is what `transport.js`
hand-builds with its STUN client and punch choreography.

**Message size limit — a real constraint, must be handled:** no hard spec cap, but the practical
cross-browser safe chunk is **16 KiB** (Firefox→Chromium reliable/ordered caps there; Chromium closes
the channel outright above ~256 KiB; no browser implements SCTP `ndata` (RFC 8260) yet, so one big
message head-of-line-blocks the whole association)
([Lennart Grahl, "Demystifying WebRTC DC size limits"](https://lgrahl.de/articles/demystifying-webrtc-dc-size-limit.html),
[Mozilla — Large DataChannel messages](https://blog.mozilla.org/webrtc/large-data-channel-messages/),
[MDN — Using data channels](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Using_data_channels)).
→ **Chunk at ≤16 KiB, reassemble at the receiver.** For chat this is a non-issue; for file transfer
it is mandatory. Our existing `mtu: 1200` default is already far below it.

### 5.3 The framing seam — one design decision to get right

`wire.js` gives ordered/exactly-once *within* a session; `node.js` adds an app-level outbox (seq +
ACK) that survives **reconnects**. Over a DataChannel, `wire.js`'s ARQ is redundant — SCTP already
does it.

**Decision (BC-5): keep the app layer, drop the ARQ, preserve the frame *types*.** Concretely, the
WebRTC endpoint presents the same socket-like seam and speaks the same **frame type tags**
(`HELLO=0, HS1=1, HS2=2, DATA=3, …` from `wire.js`) so `node.js` is untouched — but the DataChannel
path uses a **degenerate channel** that passes DATA payloads straight through (no seq/ack/resend/RTO
timers), because the transport already guarantees them. The `node.js` app-level outbox/ACK stays
(it is what makes exactly-once survive a *reconnect*, which SCTP does not).

This matters for interop: the **Noise handshake bytes and the app frames are identical on both
transports**; only the reliability machinery underneath differs. A TUI peer and a browser peer that
meet over a common transport (§6) therefore agree on every byte that matters.

### 5.4 STUN and TURN

**STUN:** use the free public servers `transport.js` already lists (`stun.l.google.com:19302`,
`stun.cloudflare.com:3478`) as ICE `iceServers`. Same infra, no new dependency. Caveat: Google's STUN
has **no published ToS/SLA** — community-consensus "fine, but don't bet the company on it"
([iceperf.com](https://iceperf.com/providers/google)). Ship a list, not a single server, and let it
be user-overridable.

**TURN — do we need it?** Published field data:

| Source | Direct (STUN only) | Needs relay |
|---|---|---|
| [Twilio](https://www.twilio.com/docs/video/networking-considerations) | ~85% | **~15%** |
| [Tailscale](https://tailscale.com/blog/how-nat-traversal-works) (native, not browser) | >90% | ≤10% |
| Industry range ([RTC Insights](https://www.rtcinsights.com/blog/stun-turn-configuration/), [Hancke](https://medium.com/@fippo/so-i-read-that-20-of-webrtc-calls-fail-67b185e49765)) | ~70–85% | 15–30% |

*(Note: the frequently-cited "Google says 8–15%" figure could not be traced to a primary Google
source — **UNVERIFIED**, do not cite it. Twilio's ~15% is the solid number.)*

**The browser-specific wall:** when both peers are behind **symmetric NAT**, the TUI can still fight
— `transport.js` + `research/transport-nat.md` §3.1 describe birthday-punch / port-prediction, which
need **many parallel sockets with controlled source ports**. A **browser has none of that**: the ICE
agent owns the sockets, and JS never touches them. So **for a browser, symmetric↔symmetric means a
relay is mandatory** ([webrtcHacks — symmetric NAT](https://webrtchacks.com/symmetric-nat/)). There is
no clever way out; anyone claiming otherwise is wrong about the browser sandbox.

**Our answer, in priority order (never running TURN ourselves):**

1. **ICE direct (host/srflx)** — covers ~85%.
2. **Peer-relay via a mutual friend** (application-level, over already-open DataChannels — the
   browser-native form of D8's "peer-relay via mutual friend"; prior art: libp2p circuit-relay-v2
   ([spec](https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md),
   [js-libp2p WebRTC](https://libp2p.io/docs/webrtc-browser-connectivity/))). The relaying peer
   forwards **Noise ciphertext frames** — it is a *blind* relay even though it is a friend. Note
   honestly: libp2p/trystero prior art relays *signaling* then goes direct; full **data-plane**
   multi-hop peer relay is a pattern we would be implementing ourselves (~150 LOC, same estimate as
   D8's UDP peer-relay).
3. **WSS-relay data plane** (§6.2) — the zero-dep universal floor. Also solves browser↔TUI.
4. **Optional user-supplied TURN** — a config field, empty by default. If a user pastes in their own
   (or a free-tier [Open Relay](https://www.metered.ca/tools/openrelay/): 20 GB/mo, account required),
   ICE uses it. **Safe by construction: a TURN relay sees only DTLS-encrypted SCTP — and under that,
   our Noise ciphertext. It is doubly blind** (§8).

---

## 6. INTEROP: browser ↔ TUI — the honest gap

### 6.1 The hard fact

The TUI's transport is **UDP** (with a TCP fallback). The browser's transport is **WebRTC**. **They
cannot speak each other's transport directly, and no amount of cleverness changes that** — the
browser physically has no UDP socket. Every path to interop therefore requires **one side to gain a
new transport**. Enumerating the real options:

| # | Option | Zero-dep? | Works? | Verdict |
|---|---|---|---|---|
| **A** | **TUI gains a WebRTC DataChannel transport** | ❌ (needs a WebRTC impl) | ✅ Yes — best latency, direct P2P | **RECOMMENDED as the fast path**, as an *optional, dynamically-imported adapter* |
| **B** | **Both sides use a Noise-over-public-WSS relay data plane** | ✅ **Yes** (Node ≥22 and every browser have a global `WebSocket`) | ✅ Yes — works through any NAT, incl. symmetric↔symmetric | **RECOMMENDED as the universal zero-dep floor** |
| C | Browser opens a WebSocket straight to the TUI | — | ❌ **NO** | Blocked twice over: an HTTPS page cannot open `ws://` (mixed content, no override — [MDN](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content)), and a `wss://` with a self-signed cert cannot be trusted programmatically ([bug 1187666](https://bugzilla.mozilla.org/show_bug.cgi?id=1187666)). A CLI cannot get a CA cert for a home IP. **Dead end.** |
| D | Browser speaks WebTransport to the TUI | — | ❌ **NO** | WebTransport is **client-only**; also needs HTTP/3 + a real cert. Same cert wall as C. |
| E | A bridge/relay process of ours | ❌ | ✅ | **Violates the prime directive: "NO backend of ours."** Rejected. |

### 6.2 Option A — a WebRTC transport for the TUI

Node has no native WebRTC. The candidates:

| Lib | Native build? | Notes |
|---|---|---|
| **`werift`** | **No — pure TypeScript** (ICE/DTLS/SCTP implemented in JS) | The **only** way to speak WebRTC from Node with **no native compilation**. DataChannels supported, actively maintained (recent Chrome-132 DTLS interop fixes). ([GitHub](https://github.com/shinyoshiaki/werift-webrtc), [npm](https://www.npmjs.com/package/werift)) |
| `node-datachannel` | Yes (N-API → libdatachannel C++) | Prebuilds for the big three platforms; battle-tested. ([npm](https://www.npmjs.com/package/node-datachannel)) |
| `@roamhq/wrtc` | Yes (native addon, WebRTC M106) | Maintained fork of the dead `node-webrtc`. ([npm](https://www.npmjs.com/package/@roamhq/wrtc)) |

**The zero-dep collision, stated plainly:** D1 says *"no build step, zero npm deps."* Every WebRTC
option is an npm dependency. `werift` at least preserves *"no native build"* (pure TS, no toolchain,
no 50 MB libwebrtc — which is what `research/transport-nat.md` §5.1 actually rejected). Its exact size
is **UNVERIFIED** but it is a full ICE+DTLS+SCTP+SRTP stack, so: substantial, certainly not "tiny."

**Recommendation (BC-6A):** ship WebRTC-for-Node as an **optional adapter, not a core dependency**:

- `src/transport-webrtc.js` is written against the **standard `RTCPeerConnection` API**. In a browser
  it uses the global. In Node it does `await import('werift')` **inside a try/catch**.
- If the import fails (nobody installed it), the TUI simply **does not offer the WebRTC transport** and
  falls back to Option B. Nothing breaks; no install is forced.
- **The shipped core library stays zero-dep.** `package.json` lists werift under
  `optionalDependencies` / `peerDependenciesMeta.optional` — installing `p2p` still pulls nothing.
- Precedent: this is exactly the shape of D11 ("vendored, optional") and D5 (a dev/CI-only audited
  Noise lib for interop testing while the shipped lib stays zero-dep). **The zero-dep rule is about
  what a user is forced to install, and this forces nothing.**

**If the owner rules that ANY optional npm dep is unacceptable**, then browser↔TUI direct-P2P is
**genuinely infeasible** and Option B is the *only* interop path. Saying so plainly, per the
escalation clause. (A from-scratch pure-JS ICE+DTLS+SCTP stack is thousands of LOC of security-critical
code — categorically outside this project's budget and a far worse risk than one optional dep.)

### 6.3 Option B — Noise over a public WSS relay (the zero-dep floor)

**The insight:** both Node ≥22 and every browser have a **native global `WebSocket`**. So both can
speak to the *same* public WSS endpoint with **zero dependencies on either side**. If we treat a
public relay as a **blind, dumb pipe carrying Noise ciphertext frames**, we get a transport that:

- works **browser↔TUI** and **browser↔browser** and **TUI↔TUI**;
- traverses **every** NAT including symmetric↔symmetric (both sides dial *out*);
- needs **no WebRTC, no TURN, no STUN, no dependency, and no server of ours**;
- leaks **nothing** — the relay sees an opaque rid-derived topic and Noise ciphertext (§8). Our
  security does not depend on it at all; it is exactly as untrusted as a tracker.

Costs, stated honestly: **latency** (two client→relay hops instead of a direct path); **throughput**
(someone else's free box); **ToS** — the public MQTT brokers surveyed in `research/rendezvous.md` §5
literally say *"please do not abuse or rely upon it for anything of importance"*; and **metadata** —
the relay operator sees the contact graph (which IPs speak under which rid) within an epoch, which is
the *same* exposure a tracker already has, and which `DESIGN.md` §3 already discloses.

Candidate relays (pick by ToS + reachability; fan out to several):
- **Public MQTT over WSS** (trystero-proven pattern; `research/rendezvous.md` §5 has the live-probe log
  and the ToS warning). MQTT framing is ~150–300 LOC, no crypto dep.
- **Nostr relays over WSS** — hundreds, free, purpose-built for blind ciphertext fan-out, and they
  double as the **offline dead-drop** (D11). Cost: NIP-01 events need **BIP340 Schnorr/secp256k1**,
  which is not native in Node *or* the browser → a vendored `noble-secp256k1` (already D11's plan).
  **This is the strongest long-term answer** — it merges the interop fallback with the P2 offline
  story — but it is not zero-vendor, so it lands in P2 alongside D11.

**Recommendation (BC-6B): build Option B as `transport-wss.js` — a small, zero-dep, blind-relay
transport that both the browser and the TUI can speak — and make it the automatic fallback when the
WebRTC path is unavailable or fails.** It is the safety net that makes the interop promise
unconditional, and it is the *only* path that keeps a strict zero-dep TUI talking to a browser.

### 6.4 Interop verdict (honest)

- **browser ↔ browser: YES, cleanly, today, with zero new infra.** WebRTC DataChannel + our existing
  tracker signaling + our Noise on top. Nothing is missing but the code.
- **browser ↔ TUI: YES, but not for free.** Direct P2P requires the TUI to gain a WebRTC transport
  (one optional pure-JS dep, `werift`; core stays zero-dep, nothing forced on any user). If even an
  optional dep is refused, interop still holds via the zero-dep WSS-relay transport (§6.3) — at the
  cost of relaying through someone else's free infrastructure, with **no loss of confidentiality or
  authenticity** (the relay is blind; Noise runs end-to-end regardless).
- **There is no third way.** The browser sandbox is the constraint, not our design.

---

## 7. Groups > 2 — seamless, E2E, infra-blind

### 7.1 Where we are

`src/group.js` (42 LOC) is **pairwise fan-out**: a group is a named set of contact keys; `send()`
loops the members and does an ordinary `peer.send()` to each over its existing Noise link (D10). It
is honest and correct — but it is a *sending helper*, not a group:

- **No group state.** No membership, no shared identity, no ordering, no history.
- **No echo to the group.** A member receiving a message does not learn *which group* it belongs to
  (the payload is raw bytes on a 1:1 link) — the receiver cannot render a coherent group thread.
- **No membership agreement.** Each member holds their own private list. Alice's "group" and Bob's
  "group" are unrelated objects that happen to overlap.
- **Sender fan-out cost is O(n) per message** — fine at this scale, but it means every member must be
  *directly connected* to every other member: an **O(n²) full mesh** of Noise links.

For "more than 2 clients, seamlessly," that is not enough. Here is the design.

### 7.2 Options considered

| Option | FS | PCS | Removal cost | Server/ordering need | Verdict |
|---|---|---|---|---|---|
| **Pairwise fan-out** (today) | per-pair, free | per-pair | free (just stop sending) | none | Correct but no group semantics. **Keep as the transport substrate, build on top.** |
| **Sender Keys** (Signal / Matrix Megolm) | ✅ one-way symmetric ratchet | ❌ not until re-key | **re-key + redistribute to survivors** (n−1 pairwise sends — trivial at n≤30) | none | ✅ **RECOMMENDED** |
| **MLS (RFC 9420)** | ✅ per epoch | ✅ per epoch | O(log n) | **wants a Delivery Service to ORDER commits** | ❌ for v1 — see below |
| **DCGKA** (Weidner et al., CCS'21) | ✅ | ✅ | — | none (built for decentralized) | ❌ **no public implementation exists** — research-grade |

**Why not MLS, concretely.** MLS's headline win is TreeKEM's O(log n) group ops — at n=30 that's
log₂30 ≈ 5 vs sender-keys' 30, i.e. **nearly invisible**; MLS is built for hundreds-to-thousands.
Meanwhile it *structurally wants a Delivery Service to impose a linear epoch order* on Commits
([RFC 9420 §3](https://www.rfc-editor.org/rfc/rfc9420.html)) — and **we have no server, by
definition**. Concurrent Commits fork the group; the decentralized-MLS variants that fix this
([draft-kohbrok-mls-dmls](https://datatracker.ietf.org/doc/draft-kohbrok-mls-dmls/), de-MLS/Waku) pay
for it with a DAG-of-epochs + **puncturable PRFs** (~8 KB/epoch) to keep FS — disproportionate
machinery for a 30-person chat. (MLS's *confidentiality* does survive a malicious DS — the objection
is the ordering requirement, not trust.) Library reality in JS 2026: `ts-mls` is pure TS + MIT but
**explicitly unaudited**; `@wireapp/core-crypto`/`openmls` are mature but **Rust→WASM + GPL-3.0**.
Neither fits "tiny, zero-dep, MIT, no build step."

**The empirical tiebreaker:** *no shipping p2p messenger in the survey runs MLS.* Briar, Tox, Berty,
Cwtch, Keet all use pairwise fan-out or a sender-keys-style ratchet; Matrix's **Megolm** is sender
keys with a different name ([spec.matrix.org — Megolm](https://spec.matrix.org/v1.18/olm-megolm/)).
Sender keys is the proven serverless answer at our scale. MLS stays the documented upgrade path if
groups ever exceed ~100 members (revisit when `ts-mls` is audited).

### 7.3 Recommended design (BC-7)

**Three thin layers on top of the pairwise Noise links we already have.** No new transport, no new
infra, no server, nothing the rendezvous can read.

**(a) Group identity & rendezvous.** A group is born from a **32-byte random group secret `G`**,
encoded as a shareable string (same Crockford base32 machinery as `key.js`). Members are found the
same way people are: `rid_group = HKDF(G, "p2p-rv-<channel>-v1", epoch, 20)`. **Zero new
mechanism — the existing rendezvous already does this**, and to a tracker a group rid is
indistinguishable from a person's rid. Everyone announcing under `rid_group` discovers everyone else,
then each pair does a **normal Noise IK handshake** using the pubkeys they exchange — so **every
group edge is an ordinary authenticated 1:1 p2p link**, with the same commitment-gate guarantee.
(Membership authorization is (c); knowing `G` gets you *discovery*, not *authorship*.)

**(b) Sender keys for content.** Each member generates a **sender key** = a 32-byte chain key + an
Ed25519 signing key. They distribute it **once**, over the existing authenticated pairwise Noise
channels (which is what makes distribution confidential *and* authenticated — no new crypto). To send:
advance the chain key one HKDF step, encrypt **once** with ChaCha20-Poly1305, **sign with the sender's
Ed25519 key**, and fan the single ciphertext to the connected members.

- **Per-sender authentication is intrinsic** — the Ed25519 signature says *who wrote it*, and no other
  member can forge it (a plain shared group key would let any member impersonate any other; this
  closes that).
- **Forward secrecy: yes** — the chain ratchets one-way; past messages are unrecoverable from a
  current chain key.
- **Post-compromise security: no, until rotation.** Stated honestly — this is the known sender-keys
  gap ([arXiv 2301.07045](https://arxiv.org/pdf/2301.07045)). Mitigation: **rotate on every membership
  change and periodically** (cheap here — a rotation is n−1 pairwise sends). It is exactly the FS
  posture the TUI already has (session-granular, no in-session ratchet, D4) — **so the group is not
  weaker than the 1:1 chat it is built from.**
- **Removal:** rotate the sender key and redistribute **to survivors only**. The removed member's copy
  of the old chain is now useless for anything future. O(n) pairwise sends — trivial at n≤30.

**(c) Membership + ordering: one signed hash-chain.** Both problems have the same answer, and it costs
one data structure:

- Every **membership op** (`create` / `add` / `remove` / `rotate`) is **signed by its author** and
  **hash-links to the ops it saw** — an append-only, tamper-evident DAG (git-like). Current membership
  = a **deterministic fold over the chain**, so every member computes the same answer with no server.
  Prior art: [local-first-web/auth](https://github.com/local-first-web/auth) (MIT, TS, Keybase-Teams
  lineage) — adoptable as a library, or ~150 LOC in-house.
- Every **chat message** likewise references the parent hashes it saw → **causal order** reconstructed
  locally, git-style. This is what Briar's Bramble Sync and Matrix's event DAG both do. Signatures
  come free from (b), so it is Byzantine-safe in a way vector clocks alone are not.
- **Authorization policy v1:** admin-signed (the creator, plus anyone they promote). Simple, matches
  Briar's private groups.
- **Fork/split-brain, honestly:** two admins partitioned can concurrently produce divergent chains. The
  deterministic fold + hash-linking makes divergence **detectable** (different chain heads), never
  silent. v1 resolves with a deterministic tie-break + a visible "membership diverged" surface; nobody
  in this space (including Matrix's state-res v2) prevents a *malicious* admin from forking — only
  detects it. Documented, not hidden.

**Mesh & relaying.** Members maintain a full mesh where they can. When a pair can't connect directly
(symmetric NAT — §5.4), the message reaches them via **another member relaying the ciphertext**: the
sender-key ciphertext is already E2E and signed, so a relaying member **cannot read or forge it** — it
is exactly as blind as a TURN box. This is the same peer-relay primitive as §5.4(2), and it is what
makes the group "seamless" when the mesh is incomplete.

### 7.4 What this buys, versus what exists

| | today (`group.js`) | recommended |
|---|---|---|
| Encryptions per message | n (one per member) | **1** (+ n sends) |
| Group state / membership | none (local list) | **signed hash-chain, deterministic, agreed** |
| Sender authentication | implicit (1:1 link) | **explicit Ed25519 per message** — no member can impersonate another |
| Ordering | none | **causal DAG** |
| Removal | remove from a local list (others may still send to them) | **key rotation** — cryptographically ejected |
| Infra sees | opaque rid + ciphertext | **opaque rid + ciphertext** (unchanged — still blind) |
| Members who can't connect directly | silently unreachable | **relayed blind through another member** |

**Migration is additive:** `group.js` keeps its `send()` signature. The sender-key + hash-chain layers
slot underneath it. Browser and TUI implement the *same* three layers — it is all plain JS above the
transport, so **group interop follows automatically from 1:1 interop** (§6).

---

## 8. THREAT MODEL — why the browser client leaks nothing, and is ≥ the TUI

### 8.1 The core argument

**The security of a p2p session does not depend on the transport.** It never did — that is why the
TUI's design works over a hostile UDP internet. The full security argument is:

1. **The 26-char key is a commitment** to `(edPub, xPub)`: `first110(SHA256("p2p-id-v1"‖ed‖x))`.
   Second-preimage bound **2^110** (DESIGN D2).
2. **The gate** rejects any HELLO whose pubkeys don't hash to that commitment. (Cheap pre-filter — it
   proves nothing on its own, and `node.js:272` correctly treats it as such.)
3. **Noise IK** then runs with the responder's static X25519 key *pinned by that commitment*. The
   initiator's ability to **decrypt msg2** is possible only for a party holding the **static private
   key** committed to by the string. That decrypt **is** the key confirmation — the MITM proof.
4. **`Split()`** yields per-direction ChaCha20-Poly1305 keys with per-session ephemerals ⇒ forward
   secrecy at session granularity.

**Every one of those four steps is transport-independent, and every one runs identically in the
browser** (§3 proves each primitive is available and byte-compatible). Therefore an attacker who
**fully controls the tracker, the STUN server, a TURN relay, the WSS relay, and every router on the
path** is in *exactly the position the TUI's threat model already assumes*, and gains exactly nothing:

- They see an **opaque rid** (HKDF of a 130-bit secret — a non-holder cannot compute or invert it).
- They see **ciphertext** (WebRTC DTLS on the outside; **our Noise AEAD on the inside**).
- They can **substitute keys in the SDP** — WebRTC's DTLS fingerprints are self-signed and
  MITM-able at signaling, which is the classic WebRTC weakness. **It buys them nothing:** they'd own
  the DTLS layer and still face the Noise handshake underneath. Without the committed X25519 static
  private key, they cannot produce a msg2 the initiator can decrypt. **The handshake fails closed.**
  Forgery bound ≤ max(2⁻¹¹⁰, 2⁻¹²⁸) (`research/crypto-firstcontact.md` §10).
- They can **drop, delay, or DoS** — availability, not confidentiality. Same as the TUI.

**This is the crux and it is worth stating loudly: we do not trust WebRTC's security at all.** DTLS is
a redundant outer wrapper. If DTLS were removed entirely, our security claim would be unchanged. That
is what makes the browser client's guarantee *equal* to the TUI's rather than *dependent on* the
browser's crypto stack.

### 8.2 Browser vs TUI — side by side

| Property | TUI (UDP) | Browser (WebRTC) | Δ |
|---|---|---|---|
| Identity binding | 26-char commitment, 2^110 | **identical** | **=** |
| First-contact MITM proof | Noise IK msg2 decrypt | **identical, same bytes** | **=** |
| AEAD | ChaCha20-Poly1305 (native OpenSSL) | ChaCha20-Poly1305 (**vendored, Cure53-audited noble**) | **=** on protocol; ⚠️ not formally constant-time in JS (§3.4) |
| Forward secrecy | session-granular (no ratchet) | **identical** | **=** |
| Transport encryption | none beneath Noise (raw UDP) | **DTLS beneath Noise** | **browser +1** (redundant extra layer) |
| What the rendezvous sees | opaque rid + IP | **opaque rid + IP** | **=** |
| What a relay sees | (peer-relay, P2) ciphertext | TURN/WSS relay: **ciphertext only** — DTLS terminates at the peers, and Noise under it | **=** |
| Discovery channels | mDNS + DHT + trackers | **trackers only** | **browser −1** (availability, not confidentiality) |
| Symmetric↔symmetric NAT | can birthday-punch (P2) | **cannot** — needs a relay | **browser −1** (availability, not confidentiality) |
| Key material at rest | file, `0600` | **browser storage** — see §8.3 | **needs care** |
| Code delivery | `npm`/installer, pinned | **served fresh from a web origin every load** — see §8.4 | **the one real new attack surface** |

**Conclusion: on the wire, the browser client is exactly as secure as the TUI — provably, because it
runs the same handshake with the same keys over an untrusted pipe — and it adds a redundant DTLS
layer on top. The two genuine losses are availability-only (fewer discovery channels, no
birthday-punch). The two genuine new risks are local, not network: key storage and code delivery.**

### 8.3 New risk 1 — key storage in a browser

The TUI writes `~/.p2p/default.json` at `0600`. A browser has no such thing. Options, ranked:

1. **Non-extractable `CryptoKey` in IndexedDB** — WebCrypto keys can be stored with
   `extractable: false`; the private scalar is then **never exposed to JS**, even to our own code, and
   XSS cannot exfiltrate it (it can only *use* it while the page is live). **This is strictly stronger
   than the TUI's on-disk 0600 file** against a malware-reads-your-disk attacker.
   ⚠️ **Conflict:** our Noise impl needs raw scalars? — **No.** It needs *DH operations*, which
   `deriveBits` performs on a non-extractable key handle. **So the static X25519 private key can be
   non-extractable.** (Ephemerals are per-session and can be too.) The only thing this breaks is
   *exporting your identity to another device* — make that an explicit, deliberate "export key"
   action that generates an extractable copy (or simply generate a fresh identity per device and let
   the user hold multiple keys).
2. Encrypted-at-rest blob in IndexedDB under a passphrase-derived key (PBKDF2/Argon2-in-WASM). Needed
   only if identity portability is required.
3. ❌ **Never `localStorage`** (plain text, trivially XSS-readable).

**Decision (BC-8): default to a non-extractable X25519 static key in IndexedDB.** Add explicit,
user-initiated export if identity portability is wanted.

### 8.4 New risk 2 — code delivery (the honest asymmetry)

**This is the one place a browser client is structurally weaker than a CLI, and it must be stated
plainly:** the TUI is installed once and pinned; **a web page is re-fetched from an origin on every
load.** Whoever controls the origin (or a CDN, or a TLS cert for it) can serve *different JavaScript
tomorrow* — code that simply prints the plaintext to an attacker. No amount of Noise fixes that; the
crypto is only as trustworthy as the code implementing it.

This is not a p2p-specific flaw — it is the well-known critique of all browser-delivered E2E crypto —
but our threat model says "nothing interceptable outside the authorized clients," so we owe the user
honesty and mitigations:

- **Subresource Integrity + a fully static, self-contained page** (no CDN, no external scripts, no
  analytics, no fonts). A strict **CSP** with no `unsafe-inline` and no third-party origins.
- **Reproducible build + published hash**, so a user (or a watchdog) can verify the served bytes
  match the audited source. Publish the hash in the repo and in release notes.
- **Ship an installable, pinned artifact for anyone who wants it**: a signed browser
  extension / PWA-with-a-pinned-cache, which restores the "installed once" property. (P2.)
- **Document it.** The README must say: *the browser client is as secure as the TUI on the wire, but
  it trusts whoever serves the page; if you need the strongest guarantee, run the TUI.* Anything less
  would be dishonest, and the project's own doc culture ("Verification status (honest)") demands it.

### 8.5 Residual risks inherited from the TUI (unchanged)

Stated for completeness, all identical to `DESIGN.md` §3: session-granular FS (no in-session ratchet
⇒ no post-compromise security); the rendezvous operator sees the contact graph within an epoch;
presence-privacy holds only against non-holders of `S`; any `S`-holder can dial-DoS; pre-quantum
harvest-now-decrypt-later.

---

## 9. Security proof sketch — why the browser client is ≥ the TUI

**Setup.** Let `S` be Alice's 26-char string, committing to `(edA, xA)` via
`c = first110(SHA256("p2p-id-v1" ‖ edA ‖ xA))`. Bob holds `S`. The adversary 𝒜 controls: the WSS
trackers, every STUN server, any TURN/WSS relay, the whole network path, and may inject, drop,
reorder, replay and forge at will (i.e. 𝒜 **is** the transport). 𝒜 does **not** hold `xA`'s private
scalar and does **not** hold `S`… *(and even if 𝒜 holds `S` — it is public to holders — see step 5)*.

**Claim.** 𝒜 cannot read, forge, or MITM the session. Identical claim, identical bound, to the TUI's
(`research/crypto-firstcontact.md` §10).

1. **Rendezvous leaks nothing.** Bob publishes/looks up `rid = HKDF(S, salt, epoch, 20)`. HKDF-SHA256
   is a PRF; without `S` (130 bits), `rid` is indistinguishable from random and one-way. 𝒜-as-tracker
   sees an opaque 20-byte id and an IP. **Identical to the TUI — same function, same inputs, byte for
   byte (§3.3).**
2. **The signaling channel is untrusted by construction.** 𝒜 may rewrite the SDP freely, substituting
   its own DTLS fingerprint and ICE candidates. It therefore *can* own the WebRTC/DTLS layer end to
   end. **We concede this entirely — and it gains 𝒜 nothing**, because:
3. **The gate binds the pubkeys to the string.** Alice's HELLO carries `(edA, xA)`; Bob accepts only
   if they hash to `c`. To pass the gate with keys of its own, 𝒜 must find `(ed', x') ≠ (edA, xA)`
   with a colliding 110-bit commitment: **second-preimage work 2¹¹⁰.**
4. **Noise IK is the actual authentication.** Bob runs IK as initiator with `remoteXPub = xA` — the key
   *pinned by the commitment*. msg2 (`e, ee, se`) is decryptable only by a party who can compute `se`,
   i.e. who holds **xA's private scalar**. 𝒜, sitting in the middle with its own keys, cannot produce
   a msg2 that Bob decrypts. `noise.js` throws `HandshakeError` on tag failure and **fails closed**
   (`node.js:281`). So **Bob's successful msg2 decrypt is a proof of no-MITM** — the "first ack."
   Forgery bound **≤ max(2⁻¹¹⁰, 2⁻¹²⁸)**.
5. **A malicious relay (TURN, WSS-relay, or a peer-relay) is blind.** It carries DTLS-wrapped SCTP
   (or raw Noise frames on the WSS path). Under either, the payload is a **Noise AEAD frame from
   `Split()`** — ChaCha20-Poly1305 under a key derived from an X25519 handshake it did not
   participate in. It cannot decrypt (IND-CPA/CCA of ChaCha20-Poly1305), cannot forge (Poly1305 tag),
   cannot replay (the Noise nonce counter is strictly increasing and never reused —
   `noise.js:139`), and cannot MITM (step 4). **Even an 𝒜 that holds `S` gains only the ability to
   *find* Alice and to *dial-DoS* her — never to impersonate her or read a byte** (that is exactly
   D2's stated privacy scope).
6. **Forward secrecy.** Ephemerals are fresh per session; `Split()` keys are discarded at session end.
   Compromising a static key later does not decrypt recorded sessions. **Identical to the TUI** —
   session-granular, no in-session ratchet (the same honest limitation, not a new one).

**Therefore:** the browser's guarantee is *the same theorem with the same bound*, because it is
literally the same protocol over a different pipe — and the pipe was never in the trust base. The
browser additionally wraps everything in DTLS (a layer the TUI lacks), which is **defense in depth we
never rely on**.

**The two places the browser is genuinely different — stated without spin:**

- **Availability, not confidentiality:** fewer discovery channels (trackers only) and no
  birthday-punch escape from symmetric↔symmetric NAT. A browser pair can *fail to connect* where a TUI
  pair would succeed. It cannot be *silently spied on*.
- **Local trust, not wire trust:** the code is served from an origin on every load (§8.4), and the
  vendored ChaCha20 is not formally constant-time in JS (§3.4). These are real, they are honest, and
  neither is a network-observable weakness. **On the wire — the property the owner asked for
  ("nothing interceptable, decodable, or monitorable outside the authorized clients") — the browser
  client is exactly equal to the TUI.**

---

## 10. What's buildable now vs. the real gaps

### ✅ Buildable today, no blockers

| Piece | Basis |
|---|---|
| `key.js` in the browser (keygen, encode/decode, checksum, gate, `deriveRid`) | WebCrypto X25519/Ed25519/SHA-256/HKDF — all shipped in all 3 engines (§3.1) |
| `noise.js` in the browser — byte-identical `Noise_IK_25519_ChaChaPoly_SHA256` | WebCrypto + one vendored 3 KB audited ChaCha20-Poly1305 (§3.4); our own DER constants reused verbatim (§3.2) |
| Tracker signaling from a browser | `tracker.js` already uses the global `WebSocket` + the same `infoHashFor(rid)` (§4.1) |
| WebRTC DataChannel transport behind the existing endpoint seam | `RTCPeerConnection` is universal; `node.js` needs **zero changes** (§1, §5.3) |
| browser ↔ browser chat across different NATs | ICE + free public STUN, ~85% direct (§5.4) |
| App semantics (MSG/ACK, outbox, reconnect, peer identity, friends) | pure JS in `node.js` — ports unchanged |
| Sender-keys groups + signed membership chain | pure JS above the transport — same code on both clients (§7) |

### ⚠️ The real gaps (ranked by how much they hurt)

1. **browser ↔ TUI needs the TUI to gain a transport it doesn't have.** *This is the biggest gap, and
   it is unavoidable* — a browser has no raw UDP, forever. Either the TUI takes an **optional pure-JS
   WebRTC dep** (`werift`) or both sides use the **zero-dep WSS-relay** transport. **Owner decision
   required** (§6). There is no option that is simultaneously (a) direct P2P, (b) zero-dep on the TUI,
   and (c) browser-compatible. Anyone who claims otherwise has not read the browser sandbox rules.
2. **Symmetric↔symmetric browser pairs cannot connect without a relay.** No birthday-punch in a
   browser, ever. Covered by peer-relay or the WSS-relay; not by cleverness. (~15% of pairs need
   *some* relay; the both-symmetric subset is smaller still.)
3. **Trackers become load-bearing** for any browser connection (no DHT, no mDNS). Single channel =
   single point of failure. Mitigate: wider tracker pool now; a second browser-reachable signaling
   channel (nostr-over-WSS) in P2.
4. **Code-delivery trust** (§8.4) — mitigable (static page, CSP, SRI, reproducible build, published
   hash, eventually a signed extension/PWA) but never fully eliminable. Must be documented honestly.
5. **Vendored ChaCha20 is not formally constant-time in JS** (§3.4). Low risk for this threat model;
   swap to a libsodium WASM build if the model ever changes.
6. **`werift`'s real size is UNVERIFIED** — it is a full ICE+DTLS+SCTP stack, so "not tiny." Must be
   measured before committing to Option A (§12).

### ❌ Impossible — do not attempt

- A browser on the BitTorrent DHT (raw UDP) — [webtorrent#288](https://github.com/webtorrent/webtorrent/issues/288).
- A browser doing mDNS, STUN-by-hand, hole-punching, or port prediction.
- A browser **accepting** any inbound connection (no WebSocket server, no WebTransport server).
- A browser talking `ws://` from an HTTPS page, or trusting a CLI's self-signed `wss://` cert
  ([MDN mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content)).

---

## 11. Phased build plan

**P0 — spike gates** (kill-criteria first, exactly as `DESIGN.md` §5 did). Each is a throwaway page
under `spikes/`; any failure escalates before a line of real code:

- **G1 — crypto parity.** In a real browser: run the **official Noise KAT vector** (`test/vectors/`)
  through the browser port of `noise.js` and assert **byte-exact** equality with the Node
  implementation, both directions. *This is the interop gate. Nothing proceeds if it fails.*
- **G2 — signaling parity.** A browser page derives `rid` from a key and completes an offer/answer
  exchange with a **Node peer running the existing `tracker.js`** on a public tracker. Proves the
  browser reuses our rendezvous with zero new infra.
- **G3 — DataChannel handshake.** Two browsers on **different networks/NATs** open a DataChannel and
  complete the **full HELLO → gate → IK** flow over it, ending in a decrypted msg2.

**P1 — the browser client (browser ↔ browser, shippable on its own).**
`crypto-webcrypto.js` (primitive adapter) · vendored `chacha.js` (pinned + hash-checked) ·
`transport-webrtc.js` (the only genuinely new module) · browser `tracker.js` (Buffer → Uint8Array) ·
non-extractable-key storage (§8.3) · a static page served over HTTPS with a strict CSP. `key.js`,
`noise.js`, `node.js`, `group.js` are shared source. **Deliverable: two browsers on different
networks chat, E2E, with a verified no-MITM first ack — and the page is served from the existing
static host with no backend.**

**P2 — interop (the owner-decision phase).** Land **both** paths and let them race, exactly like the
rendezvous channels do:
  - **`transport-wss.js`** — zero-dep blind-relay transport (§6.3), works browser↔TUI↔browser through
    any NAT. This is the floor: it makes the interop promise unconditional.
  - **`transport-webrtc.js` in Node** via an **optional, dynamically-imported `werift`** (§6.2), so a
    user who wants direct browser↔TUI P2P installs one optional dep and the core stays zero-dep.
  **Gate:** a **TUI ↔ browser chat across two real networks**, plus the byte-exactness assertion from
  G1 holding on the live wire.

**P3 — groups (§7).** Sender keys + signed membership hash-chain + causal DAG ordering + blind
peer-relay for incomplete meshes. Same code both clients, so browser and TUI join the same group.
Gate: a 3-way chat with **one browser and two TUIs on three networks**, then a member removal that
provably ejects the removed party (they can no longer decrypt).

**P4 — hardening.** Reproducible build + published hash; signed extension/PWA (pins the code, closing
§8.4); second browser signaling channel (nostr-over-WSS) to de-risk gap #3; optional user-supplied
TURN field; an in-browser `p2p doctor` (ICE/STUN/tracker diagnostics, mirroring the CLI's).

---

## 12. Decisions (BC-table) + open questions

| # | Decision | Rationale |
|---|---|---|
| **BC-1** | **Browser transport = WebRTC DataChannel** (reliable+ordered), behind the existing `createEndpoint`/`punch`/`onConnection` seam | The only P2P primitive a browser has. Seam already exists → `node.js` unchanged (§1, §5) |
| **BC-2** | **Signaling = our existing WSS tracker matchmaker**, same `rid`, same `infoHashFor` — real SDP where we currently put a fake one | Zero new infra; the code is already written and browser-native (§4) |
| **BC-3** | **Vendor ChaCha20-Poly1305** (`@noble/ciphers` chacha subset, ~3 KB gz, Cure53-audited, pinned in-tree). **Reject AES-GCM** for the default path | Keeps ONE wire format → TUI interop. AES-GCM is a *different Noise suite with different nonce endianness* — it would fork the protocol (§3.4). Closes `crypto-firstcontact.md` §12's open question in favor of its own recommendation |
| **BC-4** | **WebRTC/DTLS, trackers, STUN and any TURN are all UNTRUSTED.** Noise IK + the commitment gate run on top, exactly as over UDP | This is what makes browser security **=** TUI security rather than dependent on the browser's stack (§8, §9) |
| **BC-5** | Over a DataChannel, **skip `wire.js`'s ARQ** (SCTP already gives reliable+ordered) but **keep the frame types and the app-level outbox/ACK** | Reconnect-survival lives in `node.js`, not SCTP. Handshake + app bytes stay identical across transports (§5.3) |
| **BC-6** | **Two interop paths:** (a) optional, dynamically-imported `werift` gives the TUI a WebRTC transport (core stays zero-dep — nothing forced on any user); (b) a **zero-dep WSS-relay** transport as the universal floor | A browser can never speak UDP. One side must gain a transport. (a) is fast and direct; (b) is unconditional and dep-free (§6) |
| **BC-7** | **Groups = sender keys + signed membership hash-chain + causal DAG**, over the existing pairwise Noise mesh, with blind peer-relay for unreachable members | Proven serverless shape (Megolm/Berty/Briar). MLS needs an ordering DS we don't have and wins nothing at n≤30 (§7) |
| **BC-8** | **Static X25519 key stored non-extractable in IndexedDB**; explicit user-initiated export only. Never `localStorage` | Noise only needs `deriveBits`, not the raw scalar → the private key never touches JS. Strictly stronger than the TUI's `0600` file against disk-reading malware (§8.3) |
| **BC-9** | **Ship the honest caveat in the README:** on the wire, browser = TUI; but the browser trusts whoever serves the page. For the strongest guarantee, run the TUI | The project's own doc culture ("Verification status (honest)") requires it (§8.4) |

### Open questions for the owner

1. **BC-6 is the one real decision.** Is an **optional** (never auto-installed) pure-JS npm dependency
   acceptable to unlock direct browser↔TUI P2P? If **no**, browser↔TUI works **only** via the
   WSS-relay path — still E2E-secure and still no backend of ours, but relayed through someone else's
   free infrastructure, with the latency and ToS caveats of §6.3. **Escalating this explicitly, per
   the brief: there is no zero-dep, direct-P2P, browser↔TUI option. The browser sandbox forbids it.**
2. **Which public WSS relay** for the zero-dep fallback (MQTT-over-WSS now, vs waiting for
   nostr-over-WSS in P2 which needs the D11 vendored secp256k1 but also buys the offline dead-drop)?
3. **Group size target** — the §7 design is sized for ≤30 (the same question `DESIGN.md` §7.3 already
   asked). If groups of hundreds matter, revisit MLS when `ts-mls` has been audited.

### UNVERIFIED / to measure before committing

- **`werift`'s actual bundle size and LOC** — not published; it is a full ICE+DTLS+SCTP stack, so
  "substantial." **Measure before BC-6(a) is ratified.**
- **Public WSS tracker rate limits** — no published numbers; treat as best-effort, no SLA.
- **`stun.l.google.com` ToS/SLA** — no official document found; community consensus is "fine, don't
  rely on it alone." Ship a list.
- The oft-quoted **"Google: 8–15% of WebRTC calls need TURN"** — **could not be traced to a primary
  source. Do not cite it.** Twilio's **~15%** is the solid published figure.
- **Safari's exact Ed25519 version** (sources say 17.x; X25519 is firmly Safari 18.4).
- **Nothing in this document has been run in a browser yet.** Every claim about our own code is
  verified by reading `src/` on disk; every browser claim is sourced. **G1–G3 (§11) exist to convert
  this from sourced to observed.** Honest status: **DESIGNED, NOT YET DEMONSTRATED.**

---

## 13. Sources

**Browser crypto:** [WICG Secure Curves](https://wicg.github.io/webcrypto-secure-curves/) ·
[chromestatus X25519](https://chromestatus.com/feature/6291245926973440) ·
[chromestatus Ed25519](https://chromestatus.com/feature/4913922408710144) ·
[Firefox bug 1904836 (X25519)](https://bugzilla.mozilla.org/show_bug.cgi?id=1904836) ·
[WebKit Safari 18.4](https://webkit.org/blog/16574/webkit-features-in-safari-18-4/) ·
[MDN importKey](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey) ·
[MDN deriveBits](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveBits) ·
[MDN Crypto.subtle (secure context)](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/subtle) ·
[w3c/webcrypto#223 — ChaCha20 (open since 2019)](https://github.com/w3c/webcrypto/issues/223) ·
[WICG Modern Algorithms](https://wicg.github.io/webcrypto-modern-algos/) ·
[@noble/ciphers (Cure53-audited)](https://github.com/paulmillr/noble-ciphers) ·
[libsodium.js](https://github.com/jedisct1/libsodium.js/) ·
[Noise spec (nonce endianness)](https://noiseprotocol.org/noise.html)

**WebRTC / transport:** [RFC 8831 (DataChannels)](https://datatracker.ietf.org/doc/html/rfc8831) ·
[RFC 8832 (DCEP)](https://www.rfc-editor.org/rfc/rfc8832.html) ·
[MDN — Using data channels](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Using_data_channels) ·
[Grahl — DC size limits](https://lgrahl.de/articles/demystifying-webrtc-dc-size-limit.html) ·
[Mozilla — large DC messages](https://blog.mozilla.org/webrtc/large-data-channel-messages/) ·
[Twilio — networking (≈15% relay)](https://www.twilio.com/docs/video/networking-considerations) ·
[Tailscale — how NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works) ·
[webrtcHacks — symmetric NAT](https://webrtchacks.com/symmetric-nat/) ·
[MDN — WebTransport (client-only)](https://developer.mozilla.org/en-US/docs/Web/API/WebTransport_API) ·
[MDN — mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content) ·
[Mozilla bug 1187666 (self-signed WSS)](https://bugzilla.mozilla.org/show_bug.cgi?id=1187666) ·
[werift (pure-TS WebRTC)](https://github.com/shinyoshiaki/werift-webrtc) ·
[node-datachannel](https://www.npmjs.com/package/node-datachannel) ·
[@roamhq/wrtc](https://www.npmjs.com/package/@roamhq/wrtc) ·
[Open Relay TURN](https://www.metered.ca/tools/openrelay/) ·
[libp2p circuit-relay-v2](https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md) ·
[libp2p WebRTC in the browser](https://libp2p.io/docs/webrtc-browser-connectivity/)

**Signaling / discovery:** [bittorrent-tracker (WS protocol de-facto spec)](https://github.com/webtorrent/bittorrent-tracker) ·
[webtorrent#288 — no DHT in browser](https://github.com/webtorrent/webtorrent/issues/288) ·
[webtorrent#1467 — no udp:// trackers](https://github.com/webtorrent/webtorrent/issues/1467) ·
[trystero](https://github.com/dmotz/trystero) ·
[ngosang/trackerslist](https://github.com/ngosang/trackerslist) · [newtrackon](https://newtrackon.com/)

**Groups:** [Signal — private group messaging](https://signal.org/blog/private-groups/) ·
[Matrix — Megolm](https://spec.matrix.org/v1.18/olm-megolm/) ·
[Sender Keys analysis (arXiv 2301.07045)](https://arxiv.org/pdf/2301.07045) ·
[RFC 9420 (MLS)](https://www.rfc-editor.org/rfc/rfc9420.html) ·
[draft-kohbrok-mls-dmls](https://datatracker.ietf.org/doc/draft-kohbrok-mls-dmls/) ·
[DCGKA (Weidner et al., CCS'21)](https://eprint.iacr.org/2020/1281.pdf) ·
[ts-mls](https://github.com/LukaJCB/ts-mls) · [openmls](https://github.com/openmls/openmls) ·
[local-first-web/auth](https://github.com/local-first-web/auth) ·
[Briar — how it works](https://briarproject.org/how-it-works/) ·
[Berty protocol](https://berty.tech/docs/protocol/) · [Cwtch](https://docs.cwtch.im/)

**In-repo (read on disk 2026-07-12):** `DESIGN.md` (D1–D12) · `docs/HOW-IT-WORKS.md` ·
`docs/INTERFACES.md` · `research/crypto-firstcontact.md` (§7.3, §10, §12) ·
`research/rendezvous.md` (§3, §5) · `research/transport-nat.md` (§3, §5.1) · `research/prior-art.md`
(trystero) · `src/key.js` · `src/noise.js` · `src/node.js` · `src/wire.js` · `src/transport.js` ·
`src/group.js` · `src/rendezvous/tracker.js` · `src/rendezvous/race.js`

---

*End of study. A senior engineer can build the browser client from §2 (architecture), §3 (crypto),
§4 (signaling), §5 (transport), §6 (interop), §7 (groups) and §11 (phases) without re-researching —
and defend it with §8–§9. Every load-bearing claim carries a URL; §12 lists everything UNVERIFIED.
Honest status: **DESIGNED, NOT YET DEMONSTRATED** — G1–G3 are the gates that change that.*
