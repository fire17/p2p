# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0: minor bumps may carry breaking changes).

## [0.3.3] — 2026-07-13

Internal reliability + safety hardening — no user-facing behavior change. Every fix gated.

### Fixed

- **Group self-heal is correctly bounded.** The KEYREQ pull now shares one budget across both pull
  paths (was `1 + MAX` — two "bounded" paths whose sum wasn't), and a member that reconnects after
  exhausting its budget is pulled again instead of being permanently given up on.
- **One record per peer.** Dialing a peer that had already reached you inbound no longer opens a
  duplicate connection / second Noise session (the two peer-table keyings are now bridged by the
  key's commitment). Bonus: messages queued while a peer was down replay on reconnect.

### Safety / tests

- A **live-egress sweep** now fails the build if any test reaches the real network without a gate —
  it caught two harnesses that were dialing public brokers on every run, "safe" only because a dev
  dependency happened to be absent. Plus a first-run-mints regression test for the storage guard.

## [0.3.2] — 2026-07-12

### Added / Fixed

- **Boot guard — the site can never silently hang again.** If the app fails to start it now shows the
  actual reason (too-old browser → "needs iOS 16.4+/Chrome 89+", a file missing from the server, a
  thrown error, or blocked storage) instead of an endless "booting…". Ships `app/boot-guard.js` (the
  file v0.3.1 already referenced — resolves a dangling 404) plus a deploy-graph test that walks the
  real module graph and fails CI on the exact class of bug that took the site down (Jekyll-excluded
  files, CSP-hash drift) — a green unit suite is no longer enough to call a deploy healthy.
- **IndexedDB hang + data-integrity guards.** `indexedDB.open` can throw, block, or never settle on
  mobile (esp. private mode) — that used to hang the boot forever; now guarded with a 5s timeout that
  reports the reason. And `identity()` no longer silently mints a fresh key on top of broken storage
  (a key that couldn't survive a reload) — a storage failure is fatal and explained.
- **Faster tui→web dial** — a terminal dialing a browser no longer waits ~13s for the rendezvous
  stream to drain; it punches as soon as the relay is reachable, while a direct UDP path still races
  and wins whenever it lands (WAN tui↔tui is unaffected — it never touches the relay).
- **CLI Ctrl+C always exits, everywhere** — the last front-end (`p2p group`) joins the rest; a hung
  peer can no longer trap any of `p2p`, `p2p connect/chat`, `p2p-tui`, or `p2p group`.

Minimum browser (import-map floor): Safari 16.4+, Chrome 89+, Firefox 108+, Samsung Internet 15+.

## [0.3.1] — 2026-07-12

### Fixed

- **CRITICAL — the live site (p2p.akeyo.io) was broken for every cold-cache visitor.** GitHub Pages
  runs Jekyll, which silently excludes `_`-prefixed files; four vendored crypto files
  (`_md.js`, `_u64.js`, `_arx.js`, `_poly1305.js`) 404'd, so the ES-module graph failed to load and
  the app never booted — it hung on "booting…" with no error. Fixed with a repo-root `.nojekyll`.
  (Mobile was the first to hit it, having no warm cache; desktop was masked by cached assets.)
- **Group self-heal hardened** — the KEYREQ pull is bounded (≤8 per gap) and the held-message stash
  is bounded (16/sender, evict-oldest), so an unreachable, chatty member can't storm the network or
  grow memory (fixes a self-heal storm in the 0.3.0 group delivery fix).

## [0.3.0] — 2026-07-12

The reliability + hardening release. **Breaking protocol bump from 0.2.0** — the authenticated
wire control-plane (WIRE MAC) and signed group `init` are fail-closed-incompatible with 0.2.0
peers, so the fleet moves together. Shipping with known gaps listed below (a reship follows);
everything claimed is backed by a test or a gated review.

### Fixed / Added

- **web↔web reliability — the "50%" is gone.** Root cause was a duplicate-default-identity
  *zombie*: two browser tabs both booted the `default` identity, both answered an incoming dial,
  one won and the other sat **connected-but-deaf**, so half your messages landed in the wrong tab.
  An identity is now **single-live per browser** (Web Locks, fails open — never blocks going online),
  and a second default tab **auto-adopts a fresh identity** with a banner explaining the key change.
- **tui↔web actually connects.** The Node/CLI peer now composes the **WSS relay** into its default
  endpoint, so a terminal and a browser share a transport (a browser can't speak UDP). Verified live
  over a public relay; `wss:false` opt-out keeps a UDP-only node.
- **Group code checksum** — a mistyped group code now fails **loudly** at paste instead of silently
  dropping you into a different, empty "ghost" group.
- **Terminal groups** — `p2p group new / join`, sender-keys + signed membership chain, wire-compatible
  with the browser group client (same code puts a terminal and a browser member in one group).
- **CLI Ctrl+C always exits** — a hung or failed peer can no longer trap the process (raw-mode Ctrl+C
  is force-handled; teardown awaits nothing). Plus **↑/↓ sent-message history** and **scrollback**.
- **Metadata privacy** — invite-mode **mDNS TXT is now sealed** (no plaintext IP/port on the LAN;
  tracker + DHT were already sealed), authenticated **wire control-plane** (16-byte MAC over every
  control frame), and **burn-after-connect** (a one-time invite goes dark the instant its invitee
  connects — no re-use, no trail).
- **Installer integrity** — the install script pins and verifies the app source archive.
- **Test safety** — every real-network test is gated behind `P2P_LIVE=1`; a plain `npm test` now
  emits **zero** off-box traffic (audit closed two pre-existing live-traffic leaks).

### Known gaps (shipping as-is; reship to follow)

- **Group delivery to a browser member** can warn `no-sender-key` — the sender key was being sent via
  a reverse dial a browser can't make; a fix (ride the existing channel + self-heal) is in progress.
- **Mobile browsers** may stick on "booting…" — under investigation.
- **tui→web dial** can take ~10s (browser→tui is fast) — a fix to punch on first candidate is queued.

## [0.2.0] — 2026-07-12

The release that gives p2p **a second runtime, a private front door, and real groups**. Every
claim below is backed by a test or a witnessed live run (`docs/ACCEPTANCE-LOG.md`); the honest
gaps are listed at the bottom rather than omitted.

### Added

- **Browser client — the same peer, in a tab.** The browser loads the *same* protocol source the
  terminal runs (`key.js`, `noise.js`, `wire.js`, `node.js`, `group.js`) over a `node:crypto` →
  WebCrypto shim. Same key format, same commitment gate, same Noise IK, same MITM proof. Witnessed
  in a real browser: **browser ↔ browser**, and **browser ↔ TUI** over both a WebRTC DataChannel and
  the zero-dependency WSS relay — a paired witness, not two self-reports. Ships **pair chat, group chat,
  and deep links** (`/app/#<KEY>` → dial box, `/app/#<group-code>` → join box) — each witnessed in real
  browsers, the group flow driven end to end through the shipped buttons.
- **Private one-time invites — metadata privacy v1.** `p2p invite` mints a 128-bit `K_inv` and
  publishes presence under it: the rendezvous id is `HKDF(K_inv,…)` (a non-holder cannot even
  *locate* the record), candidates are AEAD-sealed under `HKDF(K_inv,"ip")` and padded to a fixed
  length, the DHT leg moves from plaintext `announce_peer` to **encrypted BEP44**, and the handshake
  upgrades to **Noise IKpsk2** (only the invitee can complete it). Public API: `listen(id, {invite})`
  and `connect('S-<tail>')`. **Witnessed live over the public rendezvous** (real Mainline DHT +
  public WSS trackers, mDNS removed) — IP never in the clear on any public channel.
- **Sender-key groups (>2).** One encryption per message, fanned out as a single ciphertext and
  signed — a member **cannot forge another member's authorship**. A member unreachable directly is
  **blind-relayed** through another member (the relay can't read it). Removal is **cryptographic**:
  rotate and the removed member decrypts nothing. Join order does not matter. The browser runs this
  same `group.js` unchanged.
- **Zero-dependency WSS-relay transport** — the floor that always works, carrying ciphertext only,
  and the path that lets a browser reach a terminal.
- **WebRTC transport** for the browser, with DataChannel frames chunked to ≤16 KiB and reassembled.
- **CLI:** `p2p invite`, share-string dialing (`p2p connect <S-…>`, `p2p <S-…>`, and in the TUI).
- **Package exports:** `@fire17/p2p/invite`, `@fire17/p2p/key` and `@fire17/p2p/group` subpaths —
  `createSecureGroup` is now reachable from an npm install.
- **`CHANGELOG.md`** (this file).

### Fixed

- **`peer.send()` no longer hangs forever on an oversized payload.** A payload past the wire budget
  made `wire.sendReliable` throw; `node.js` swallowed the throw and the caller's promise **never
  settled** — an app-level deadlock. `send()` now rejects (with `peer.maxMessage` as the documented
  limit), including while disconnected, and a doomed message never lingers in the outbox to be
  replayed on reconnect. Falsified: reverting the fix reproduces the hang.
- **Noise `IKpsk2` conformance** — a PSK handshake must `MixKey(e.public_key)` after
  `MixHash(e.public_key)` (Noise §9.2). Invite-mode handshake bytes changed accordingly.
- **DHT BEP44 put** must target the 8 **closest** nodes, not the first 8 that return a token.
- **Groups:** join order no longer matters (members re-sync when the chain reveals membership); the
  group secret is no longer gated on `Buffer.isBuffer` (broke under the browser shim).
- **Browser transport race** now races to first **peer contact**, not first socket.

### Changed

- Collapsed to **one** WebRTC transport (`src/transport-webrtc.js` deleted).
- Site + README rebuilt around **"play with everything"** — every shipped surface, with its honest
  boundaries stated inline.

### Known gaps (stated, not hidden)

- **Post-hoc `group.add` is best-effort** — the supported flow is creating the group **with** its
  members. Adding a member after creation is limited today (a `group.js` limitation, fix queued).
- **Invites are terminal-only.** The web client cannot dial an `S-…` share string; it detects one and
  points you at the CLI rather than misrouting it. This is a real feature, not a missing seam: in the
  browser the tracker leg carries the WebRTC SDP offer/answer, so invite-scoping it means teaching
  `webrtc.js` to use the invite rid for the infohash **and** AEAD-seal the SDP on both publish and
  dial (and the WSS-relay leg for browser↔TUI). Fast-follow.
- **Invite burn/rotate is v2.** Single-use is a convention today: nothing stops a second connection
  with the same string, and `K_inv` is not retired after first contact.
- **The peer you connect to still learns your IP.** Invites hide it from infrastructure and
  non-invitees, not from your correspondent. Only an onion transport (v3, researched) changes that.
- **A freshly minted invite is not instantly resolvable over public infra** (~tens of seconds for the
  BEP44 put / tracker announce to land). On a LAN, mDNS makes it instant.
- Not yet witnessed: a run across two **different** networks (rendezvous has been proven public; the
  punch in our gates was local).

### Verification

162/162 deterministic tests (`node --test test/*.test.js`) · `p2p --selftest` PASS · two-process
`bin/p2p` gates over the real rendezvous stack (reusable-key **and** invite) · browser↔TUI paired
witnesses over WebRTC and the WSS relay · invite mode live over DHT + public trackers.

## [0.1.0] — 2026-07-11

Initial release: 26-char key identity with a 110-bit commitment gate, serverless rendezvous
(mDNS + Mainline DHT + WebSocket trackers), STUN + ICE-lite NAT hole-punching, in-house
Noise `IK` (KAT-verified) with the first-ack MITM proof, sliding-window ARQ with exactly-once
reconnect, a friends store, a TUI + CLI, and a one-command cross-platform installer.
