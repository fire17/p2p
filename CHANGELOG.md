# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/) (pre-1.0: minor bumps may carry breaking changes).

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

- **Invites are terminal-only.** The browser build has no `makeRace` seam, so it cannot dial an
  `S-…` share string; it detects one and says so rather than misrouting it. Fast-follow.
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
