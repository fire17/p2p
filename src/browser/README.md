# p2p — browser client

A **browser-only** p2p chat client. No backend of ours, no accounts, no build step. It uses the
**same 26-char key, the same Noise IK handshake + commitment gate, and the same message semantics**
as the CLI/TUI — a browser peer and a CLI peer are the same protocol on the wire.

> Full design + threat model: [`research/browser-client.md`](../../research/browser-client.md).

## How it works (one paragraph)

The browser runs the TUI's **own protocol source unchanged** — `src/key.js`, `src/noise.js`,
`src/wire.js`, `src/node.js`, `src/group.js` — by swapping the two things a browser lacks:

- `node:crypto` → [`shim/node-crypto.js`](shim/node-crypto.js) (vendored [noble](vendor/PROVENANCE.md)
  primitives; ChaCha20-Poly1305, which no browser has, plus sync X25519/Ed25519/SHA-256/HKDF), wired
  in by the `<script type="importmap">` in [`index.html`](index.html);
- `Buffer` → [`shim/buffer.js`](shim/buffer.js) (a `Uint8Array` subclass).

The **transport** is the only genuinely new module: [`webrtc.js`](webrtc.js) opens a WebRTC
DataChannel behind the *same* endpoint seam `src/node.js` already injects, signalled over the
**existing public WSS trackers** (`src/rendezvous/tracker.js`) keyed by the same `rid`. Because it
is the identical Noise handshake over an untrusted pipe, the trackers, STUN, and WebRTC's own DTLS
are all untrusted plumbing — the security is **≥ the TUI** (proven byte-for-byte; see the tests).

## Run it

Serve this directory over HTTPS or `localhost` (SubtleCrypto/IndexedDB need a secure context):

```sh
# from the repo root
python3 -m http.server 8080
# then open  http://localhost:8080/src/browser/
```

Open it in two tabs (or two browsers), copy one key into the other's Connect box. They meet over the
public trackers and chat directly, E2E. Deep link: `…/src/browser/#<26-CHAR-KEY>` pre-fills the dial box.

## Tests

Deterministic (run in CI, no browser needed):

```sh
node --test test/browser-shim.test.js test/browser-noise-parity.test.js test/browser-mitm.test.js
```

Real-browser end-to-end (needs Playwright + Chromium + the live public trackers):

```sh
PLAYWRIGHT=$(node -e "console.log(require.resolve('playwright'))") node test/browser-e2e.mjs
PLAYWRIGHT=$(node -e "console.log(require.resolve('playwright'))") node test/browser-group.mjs
```

Playwright is **not** a dependency of this repo (it stays zero-dep) — the harness loads it from an
existing install via `$PLAYWRIGHT` and skips loudly if absent.

## Status & limits (honest)

- ✅ **browser ↔ browser** across NATs, verified in a real browser (~3.5 s first contact).
- ✅ **groups > 2** via pairwise fan-out (sender-keys is the P3 scale upgrade, see the study §7).
- ⏳ **browser ↔ TUI** is designed, not built — it needs a transport both can speak (a browser has no
  UDP): either the TUI gains an optional `werift` WebRTC transport, or both use the zero-dep
  `src/transport-wss.js` relay. See the study §6.
- ⏳ **two real networks** not yet exercised (same gap the TUI has).
- ⚠️ **Code-delivery trust:** a web page is re-fetched every load, so you trust whoever serves it.
  The page is fully static with a strict CSP; for the strongest guarantee, run the CLI. Study §8.4.
