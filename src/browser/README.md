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
  in by the `<script type="importmap">` in the page shell ([`/app/index.html`](../../app/index.html));
- `Buffer` → [`shim/buffer.js`](shim/buffer.js) (a `Uint8Array` subclass).

The **transport** ([`webrtc.js`](webrtc.js)) opens a WebRTC DataChannel behind the *same* endpoint
seam `src/node.js` already injects, signalled over the **existing public WSS trackers**
(`src/rendezvous/tracker.js`) keyed by the same `rid`; a raced [`transport.js`](transport.js) also
carries a zero-dep WSS-relay floor (`src/transport-wss.js`) so a browser can even reach a CLI peer.
Because it is the identical Noise handshake over an untrusted pipe, the trackers, relays, STUN and
WebRTC's own transport encryption are all untrusted plumbing — security is **≥ the CLI** (proven
byte-for-byte; see the tests).

## The page

The shipped client is [`/app/index.html`](../../app/index.html) at the repo root — served live at
**p2p.akeyo.io/app/**. It is a thin shell (strict CSP + an ABSOLUTE import map + `<script
src="/src/browser/app.js">`) so the ONE committed copy of the source under `/src/browser/…` and
`/src/…` is exactly what runs — no bundler, no fork, no duplication. [`app.js`](app.js) is the UI
(1-to-1 + group chat); everything it imports resolves by absolute path.

## Run it locally

```sh
# from the repo root — localhost is a secure context, so WebCrypto/IndexedDB work
python3 -m http.server 8080
# then open  http://localhost:8080/app/
```

Open it in two tabs (or browsers), copy one key into the other's Connect box → they meet over public
infrastructure and chat directly, E2E. Deep links: `…/app/#<26-CHAR-KEY>` pre-fills the dial box;
`…/app/#<GROUP-CODE>` pre-fills the group Join box.

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
