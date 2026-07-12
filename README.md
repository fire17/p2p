# p2p

> Tiny, zero-dependency P2P chat framework. One 26-char key is your whole contact
> surface — copy it to a friend, they find you and message you: direct, E2E-encrypted,
> **provably MITM-proof on first contact**, through NAT, with **no coordinator server of
> ours**. Embed it as the messaging backbone of any project.

**Status: v0.1 in active build.** See `DESIGN.md` for the full protocol and `docs/` for the
premortem, interfaces, and API. This README fills in as modules land + verify.

## Why

- **Zero dependencies** — Node built-ins only (`node:crypto` gives X25519 + Ed25519 +
  ChaCha20-Poly1305 + HKDF; `dgram`/`net`; native WebSocket). Nothing to audit but us.
- **No server of ours** — rendezvous rides free public infrastructure (LAN mDNS,
  BitTorrent Mainline DHT, public WebSocket trackers); we operate none of it.
- **MITM-proof first contact** — the 26-char key commits to your identity keys; the first
  ack a peer decrypts is a cryptographic proof no man-in-the-middle is present.
- **Small** — the whole thing targets ~2.5–3.5k LOC.

## Quickstart

```js
import { identity, listen } from '@fire17/p2p'

// Machine A
const me = await identity()          // { S: "5J8K…26 chars", ... }  ← share me.S
const node = await listen(me)
node.on('message', (peer, data) => console.log(data.toString()))   // (peer, data)

// Machine B (holds A's key string)
const node = await listen(await identity())
const peer = await node.connect('5J8K…')   // resolves only after the MITM-proof handshake
await peer.send('hey')                        // realtime, ordered, encrypted
```

`identity()` is async and returns `{ S, edPub, edPriv, xPub, xPriv }` — `S` is the 26-char
key string you share. The `message` event is `(peer, data)`. (Or just use the CLI: `p2p`.)

CLI demo: `npx p2p-chat` (generates a key on one machine, `p2p-chat <key>` connects from another).

## Security in one paragraph

Your key = `version ‖ 110-bit commitment to (Ed25519, X25519) pubkeys ‖ checksum`, in
Crockford base32. A contacting peer fetches your candidate keys over the rendezvous
channel, gates them against the commitment (2¹¹⁰ second-preimage), then runs a Noise `IK`
handshake — so the very first message it can decrypt proves it's talking to the holder of
your private key, not a relay or a MITM. Rendezvous topics are `HKDF(key, …)`, so channel
operators can't enumerate or read. Full threat model + honest residual risks (session-granular
forward secrecy, TOFU on the initiator direction with a single published key, metadata to
relays): `research/crypto-firstcontact.md` and `DESIGN.md §3`.

## License

MIT.
