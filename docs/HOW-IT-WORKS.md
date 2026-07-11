# How p2p works — especially "how do far-away computers find each other with no server?"

Plain-English walkthrough. The surprising part is discovery, so that gets the most space.

## The key IS the identity

When you run `p2p key`, your computer generates two cryptographic keypairs (an Ed25519
signing pair and an X25519 Diffie-Hellman pair) and keeps the private halves secret on
disk (`~/.p2p/default.json`, permissions `0600`). Your **26-character key** is not random —
it's a *fingerprint* of your public keys: `version ‖ 110-bit hash(your public keys) ‖ checksum`.

So the string you copy to a friend simultaneously (a) names you and (b) lets your friend
**verify** they're really talking to you. Nobody can hand out a string that points at your
identity but is secretly theirs — the fingerprint wouldn't match.

## The hard question: finding each other with no server

Normally, "how does computer A reach computer B across the internet?" needs a server both
sides know: a chat server, a signaling server, something with a fixed address. We have
**none of our own**. Here's how it still works — three ideas stacked.

### Idea 1 — a shared secret location derived from the key

Both you and your friend can compute the **same secret rendezvous ID** from the key,
because it's just a hash:

```
rendezvous_id = HKDF(the 26-char key, "today's date")
```

Anyone holding the key computes the identical `rendezvous_id`. Anyone *not* holding it
can't — it's a one-way hash. So the key doubles as a **secret meeting-point address** that
only the two of you know. No server told you where to meet; the math did.

### Idea 2 — leave a note at that location on infrastructure that already exists

We don't run a server, but the internet is full of **free, public, shared bulletin boards**
that already exist for other reasons. We ride three of them:

- **Your local network (mDNS):** your computer shouts "anyone looking for `rendezvous_id`?
  I'm at 192.168.1.20" over Wi-Fi multicast. If your friend is on the same Wi-Fi, they hear
  it instantly. This is why same-network chat connects in ~1.5 seconds.
- **The BitTorrent DHT:** the same giant peer-to-peer network that powers torrents is,
  underneath, a worldwide **distributed hash table** — a lookup system with no owner, run by
  millions of ordinary BitTorrent clients. We use its normal "announce / find peers"
  operation, but under *our* `rendezvous_id` instead of a movie's hash. You announce "I'm
  here" to the DHT; your friend asks the DHT "who's at `rendezvous_id`?" and gets your
  current IP address back. **No server of ours — we're just guests on a network built for
  something else.**
- **Public WebSocket trackers:** small free servers (run by the BitTorrent community) that
  introduce peers. Another redundant path.

We publish to all three at once and read from all three at once ("publish-to-N, race the
reads"), so if one is blocked or slow, the others still work. The critical point: **the
only thing anyone learns from these boards is an opaque hash and an IP address** — never
your identity, never your messages. Observers can't even tell it's "p2p" traffic.

### Idea 3 — punch a hole through the firewalls (NAT traversal)

Now each side knows the other's public IP address — but home routers (NAT) normally drop
unexpected incoming packets. So both computers do a **hole punch**: they each fire a UDP
packet *at the other at the same moment*. The first packet outbound teaches your own router
"I'm expecting a reply from this address," which props the firewall open just long enough
for the other side's packet to get in. Both sides do it simultaneously, so both firewalls
open at once and a direct path forms. (We learn each computer's public address for this
using free public **STUN** servers, another tiny piece of borrowed infrastructure. `p2p
doctor` shows you these working.)

Real-world success for direct punching is ~70–90%. When two networks are *both* the
stubborn kind ("symmetric NAT"), a direct path can't form; the design's fallback is to
relay through a mutual online peer (still end-to-end encrypted, so the relay is blind) —
that part is v2.

## Putting it together: what happens when your friend runs `p2p <yourkey>`

1. **Check the key** locally — a typo is caught by the checksum before any network use.
2. **Find you:** derive `rendezvous_id` from your key, look it up on mDNS + DHT + trackers,
   get your candidate IP addresses.
3. **Punch** a direct UDP path to you.
4. **Prove it's really you (no man-in-the-middle):** your friend fetches your public keys
   over that path and checks they hash to the fingerprint inside your key. Then both sides
   run a **Noise IK handshake** — a standard, audited cryptographic key-exchange.
5. **The first ack.** The very first message your friend can *decrypt* could only have been
   produced by someone holding your real private key. An impostor who intercepted everything
   but doesn't have your private key can never produce it. That's why `✅ secure channel
   established — verified, no MITM` is a genuine proof, not a hopeful label: **seeing that
   line means the channel is provably clean.**
6. **Chat.** From here it's a direct, encrypted (ChaCha20-Poly1305) UDP link between the two
   computers — no server in the middle, messages ordered and re-sent if a packet drops.

## Why "no dedicated servers" is true and not a trick

We never operate anything. We borrow **shared, public, ownerless-or-community infrastructure**
(the BitTorrent DHT, public STUN/trackers, your LAN's multicast) purely as a *notice board*
to swap IP addresses — and even they only ever see opaque hashes, never your identity or
content. Once the two computers have swapped addresses, they talk **directly to each other**.
The security doesn't depend on trusting any of that infrastructure: the fingerprint + Noise
handshake make a man-in-the-middle mathematically detectable no matter what the notice
boards do.

## The honest limits (today)

- **Same Wi-Fi / same LAN:** works, ~1.5s, verified.
- **Across the internet (different networks):** the machinery is proven (live STUN, hole
  punch, live DHT lookups all work), but a real run between two *distinct* networks hasn't
  been observed yet — it needs a second network to test (a phone hotspot or a VPS).
- **Both sides behind symmetric NAT:** needs the peer-relay fallback (v2).
- **Offline delivery:** both peers must be online at the same time in v1 (store-and-forward
  dead-drops are v2).
