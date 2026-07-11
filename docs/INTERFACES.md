# p2p — module interface contracts (v1)

> Law for all build lanes. ESM, Node ≥22, JSDoc types, zero deps. Buffers everywhere
> (no strings on the wire). Change a seam → STOP, escalate to main (interfaces are
> single-writer: main). DESIGN.md governs semantics.

## Canonical forms
- `S` (contact string): 26 chars, Crockford base32, canonical = UPPERCASE. All KDF input
  uses the canonical ASCII bytes of `S`.
- Bit layout of the 130-bit payload: bits[0..5)=version/flags, [5..115)=commitment
  (first 110 bits, big-endian, of SHA256("p2p-id-v1"‖edPub32‖xPub32)), [115..130)=checksum.
- checksum = first 15 bits of SHA256("p2p-ck-v1" ‖ first115bits packed big-endian into
  15 bytes, low 5 bits of last byte zero).
- `rid(ch)` = HKDF-SHA256(ikm=S_ascii, salt="p2p-rv-" + ch + "-v1", info=epochUtcDayString,
  L) — L=20 for "dht"/"tracker", 32 for "mdns". Epoch = UTC day "YYYY-MM-DD"; readers
  try {today, yesterday, tomorrow}; listeners pre-announce tomorrow within 1h of rollover.

## src/key.js
```js
generateIdentity()                    // -> {edPub,edPriv,xPub,xPriv,S}  (Buffers + string)
encodeKey(edPub, xPub, version=0)     // -> S
decodeKey(s)                          // -> {version, flags, commitment(Buffer 14B/110bits)} ; throws TypoError on checksum/alphabet
verifyCommitment(commitment, edPub, xPub)  // -> boolean (constant-time compare)
deriveRid(s, channel, epochStr, len)  // -> Buffer
```

## src/noise.js  (Noise_IK_25519_ChaChaPoly_SHA256)
```js
initiator({ localX: {pub,priv}, remoteXPub })   // -> hs
responder({ localX: {pub,priv} })               // -> hs
hs.writeMessage(payloadBuf)   // -> Buffer (throws if not my turn)
hs.readMessage(buf)           // -> payloadBuf (throws HandshakeError; MUST fail closed)
hs.complete                   // boolean
hs.split()                    // -> {tx, rx, handshakeHash}   after complete
tx.encrypt(plaintext, ad=null) // -> ciphertext (nonce = internal be64 counter; throws on rollover)
rx.decrypt(ciphertext, ad=null)// -> plaintext | throws
```

## src/wire.js  (framing + ARQ; transport-agnostic)
```js
createChannel({ mtu, send(datagramBuf), now })   // -> ch
ch.connId                     // Buffer(8) — QUIC-style, survives ip:port roam
ch.sendReliable(bytes)        // ordered, sliding window, resend w/ backoff
ch.onReliable(cb)             // exactly-once, in-order delivery
ch.onDatagram(buf, rinfo)     // feed every incoming datagram here
ch.tick(nowMs)                // timers: resend, keepalive emission
ch.stats()                    // {inflight, rtt, loss}
```
Frame: [1B type][8B connId][4B seq][4B ack][payload]. Types: HELLO, HS1, HS2, DATA, ACK,
PING, PONG, CLOSE. DATA payload = AEAD frame from noise split states.

## src/transport.js
```js
createEndpoint({ port? })                 // -> ep (UDP socket + candidate gathering)
ep.candidates()                           // -> [{proto:'udp6'|'udp4'|'tcp', ip, port, kind:'host'|'lan'|'srflx'}]
ep.stun()                                 // -> {ip,port} via public STUN list (research/transport-nat.md)
ep.punch(remoteCandidates, {signal})      // -> connected socketLike (races ladder per DESIGN D8)
ep.onConnection(cb)                        // listener inbound-accept: fired once per NEW inbound peer.
                                           //   impl: unsolicited PROBE (no active punch, unknown addr)
                                           //   -> PROBE_ACK + build socketLike + cb(socketLike). Accepting
                                           //   any inbound is safe — real auth is the gate+Noise IK on top.
ep.on('netchange', cb)                     // local IPs changed -> node.js re-announces (publishAll)
// socketLike: { send(buf), onMessage: <assignable fn>, close(), closed:boolean, rinfo }
```
Keepalive 25s UDP / 60s TCP, owned by wire.tick. On local-IP-change: emit 'netchange'
(node.js re-announces immediately).

## src/rendezvous/{mdns,dht,tracker}.js — uniform surface, different roles
```js
announce(rid, info, opts)   // info: dht -> port only; mdns/tracker -> full candidate blob
lookup(rid, opts)           // -> async iterable of {candidates[], channel, ts}
// tracker.js additionally: persistent WSS conns; onOffer(cb) — live matchmaker
// (answers offers while listening). Offer blob = JSON {v, candidates[]}.
```
## src/rendezvous/race.js
```js
publishAll(s, endpoint)       // fan-out announce, per-channel rid, epoch + pre-announce, re-announce on netchange
resolve(s)                    // -> merged, deduped, ranked candidate stream (freshness+channel), dial caps per D6
```

## src/node.js (public API — docs/API-SKETCH.md budget)
```js
identity() / listen(identity, opts) -> node / node.connect(S) -> peer
peer.send(data) -> Promise<ack> ; node.on('peer'|'message'|'ack'|'disconnect'|'divergence')
node.group(keys[]) -> group ; group.send(data)      // pairwise fan-out (src/group.js)
```

## Testing law (every lane)
`node --test` native runner; test files `test/<module>.test.js`; zero dev deps; noise.js
additionally: official KAT vectors committed under `test/vectors/` + negative suite.
