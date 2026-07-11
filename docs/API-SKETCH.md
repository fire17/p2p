# p2p — embeddable API sketch (v0 intent, language-neutral)

> Budget: ~6 public calls. Anything beyond this list needs a fight. Storage, UI,
> accounts, history: forever out of scope — host app's job.

```
p2p.identity()                 -> { key: "26-char string", ... }   // create/load my identity
p2p.listen(identity, opts)     -> node                             // go online, publish presence
node.connect(theirKey)         -> peer                             // find + handshake (first contact or reconnect)
peer.send(bytes|string)        -> ack promise                      // realtime, ordered, encrypted
node.on(event, fn)                                                  // 'peer', 'message', 'ack', 'disconnect', 'divergence'
node.group(keys[]) / group.send(...)                                // groups (design v1, impl may be v1.1)
```

Design promises the API must keep:
- `connect()` resolves only after the MITM-proof handshake completes — the resolved
  "first ack" IS the proof surface the owner specified.
- Everything async/non-blocking; reconnects automatic; sends buffered + resent across
  reconnects (seq+ack), backpressure exposed.
- Instant-on: `listen()` returns fast, rendezvous publishing continues in background.
- Zero config required; every knob optional with sane defaults (defaults are the decision).
- Wire format + key format versioned from byte 0.
