# p2p — embeddable API sketch (v0 intent, language-neutral)

> Budget: ~6 public calls. Anything beyond this list needs a fight. Storage, UI,
> accounts, history: forever out of scope — host app's job.

```
await p2p.identity()           -> { S: "26-char string", edPub, edPriv, xPub, xPriv }  // async; S = the key you share
p2p.listen(identity, opts)     -> node                             // go online, publish presence
node.connect(theirKey)         -> peer                             // find + handshake (first contact or reconnect)
peer.send(bytes|string)        -> ack promise                      // realtime, ordered, encrypted
node.on(event, fn)                                                  // 'peer', 'message', 'ack', 'disconnect', 'divergence'
node.group(keys[]) / group.send(...)                                // groups (design v1, impl may be v1.1)
```

Design promises the API must keep:
- `connect()` resolves only after the MITM-proof handshake completes — the resolved
  "first ack" IS the proof surface the owner specified.
- Everything async/non-blocking. Liveness: a dead peer is detected within ~keepaliveMs×3
  of silence — the node emits `disconnect` and `peer.connected` flips false. Reconnect is
  **app-initiated in v1**: call `connect(key)` again; it re-handshakes (not the corpse) and
  the buffered outbox flushes exactly-once (seq+ack). Backpressure exposed. **Automatic
  background redial is v1.1** — v1 gives you the `disconnect` signal to trigger it yourself.
- Instant-on: `listen()` returns fast, rendezvous publishing continues in background.
- Zero config required; every knob optional with sane defaults (defaults are the decision).
- Wire format + key format versioned from byte 0.
