# p2p — Premortem & War-Table (pseudo-oracle for all future workers)

> 2026-07-11 · written before research lanes landed; update after synthesis. The moment
> reality diverges from this oracle, STOP, log the divergence, escalate — do not
> improvise past a broken map.

## The goal, restated in the owner's terms

Small p2p chat framework, quickly added to any existing project as a backbone for
seamless messaging and data coms. User generates a **26-char hashkey**, copies it to a
friend; friend can find + message them. All p2p, **E2E encrypted, blazingly fast**, no
centralized coordinator, **no server of our own**. As small/lightweight as possible.
Reliable realtime coms, friends or **groups**. **Connect and persist behind NAT.**
Chaser: first contact **provably MITM-proof** — "if the users see the first ack message
between each other… even MITM could not pretend to be any one of the parties or listen in."

## Non-negotiables (constraint set)

1. Zero external dependencies — only stdlib/platform + what we vendor in-house.
2. No owned infrastructure — free public infra only (public STUN, DHT, relays are
   allowed: they're not OUR server and not a trusted party).
3. E2E encryption always; rendezvous channel never sees plaintext or linkable IDs.
4. 26-char copyable key is the entire UX of contact exchange.
5. Embeddable: tiny API (generate key / connect(key) / send / on-message), tiny footprint.
6. NEVER invent crypto primitives — compose standard ones (X25519, ChaCha20-Poly1305,
   HKDF, Ed25519) from platform crypto or vendored reference code.

## Premortem — "six months later, it failed because…"

| # | Failure history | Likelihood | Blast radius | Detection signal | Pre-approved response |
|---|---|---|---|---|---|
| 1 | Symmetric-NAT pairs never connect; users behind CGNAT gave up | HIGH | core promise broken | punch success metrics in tests from real networks | ladder: IPv6 → punch → TCP simo-open → peer relay via mutual friend → public-infra store-and-forward; NEVER ship without a working fallback rung |
| 2 | Free public infra (trackers/relays/DHT bootstrap) flaked or blocked us; first contact intermittently fails | HIGH | first contact unreliable | multi-channel race telemetry; probe channels in CI | publish/subscribe to N≥2 channels concurrently, race reads; channel list is data (swappable), not code |
| 3 | Crypto design had a hole (replayed hello, key-holder impersonation, rendezvous linkability) | MED | catastrophic trust loss | adversarial review lane; threat-model table with explicit claims | Noise-style PSK handshake w/ transcript binding; adversarial review to zero criticals BEFORE v1 tag |
| 4 | "Zero deps" made us hand-roll WebRTC/DTLS and we drowned | MED | schedule death | LOC budget blown on transport | scope: OWN wire protocol over UDP/TCP; skip WebRTC/DTLS entirely for v1 (browser target becomes v2 with its own transport) |
| 5 | Wrong host language — nobody could embed it | MED | adoption zero | — | decide AFTER prior-art lane; bias: runtime with real built-in crypto (Node ≥ Go > Python); spec written language-neutral so ports are cheap |
| 6 | Framework crept into an app (UI, accounts, history DB) | MED | "small" died | LOC + API surface review | hard API budget: ~6 public calls; storage/UI forever out of scope |
| 7 | Groups bolted on late broke the crypto | LOW-MED | redesign | design review | design group model in DESIGN.md v1 even if impl ships in v1.1 |
| 8 | Message loss on reconnect; "realtime" but lossy | MED | trust loss | ack/replay tests killing one side mid-send | seq numbers + acks + resend buffer from day 1 (tiny) |
| 9 | Half-succeeds-and-lies: demo works on LAN, "done" declared, fails across real NATs | HIGH | false done | ONLY cross-network runs count as verification | verification task requires two distinct networks (e.g. lan vs phone-hotspot/VPS) before "done" |
| 10 | Key format locked early, regret forever (no version bits) | MED | migration pain | — | reserve version bits in the 26-char encoding NOW |

## Scariest assumptions → cheapest killing experiments (retire in week one)

1. **A stranger's UDP hole punch works between two real home NATs coordinated only via
   free public channel.** Spike: ~150-LOC punch script, two networks, measure.
2. **BEP44/DHT (or tracker/nostr) accepts our tiny signed blobs and returns them
   minutes-to-hours later.** Spike: store + fetch contact blob via public infra, timed.
3. **Platform crypto really covers X25519+AEAD+Ed25519 zero-dep.** Spike: 30-line
   handshake using only stdlib on the chosen runtime.

## Kill criteria (written while calm)

- If after 2 spike days punch success (with fallbacks) can't reach a connection between
  our two real test networks → STOP, rescope transport (relay-first architecture).
- If no free channel delivers rendezvous blobs reliably (≥95% within 30s in probes) →
  STOP, surface to owner: the "no own server" constraint needs a conversation (e.g.
  optional self-hostable rendezvous binary as escape hatch — still zero-cost default).
- If zero-dep crypto is impossible on the chosen runtime → vendor audited reference
  implementations (documented provenance), never a novel design.

## Explicitly out of scope for v1 (delete before optimize)

Browser/WebRTC build · message history/storage · multi-device identity sync · file
transfer chunking (design leaves room) · federation · TURN-style owned relays · GUI.

## Divergence rule

Every worker: if observed reality contradicts this document or DESIGN.md, STOP, write
the divergence into docs/DIVERGENCES.md, escalate. Do not improvise past a broken map.
