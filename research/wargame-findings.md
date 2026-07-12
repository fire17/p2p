# p2p — Whole-System Wargame / Unknown-Unknowns Sweep

> **Research Lane: Standing Red-Team (task #31).** Owner: fire17. Status: **RANKED ADVERSARIAL FINDINGS** (design/analysis only — NO `src/` changes).
> **Date:** 2026-07-12. **Author:** hardening red-team lane (opus @ xhigh) + 2 sonnet subagents (transports/wire/mDNS; groups/browser/installer). **Every finding below was re-verified against the actual code by the opus lane** — subagent claims were not trusted blind; anything the opus lane did not read primary is marked **UNVERIFIED-BY-LEAD**.
>
> **Method:** whole-system sweep (not diff-only) across crypto (`key`/`noise`/IKpsk2/commitment gate), transports (STUN/punch/wire/WSS/WebRTC), rendezvous (mDNS/DHT/trackers/invite), groups (sender-keys/membership DAG), browser client, installer. For each finding: (a) attack, (b) severity, (c) weakest-link `file:line`, (d) fix or accept+document.
> **Severity rubric:** CRITICAL = breaks data secrecy/auth OR arbitrary code exec · HIGH = metadata deanon, silent delivery-integrity break, or unbounded DoS-to-fail · MEDIUM = degraded-but-recoverable · LOW = hardening nit / accept+document.
>
> **Companion:** `research/surface-hardening.md` (§6 the Complexity Adversarial Gate — every fix below ships through it). Findings feed the build lanes (tasks #26–#32).

---

## 0. Headline — where the weakest links actually are

**The crypto core is sound.** No CRITICAL secrecy/auth break: Noise IK/IKpsk2 composition is spec-correct (nonce discipline, low-order-point reject, fail-closed decrypt, AEAD-verify only via `node:crypto`), the commitment gate is 2^110 fail-closed, the sealed-blob privatizes IPs as claimed (`privacy.test.js` 9/9), and **there is no psk downgrade** — an invite-mode responder runs `Noise_IKpsk2` exclusively (`node.js:404`). Those are real positives; state them.

**The breaks are in the layers AROUND the core.** Ranked by blast radius:

| Property | Weakest link | Finding |
|---|---|---|
| **Supply chain** (defeats ALL crypto below it) | installer runs unverified app source | **INST-1 (CRITICAL)** |
| **Delivery integrity** ("reliable exactly-once") | unauthenticated wire control plane; connId is cleartext | **WIRE-1/2/3 (HIGH)** |
| **Availability** | peer records allocated pre-auth, never evicted | **DOS-1 (HIGH)** |
| **Metadata** (IP↔identity) | cleartext HELLO reveals identity pubkeys to anyone reaching the socket | **META-1 (HIGH)** |
| **Group confidentiality/consistency** | non-deterministic admin fold + incomplete removal | **GRP-1/2 (HIGH)** |
| **NAT survival** (claimed, doesn't work) | roaming is dead code | **NAT-1 (MED-HIGH, DESIGN divergence)** |

A single theme runs through WIRE-1/2/3 and META-1: **the AEAD only protects DATA payloads; the control plane (ack/seq/close/HELLO/connId) is in the clear.** An on-path adversary — which the metadata threat model already concedes exists (`metadata-privacy.md` §8 rows 2 & 6), and which **a hostile WSS relay literally is** (browser-build #3) — cannot break secrecy but can silently corrupt delivery and confirm identity. That is the single highest-value hardening target after the installer.

---

## 1. CRITICAL

### INST-1 — installer executes the app source with ZERO integrity verification
- **(a) Attack.** Every fresh install / `--force` update fetches `https://github.com/fire17/p2p/archive/refs/heads/main.tar.gz` (floating `main`, not a pinned tag) and runs it as-is. The only post-fetch check is **file existence** (`package.json`, `bin/p2p.js`) — no checksum, no signature, no pinned commit SHA. A compromised `main` (stolen token, malicious merged PR, account compromise) or a CA-level MITM of `codeload.github.com` yields **arbitrary code execution on every installing machine**. The *same script* SHA256-verifies the Node runtime against `SHASUMS256.txt` (`init:157-180`) — the far-less-sensitive payload gets integrity, the actual protocol/crypto code gets none.
- **(b) Severity: CRITICAL** (arbitrary code exec; pre-runtime, so it defeats every crypto guarantee below it).
- **(c) Weakest link:** `init:214-225` (fetch→`tar -xzf`→existence-only check at `:225`); `init.ps1:~195-222` (identical Windows path — **UNVERIFIED-BY-LEAD**, symmetric to `init` which was read).
- **(d) Fix.** Pin to a release **tag**, not floating `main`; publish a signed `SHASUMS` (or `git verify-tag` / sigstore) in the repo and verify the source archive before extraction — the exact pattern already used for the Node tarball. Build task.

---

## 2. HIGH

### WIRE-1/2/3 — unauthenticated wire control plane (one root cause, three vectors)
`wire.js` frames are `[type][connId][seq][ack][payload]`; only DATA payloads are AEAD-protected. `onDatagram` gates solely on a **cleartext connId** (`wire.js:249`) — learnable by any on-path observer from any prior frame. Attacker position: on-path / hostile relay / same-NAT (all in-scope per rows 2 & 6).

- **WIRE-1 — forged ack drains the send window → silent loss + wedge.** `onDatagram` calls `onAck(f.ack)` **unconditionally before the type switch** (`wire.js:260`). One forged frame (a PING suffices) with an inflated `ack` makes `onAck` (`:202-217`) delete every `inflight` DATA seg — the sender believes them delivered and never resends. A far-future `ack` also poisons `sndUna` (`:214`) so subsequent legit acks are ignored → the send side wedges. node.js's app-outbox only replays on full reconnect, so this is real, silent, undetected message loss. **Severity HIGH.**
- **WIRE-2 — forged CLOSE tears down the channel.** `case TYPE.CLOSE` (`wire.js:272-273`) sets `closed=true` on connId match alone. One packet = instant teardown; repeat on every reconnect = persistent denial. **Severity HIGH.**
- **WIRE-3 — forged DATA advances the receive cursor pre-AEAD → permanent per-message loss.** `onData` (`wire.js:220-239`) hands the payload to `onReliableCb` (decrypt fails harmlessly at `node.js:161-164`) but **unconditionally** advances `rcvNext` (`:231-232`) and acks. The seq is fully predictable (starts 0, increments, visible in every cleartext header). When the real frame for that seq arrives it is `seqCmp < 0` → "already delivered → drop" (`:222`) — silently, forever. One injected packet erases one specific application message. **Severity HIGH.**
- **(c) Weakest link:** `wire.js:249` (connId-only gate), `:260` (unconditional `onAck`), `:202-217` (`onAck` on cleartext field), `:220-239` (`rcvNext` advance before AEAD), `:272-273` (bare CLOSE).
- **(d) Fix (single).** Authenticate the control plane: bind `type‖connId‖seq‖ack` into the DATA AEAD as associated data, and move ack/close semantics into the Noise-protected app layer (or MAC the header with a post-handshake key). Then a bare header cannot move ARQ state. **Highest-value hardening after INST-1. Build task.** Note: this is exactly why **a WSS relay is not "just a metadata observer" — it can silently drop/wedge/close sessions** (elevates browser-build #3).

### DOS-1 — unauthenticated PROBE/HS1 flood → unbounded memory, records created pre-auth
- **(a) Attack.** Any remote sender who reaches the listener's UDP port (no NAT traversal, no spoofing) streams forged 21-byte PROBE packets, each a fresh 8-byte token / source port. Each: allocates a `_udpSocketLike`, inserts into `_peers` **and** `_accepted` (**neither ever evicted — no TTL, no cap**), fires `onConnection` → node.js starts a HELLO-retransmit timer + a **peer record + channel BEFORE the handshake/psk is validated** (`node.js:435` creates `rec` on HS1, keyed by an attacker-chosen static). A fresh static per HS1 → unbounded `_peers` growth; the reusable-S static is public via S, so crafting a valid-shaped HS1 needs no secret.
- **(b) Severity: HIGH** (uncapped, zero-cost, remotely triggerable resource exhaustion; DESIGN D6's dial-caps cover the *dialer* side, not this *accepter* side).
- **(c) Weakest link:** `transport.js:148` (`_peers`, no eviction), `:151` (`_accepted`, no eviction), `:389-412` (`_acceptInbound`, no rate limit), `node.js:435` (peer record pre-auth).
- **(d) Fix.** Cap total pending/unestablished accepts; idle-evict accepted-but-no-HS1-within-Ns; rate-limit PROBE per source; defer peer-record allocation until handshake completes. Build task.

### META-1 — cleartext HELLO reveals identity pubkeys to any unauthenticated party
- **(a) Attack.** A well-formed PROBE fires `onConnection` (`transport.js:190,390-411`), and node.js immediately sends a **cleartext HELLO carrying `edPub‖xPub`** (`node.js:414`) — the full pubkeys that S only *commits* to. Anyone who reaches the socket (a scanner who learns the IP:port via infra collusion, observation, or a lucky guess) harvests the identity pubkeys → computes S → **binds IP:port → identity**. This is an IP↔identity **confirmation oracle** that partially undercuts the whole invite-mode metadata goal (which works to keep the rendezvous layer from linking identity to IP).
- **(b) Severity: HIGH** (metadata deanonymization; the invitee already has the pubkeys, so no *new* leak to them — the leak is to any *other* party reaching the socket).
- **(c) Weakest link:** `node.js:414` (HELLO before any auth), `transport.js:390-411` (`_acceptInbound` fires on any PROBE).
- **(d) Fix.** In invite mode, gate HELLO emission on a **K_inv-authenticated probe** (the invitee can prove K_inv; a scanner cannot) — only the invitee ever elicits the pubkeys. Reusable-S mode: accept (S is public by definition). Build/design task.

### GRP-1 — membership fold is non-deterministic for concurrent `create` roots → admin escalation
- **(a) Attack.** `foldMembership` visits ops via `for (const h of byHash.keys())` (`group.js:193`) — **insertion/receipt order**. Two `create` ops (both `parents:[]`, causally unlinked) picked first-visited-wins as admin (`:198 if (admin) continue`). Different peers receiving them in different order compute **different admins from the SAME op set + SAME heads** — silent non-convergence, directly contradicting the file's own determinism claim (`:177`). A G-holder (any member; or anyone who obtained the out-of-band secret) authors a competing `create` → becomes admin on the peers that visit it first → their subsequent `add`/`remove` ops are accepted → the attacker adds itself and receives sender keys. The hash-link fork-detection (`:45-47`) does **not** fire — heads are identical, only the fold diverges.
- **(b) Severity: HIGH** (privilege escalation from ordinary member; silent, same-input divergence — worse than the acknowledged partition-fork).
- **(c) Weakest link:** `group.js:182-203` (`foldMembership`), esp. `:193` (receipt-order visitation) + `:198`.
- **(d) Fix.** Canonicalize root ordering — sort concurrent roots by op hash (lowest wins) so the fold is a pure function of the op *set*; surface a second `create` for a known groupId as `divergence`, not a silent resolution. Build task.

### GRP-2 — removed member keeps reading every non-admin member's traffic forever
- **(a) Attack.** `remove()` → `rotate()` regenerates **only the caller's own** `sendChain.ck` and redistributes to survivors (`group.js:320-327,438-443`). Member B (a non-admin survivor) never rotates → keeps ratcheting the SAME chain the removed member C already holds. Because the ratchet is one-way (`nextCk`, `:134`), C computes all of B's future message keys from what it had at removal time. Contradicts the documented "cryptographic ejection … removed member can decrypt NOTHING further" (`:42-44`, `browser-client.md:522-523,558,811-812`). **Test gap:** `group-secure.test.js:166-179` only has the ADMIN send post-removal, never a non-admin survivor — the hole is untested and passes green. (Shipped UI never calls `.remove()` yet — protocol-layer bug, not yet user-triggerable.)
- **(b) Severity: HIGH** (incomplete cryptographic ejection — the headline group security claim is false for non-admin senders).
- **(c) Weakest link:** `group.js:319-327` (`rotate` fixes only the caller), `:438-443` (`remove`).
- **(d) Fix.** On observing a `remove` op, **every** surviving member auto-rotates its own sender key and redistributes to survivors only (react to the `membership` event). Add a test where a non-admin survivor sends after removal and the removed party fails to decrypt. Build task.

### GRP-3 — KEYDIST unsigned + no peer-identity check → intra-group per-sender DoS
- **(a) Attack.** `T.KEYDIST` (`group.js:334-341`) binds the claimed sender S by commitment (pubkeys are attacker-suppliable, S is public), then `recvChains.set(S, ratchet(unb64(body.ck), …))` with an **attacker-chosen `ck`** — **no signature over the body, no check that the delivering peer IS S**. Any member (or a contact with the groupId + a member's public pubkeys) sends a forged KEYDIST claiming `s:S` → clobbers the victim's receive-ratchet for S → S's real messages fail (`divergence:'ratchet'`) until S next rotates. No confidentiality break (MSG needs S's unforgeable Ed25519 sig), but a cheap, repeatable DoS on any specific sender's channel from inside the group.
- **(b) Severity: HIGH** (integrity-of-delivery DoS, insider-cheap).
- **(c) Weakest link:** `group.js:329` (`onEnvelope` never cross-checks `peer` vs `body.s`), `:334-341`.
- **(d) Fix.** Sign KEYDIST bodies with the sender's Ed25519 key (like OP/MSG) and verify before applying, or reject unless the authenticated transport peer equals the claimed S. Build task.

### GRP-4 — late-joiner keydist drop (browser-build handover; board task #32)
- **(a) Attack/gap.** `syncKeys` marks `keyedTo.add(S)` **before** `keydistTo` and only rolls back on a *node-level* throw (`group.js:285-288`). `keydistTo` (`:313`) succeeds at the node level (pairwise send acked) even when the recipient's **group object does not exist yet** (they joined the node but haven't `createSecureGroup`'d). So `keyedTo` permanently marks them done (`:285` filter excludes them forever) and they are never re-keyed → they can never decrypt. Symptom: `add()` after group creation is flaky. (Reported by browser-build at shutdown; browser-research worked around it in the UI with create-with-members + a bounded `rotate()` re-sync ~20s.)
- **(b) Severity: HIGH** (silent, order-dependent group-membership failure).
- **(c) Weakest link:** `group.js:284-289` (`syncKeys`), `:313-317` (`keydistTo`).
- **(d) Fix.** Confirm **group-level** delivery before marking `keyedTo`, OR a member-side pull via the group rid. Build task (**#32**).

---

## 3. MEDIUM-HIGH

### NAT-1 — connId roaming is dead code (DESIGN divergence)
- **(a) Attack/gap.** `transport.js._onMessage` routes app data by an **exact `(address,port)` key** set once at punch/accept time (`:196-197`). A real NAT rebind / symmetric re-map / mobile handoff — the exact "keepalive gap / symmetric NAT" conditions — arrives from a NEW tuple, is **not** in `_peers`, and is dropped **before** wire.js's connId-roaming (`wire.js:254`) ever runs. And `onRoam` is never wired in `node.js.attach` — even a roamed packet that reached wire would not re-point the socket. So D8/D9's advertised "QUIC-style migration survives NAT rebind" (`wire.js:8-9`) **never fires**. Real recovery = the 75s liveness timeout + an app-level redial (outbox replays, so no data loss).
- **(b) Severity: MEDIUM-HIGH** (a documented mitigation for a named real-world condition doesn't work; degrades to a ~75s stall + redial). Reality contradicts DESIGN → **the divergence rule (`DESIGN.md` header) applies: STOP/log/decide.**
- **(c) Weakest link:** `transport.js:196-198` (exact-tuple routing) vs `wire.js:252-257` (the roaming it defeats); `onRoam` unconsumed in `node.js`.
- **(d) Fix.** Either loosen transport routing to accept a new source once the connId validates (re-key `_peers` on a connId-authenticated roam — but authenticate the connId first, see WIRE cluster), OR drop the roaming claim from D8/D9 + `wire.js` header and rely on liveness-timeout + redial (accept + document). Decide explicitly.

---

## 4. MEDIUM

### INST-2 — Node checksum fails OPEN when no hash tool present
`init:169-180`: on a box lacking `sha256sum`/`shasum`/`openssl`, it logs a WARN and **proceeds to extract and execute** the downloaded Node with no integrity check (`node_ok` only proves it *runs* — a malicious node also runs). **Fix:** `die`, not warn, when no hash tool exists; or vendor a pure-JS SHA256 fallback. (Precondition narrows real-world impact to minimal containers/CI; still a fail-open.)

### LIVE-1 — no `connect()` timeout → indefinite hang
`node.js` waits for the first candidate with no deadline (`:313 await it.next()`) and for HELLO/HS2 with no deadline (`:355`). If a rendezvous channel never terminates its stream, or the responder's 8×250ms HELLO retransmits are all lost / it dies post-punch, `connect()` hangs forever. Relies on **every** channel self-terminating. **Fix:** an overall `connect()` deadline. **Weakest link:** `node.js:313,355`.

### DHT-1 — BEP44 `seq` is wall-clock seconds
`dht.js:261` `seq = Math.floor(now()/1000)`. Two re-announces in the same second → equal seq → storing nodes keep the old value (BEP44 requires strictly-greater seq to overwrite), so a changed candidate set under a netchange burst may not propagate until the next second. A backward clock step (NTP) makes new puts get a LOWER seq → rejected → node unpublishable until the clock catches up. **Fix:** monotonic per-publish counter persisted across re-announce, decoupled from wall-clock. **Weakest link:** `dht.js:261`.

### MDNS-1 — mDNS leaks in invite mode + answers any query + poisonable lookup
Invite mode seals tracker + DHT but **not mDNS** — `node.js:237` builds `createMdns(rz)` with no codec/invite, so plaintext candidates broadcast on the LAN under the invite rid (deviates from the study's defense-in-depth note, `metadata-privacy.md` §2). Additionally (subagent, **UNVERIFIED-BY-LEAD** on `mdns.js` internals): `respond()` answers ANY `_p2p._tcp.local` query with the full blob, and `lookup()` accepts any matching TXT with no validation (LAN candidate-poisoning — bounded downstream by gate+Noise). LAN scope. **Fix:** seal the mDNS TXT in invite mode (cheap — reuse `inv.codec`); explicitly document the LAN presence/address exposure in README. **Weakest link:** `node.js:237`; `mdns.js` respond/decodeTxt.

### BRW-1 — raced browser transport locks outbound on first inbound frame, unvalidated
`composePunch` sets `outbound` to whichever leg delivers ANY first frame (`browser/transport.js:52-55`), no shape check. A hostile WSS relay (one of two hardcoded brokers; the dial's reply topic is visible to it on subscribe) injects a bogus frame before the real peer answers → wins the lock → misroutes the handshake outbound → the dial stalls to timeout. Fails safe (Noise/gate never completes → no data exposure), recoverable via retry. **Fix:** lock only on a well-formed HELLO/wire frame, or only after the Noise handshake progresses. Ties to **browser-build #2** (race to first PEER CONTACT, not first frame) — **any new raced leg (e.g. a cycling-added transport) must respect this or re-introduce starvation.** **Weakest link:** `browser/transport.js:49-56`.

### BRW-2 — two-tab first-run identity TOCTOU
`browser/p2p.js:67-95`: two tabs opened first-run concurrently both `idbGet`→null, both mint DIFFERENT keypairs, both `idbPut` under `'default'` → last write wins; the losing tab runs a now-unpersisted identity for the session and inherits the other's identity on reload → loses reachability under the S it already shared. **Fix:** wrap identity create in `navigator.locks.request('p2p-identity', …)` (or re-check inside an IDB transaction). **Weakest link:** `browser/p2p.js:67-95`.

### NAT-2 — keepalive default sits inside the aggressive-NAT timeout floor
`wire.js:115` `keepaliveMs = 25000` vs the project's own cited ~20-60s aggressive-CGNAT floor (`transport-nat.md`). Against the most aggressive NATs a PING can arrive after the mapping expired → the (also-broken, NAT-1) drop/stall path. Matches WireGuard's default, so a known industry tradeoff. **Fix:** accept + document, or expose a mobile/flaky mode dropping toward the RFC 8445 15s floor.

### STUN-1 — STUN Binding response accepted with no source check; DNS has no DNSSEC
`transport.js:173-182` validates only txid + magic cookie, never that the response came from the STUN server queried (`dns.lookup`, no DNSSEC, `:228-235`). An on-path/DNS-hijack attacker injects a spoofed srflx mapping → corrupts the node's own advertised candidate. Bounded: a peer reaching the spoofed address still fails gate+Noise, so worst case is a misdirected punch, not MITM. **Fix:** accept + document; optional cheap source-address sanity check.

---

## 5. LOW / accept+document

- **BRW-3 (LOW).** Private X25519/Ed25519 keys stored as extractable hex in IndexedDB (`browser/p2p.js:73-92`); any XSS → identity theft. Deliberate tradeoff for the sync crypto shim (`shim/node-crypto.js:23-27`), diverges from `browser-client.md` BC-8's "non-extractable" intent. Chat renders via `.textContent` (obvious XSS vector closed). **Accept; keep the README BC-9 caveat current.** (**UNVERIFIED-BY-LEAD** on the shim file.)
- **DOS-2 (LOW).** `ZERO_TOKEN` legacy accept fires per-4-tuple with no correlation (`transport.js:126,403-411)` — compounds DOS-1's churn; auto-bounded once DOS-1 gets a cap/eviction.
- **BURN-0 (LOW / tracked = task #26).** Burn (v2) is unbuilt, so an invite is **not single-use yet** — `race.js` re-announces per epoch boundary + netchange until the node stops listening. A captured invite (malicious invitee, or K_inv leak) stays live. Known and scheduled (`metadata-privacy.md` §7/§9).

---

## 6. Browser-build handovers (cross-cutting — fold into the build lanes)

Captured from browser-build's shutdown notes (owner-relayed); load-bearing for the hardening builds:

1. **composePunch races to first PEER CONTACT, not first socket** (commit `9a369ef`). The WSS `punch()` resolves OPTIMISTICALLY on tracker SUBACK before any peer answers, so it wins any first-socket race by construction and starves real-work legs (ICE). **Any new raced transport leg (incl. a cycling-added one) must respect this.** See BRW-1 for the residual hole.
2. **Public relays/trackers are best-effort by ToS** — the WSS relay is the FLOOR under WebRTC (unconditional interop through symmetric NAT), never the default. Promoting it is a ToS + latency decision, not a config flip. Also (this sweep): a relay is an **on-path attacker** for the WIRE cluster + BRW-1 — elevate accordingly. Relevant to the tracker-pool lane (#29).
3. **werift gate (`test/werift-tui-e2e.mjs`) self-skips without werift installed** — ANY DataChannel wire change invalidates the witness; re-run, don't trust the old log (bit the team once when chunking changed framing). Ties to the CAG's monitoring-hook check.

---

## 7. Positives (honest verification — state what HELD)

- **Noise core solid.** IK/IKpsk2 composition spec-correct (`noise.js`): nonce = `0000‖u64LE`, `MAX_NONCE` refused, low-order/all-zero DH rejected (`:124`), decrypt fails closed, AEAD-verify only via `node:crypto`, nonce advances only on success. KAT-vector + interop tested (D5).
- **No psk downgrade.** Invite-mode responder runs `Noise_IKpsk2` exclusively (`node.js:404-406`) — a reusable-S holder without K_inv cannot complete the handshake. The psk gate is real.
- **Sealed-blob privacy holds.** `privacy.test.js` 9/9; fixed 544 B ciphertext; no IP/port/marker on any surface; S-holder without K_inv can neither locate nor open.
- **Commitment gate + signatures fail closed.** 2^110 second-preimage (`key.js`), `verifyEd` returns false (never throws) on malformed input (`sign.js:41-49`), group op/msg signatures gate authorship (`group.js:268,362`).
- **ARQ nonce/counter is not desynced by injected garbage** — a failed AEAD decrypt does not advance the Noise transport nonce (`noise.js:199`); the WIRE cluster attacks the *cleartext ARQ header*, not the AEAD counter.

---

## 8. How these feed the hardening lanes (CAG-gated)

Every fix ships through `research/surface-hardening.md` §6 (the Complexity Adversarial Gate). Candidate build tasks, ranked:

1. **INST-1** (CRITICAL) → pin tag + verify signed source. *(supply chain — do first)*
2. **WIRE-1/2/3** (HIGH) → authenticate the wire control plane (one fix, three vectors closed).
3. **DOS-1** (HIGH) → cap + evict pre-auth accepts; defer peer-record allocation.
4. **META-1** (HIGH) → invite-mode HELLO gated on K_inv-proof.
5. **GRP-1/2/3/4** (HIGH) → canonical root order · every-survivor rotate on remove · sign KEYDIST · late-joiner re-key (**#32**).
6. **NAT-1** (MED-HIGH) → fix roaming or retract the D8/D9 claim (a DESIGN divergence — decide).
7. **INST-2 / LIVE-1 / DHT-1 / MDNS-1 / BRW-1 / BRW-2** (MED) → per §4.

**Each, before merge, must:** prove net-security-positive + quantify; enumerate its own new attack surface; not create a new weakest link; not regress reliability (quantified); degrade-safe; and **add a leak-monitor / observer assertion that fires on regression** (CAG check 6). The standing leak-monitor (surface-hardening §7) should grow assertions for: no-IP-on-any-surface (incl. mDNS in invite mode), wire-header-authenticated (a forged ack/close/DATA is rejected), no-pre-auth-unbounded-allocation, group non-admin-survivor-ejects-removed-member.

---

## 9. UNVERIFIED-BY-LEAD (honest scope of my re-verification)

Primary files the opus lead read and confirmed: `key.js`, `noise.js`, `sign.js`, `node.js`, `invite.js`, `race.js`, `tracker.js`, `dht.js`, `wire.js`, `group.js`, `browser/transport.js`, `browser/p2p.js`, `init` (source + verify sections), `privacy.test.js`. Findings resting on subagent reads the lead did **not** open primary:
- `init.ps1` — INST-1/INST-2 Windows path (symmetric to `init`, high confidence, not directly read).
- `mdns.js` internals — MDNS-1 `respond()`/`decodeTxt()` behavior (the invite-not-sealed half **was** lead-verified via `node.js:237`).
- `transport-wss.js`, `browser/webrtc.js`, `browser/shim/*` — BB-2/3, BRW-1 relay-hostility, BRW-3 shim key handling.
- STUN-1 / NAT-2 exact line refs in `transport.js` STUN branch — cross-checked against the `onConnection`/`_onMessage` grep, not a full read.
- WIRE-cluster severity assumes an on-path/relay/same-NAT adversary (in-scope per `metadata-privacy.md` rows 2 & 6); against a purely off-path adversary these drop to LOW (connId unknown).
- GRP-1 exploitability assumes a G-holder can author a competing `create`; if the deployment restricts G to a single trusted issuer, it degrades to a benign concurrent-create convergence bug (still a determinism defect).

---

*End of sweep. Ranked: INST-1 (CRITICAL) · WIRE-1/2/3 · DOS-1 · META-1 · GRP-1/2/3/4 (HIGH) · NAT-1 (MED-HIGH divergence) · INST-2/LIVE-1/DHT-1/MDNS-1/BRW-1/BRW-2 (MED) · BRW-3/DOS-2/BURN-0 (LOW). Crypto core sound; the breaks are the layers around it. All fixes gate through the Complexity Adversarial Gate. Primary-source scope + UNVERIFIED items in §9.*
