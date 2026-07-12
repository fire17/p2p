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

> **UPDATE 2026-07-12b (redteam lane, opus @ xhigh):** the §9 UNVERIFIED list below is now **CLOSED** — every file was read primary. Results + 3 new unknown-unknowns + the build-order/collision map are in **§10**. The list is kept for provenance.

Primary files the opus lead read and confirmed: `key.js`, `noise.js`, `sign.js`, `node.js`, `invite.js`, `race.js`, `tracker.js`, `dht.js`, `wire.js`, `group.js`, `browser/transport.js`, `browser/p2p.js`, `init` (source + verify sections), `privacy.test.js`. Findings resting on subagent reads the lead did **not** open primary — **all now read primary in §10**:
- `init.ps1` — INST-1/INST-2 Windows path (symmetric to `init`, high confidence, not directly read). → **§10: INST-1 CONFIRMED; INST-2 does NOT apply to Windows.**
- `mdns.js` internals — MDNS-1 `respond()`/`decodeTxt()` behavior (the invite-not-sealed half **was** lead-verified via `node.js:237`). → **§10: CONFIRMED + sharpened.**
- `transport-wss.js`, `browser/webrtc.js`, `browser/shim/*` — BB-2/3, BRW-1 relay-hostility, BRW-3 shim key handling. → **§10: all read; BRW-1/BRW-3 confirmed; 3 NEW findings (BRW-4, DOS-1-WSS, BRW-5); WIRE-over-WSS elevated.**
- STUN-1 / NAT-2 exact line refs in `transport.js` STUN branch — cross-checked against the `onConnection`/`_onMessage` grep, not a full read.
- WIRE-cluster severity assumes an on-path/relay/same-NAT adversary (in-scope per `metadata-privacy.md` rows 2 & 6); against a purely off-path adversary these drop to LOW (connId unknown). → **§10: for the shipped browser/WSS path the relay is a GUARANTEED on-path adversary — WIRE cluster is UNCONDITIONAL there, not hypothetical.**
- GRP-1 exploitability assumes a G-holder can author a competing `create`; if the deployment restricts G to a single trusted issuer, it degrades to a benign concurrent-create convergence bug (still a determinism defect). → **§10: CONFIRMED against `group.js:193/198`; any G-holder can author a signed competing `create`.**

---

## 10. Lead deepening 2026-07-12b — §9 closed + new unknown-unknowns + build order

> **Author:** redteam lane (opus @ xhigh), primary-source reads of `init.ps1`, `src/rendezvous/mdns.js`, `src/transport-wss.js`, `src/browser/webrtc.js`, `src/browser/transport.js`, `src/browser/shim/node-crypto.js`, `src/browser/p2p.js`, re-reads of `src/wire.js`, `src/group.js`, `src/node.js`. Every claim below carries a `file:line`.

### 10.1 Confirmations against primary source (were subagent-only)

- **INST-1 (CRITICAL) — CONFIRMED on Windows.** `init.ps1:33` `$SrcDefault = 'https://github.com/fire17/p2p/archive/refs/heads/main.zip'` (floating `main`, not a pinned tag); `:195-207` downloads + extracts the zip with **no checksum/signature**; `:220-222` is an existence-only check (`package.json` + `bin\p2p.js`). The node runtime **is** SHA256-verified (`:150` `Get-FileHash`, `:151` mismatch → `Fail`). Identical asymmetry to POSIX `init` → arbitrary code exec on every install/`-Force` update via a compromised `main` or a MITM of `codeload.github.com`. Fix is shared with `init`: pin a release tag + verify a signed `SHASUMS` over the source archive.
- **INST-2 (MED) — does NOT apply to Windows (scope narrowed).** `Get-FileHash` (`init.ps1:150`) is built into PowerShell 5.1+ and is **always present**, so the POSIX `init` "fail-open when no `sha256sum`/`shasum`/`openssl`" hole has **no Windows analogue**. INST-2 is **POSIX-`init`-only**. (The Windows installer's only integrity hole is INST-1, which is fully symmetric.)
- **MDNS-1 (MED) — CONFIRMED + sharpened to a one-query LAN harvest.** `respond()` (`mdns.js:240-248`) answers with `[...announcements.values()]` — **every** active announcement — whenever any inbound packet's questions include `_p2p._tcp.local` (`:208`). In invite mode the blob is **unsealed** (`node.js:237` `mdns.createMdns(rz)`, no codec) so each TXT carries `rid` + the **full plaintext candidate blob incl. IP:port** (`encodeTxt`, `:146-151`). ⇒ any LAN device sends **one** PTR query and harvests every local p2p node's IP:port + rid. `decodeTxt` (`:154-163`) validates nothing beyond a `rid=` prefix + base64-JSON parse → LAN candidate-poisoning (bounded downstream by the commitment gate + Noise; a `lookup` only accepts a TXT whose `ridHex` matches what it wants, `:275`, so poisoning requires replaying an observed rid). Fix: seal the mDNS TXT in invite mode (reuse `inv.codec`); optionally stop answering blanket service queries.
- **BRW-1 (MED) — CONFIRMED.** `browser/transport.js:52-55` (`composePunch`) locks `outbound` to whichever leg delivers the first inbound frame, no shape check. A hostile WSS relay injecting any first byte wins the lock (`transport-wss.js:280-286` KNOCK path makes the WSS leg noisy first) → handshake outbound misroutes → dial stalls to `DIAL_TIMEOUT_MS`. Fails safe (Noise never completes), recoverable on retry. Fix stands: lock only on a well-formed HELLO/wire frame.
- **BRW-3 (LOW) — CONFIRMED.** `browser/shim/node-crypto.js` stores raw 32-byte scalars in a plain `KeyObject._raw` (`:71`); `browser/p2p.js:73-92` persists them as extractable hex in IndexedDB. Sync-shim tradeoff, documented (`node-crypto.js:26-27`); any XSS → identity theft. Accept; keep the BC-9 caveat current.
- **WIRE-1/2/3 (HIGH) — re-confirmed at line level.** `wire.js:260` `onAck(f.ack)` runs unconditionally before the type switch; `onAck` (`:202-217`) drops in-window inflight and can poison `sndUna` on a far-future ack → silent loss + wedge (WIRE-1). `:272-273` bare CLOSE on connId-match (WIRE-2). `:220-239` `onData` advances `rcvNext` (`:232`) after handing the payload to `onReliableCb` — a forged DATA at the predictable `rcvNext` burns that seq; the real frame later is `seqCmp<0` → dropped at `:222` (WIRE-3). Gate is connId-only (`:249`).
- **GRP-1/2/3/4 (HIGH) — re-confirmed at line level.** GRP-1: `foldMembership` visits `for (const h of byHash.keys())` (`group.js:193`) = receipt order; two `create` roots → first-visited wins admin (`:198`); any G-holder can author a valid signed competing `create` (`ingestOp` accepts it, `:265-281`). GRP-2: `rotate()` regenerates only the caller's `sendChain.ck` (`:320-327`); `remove()` → `rotate()` (`:438-443`); **no code reacts to an observed `remove` op** — non-admin survivors never rotate. GRP-3: KEYDIST handler (`:334-341`) sets `recvChains.set(S, ratchet(unb64(body.ck), …))` with **no signature over the body and no check that the delivering `peer` equals the claimed `body.s`**. GRP-4: `syncKeys` marks `keyedTo.add(S)` before `keydistTo` and only rolls back on a node-level throw (`:284-289`); `keydistTo` acks at the pairwise layer even if the recipient has no secure-group object → permanently marked, never re-keyed.

### 10.2 Non-issue I checked and falsified (recorded so nobody re-chases it)

- **WSS topic is `HKDF(S,…)`, not `HKDF(K_inv,…)` — but this is NOT an invite-mode bypass.** `transport-wss.topicFor(S,epoch)` (`transport-wss.js:49`) keys off the reusable `S`. That *would* let a bare-`S` holder locate a listener over the relay and elicit HELLO (META-1). **It does not apply**, because WSS + WebRTC are wired **only in the browser client**, and the browser is **reusable-S ONLY**: `browser/p2p.js` never passes `invite`/`makeRace`, and `browser/app.js:141` explicitly refuses invite dialing ("Invite dialing isn't supported in the browser yet"). The TUI never imports `transport-wss` at all (grep: only `browser/*` + tests). So no path runs WSS in invite mode → no bypass. (If WSS is ever wired into invite mode, this becomes a real META-1 vector — flag on that change.)

### 10.3 NEW unknown-unknowns (found while reading; ranked)

- **BRW-4 (HIGH, reliability — LIVE in shipped v0.2.0) — browser listener leaks RTCPeerConnections unboundedly → self-DoS.** `publishAll` re-announces every `ANNOUNCE_INTERVAL_MS = 10_000` (`webrtc.js:393`), and each announce builds `OFFERS_PER_ANNOUNCE = 4` fresh offers (`:366`), each a `new RTCPeerConnection` added to `live` **and** `pending` (`makeOffer` `:347-362`; `newPc` `:174-178`). A parked offer is removed from `pending` **only** on `dc.onopen` (`:354`) and from `live` **only** at `node.close()` (`:331`). Unanswered/expired offers are **never closed or GC'd** — no expiry timer, no cap. With `TRACKERS`=3 and `announceEpochs`≈1 that is **~12 leaked RTCPeerConnections every 10 s (~72/min, ~4300/hour)**, each holding an ICE agent + STUN state. A long-lived browser *listener* (the v0.2.0 headline "stay reachable at /app/") degrades and eventually exhausts the browser's connection/memory budget. **No attacker needed** — self-inflicted. Weakest link: `webrtc.js:347-362` (no offer expiry) + `:393` (10 s × 4) + `:174-178`/`:331` (`live` only cleared at teardown). *(Code-analysis-confirmed; NOT live-soaked — the build lane must add a soak/leak test to size time-to-failure exactly.)* **Fix:** close + evict a parked offer's pc if unanswered within an expiry (~120 s, matching the tracker's own offer-expiry note at `:49`); cap concurrent `pending`; `live.delete(pc)` on every close.
- **DOS-1-WSS (HIGH, within the relay/topic-knower threat model) — `transport-wss` `accepted` map is unbounded, one node peer-record per attacker-chosen senderId.** `inbound` (`transport-wss.js:179-196`) keys inbound sockets by a **sender-supplied** 16-byte id (`:181`), creates a `socketLike` + fires `onConnCb` for each new sender (`:189-194`), and **`accepted` (`:167`) is never evicted — no TTL, no cap**. `onConnCb` = `node._accept` → `acceptConnection` sends HELLO + allocates a peer record pre-auth (the same pre-auth allocation as DOS-1 over UDP). The relay operator IS the pipe (zero-cost injection of fresh senderIds); any other party who learns the topic can do it too. ⇒ DOS-1 extends to the shipped browser/WSS path with a **guaranteed** on-path attacker. Fix: cap + idle-evict `accepted`; defer the node peer-record until the handshake completes (shared with DOS-1). *(Minor sibling: `dials` (`:168`, `:261`) is also never evicted after a dial — LOW self-leak.)*
- **WIRE-over-WSS (elevation, not new mechanism) — the relay is a GUARANTEED on-path adversary for WIRE-1/2/3.** `transport-wss.inbound` hands the cleartext wire frame straight up to `wire.js` (`:183`, `:186`/`:195`); the relay reads `connId/seq/ack` and can forge `ack`/`CLOSE`/`DATA` at will. So the WIRE cluster's "assumes an on-path adversary" caveat (§9) is **unconditional** for the WSS transport — a hostile or subpoenaed relay can silently drop/wedge/close **any** browser session. This raises the browser-path priority of the WIRE control-plane-auth fix.
- **BRW-5 (MED) — unbounded chunk-reassembly buffer in `socketFromChannel`.** `reasm` (`webrtc.js:89`) is keyed by a **sender-controlled** `msgId` (`:127`); partial reassemblies are **never timed out and the number of concurrent in-flight ids is never capped** (`:133-145`). A peer that has an open DataChannel (post-DTLS, **pre-Noise**) can stream many chunk-starts (`total` up to `MAX_CHUNKS=4096` → `new Array(total)`) with distinct ids → memory exhaustion before Noise gates anything. Bounded (needs an established channel; over WebRTC only the DTLS peer can send). Fix: cap concurrent `reasm` entries + evict stale partials on a timer.

### 10.4 Recommended BUILD ORDER + effort + collision map

**Hub-file collision map (which fixes touch the same files — serialize or worktree these):**

| File | Touched by | Serialization rule |
|---|---|---|
| `init` + `init.ps1` | INST-1 (both) | Installer-only; **no `src/` collision** — fully parallel-safe. |
| `wire.js` | WIRE-1/2/3 | Isolated except the `node.js` app-layer edits below. |
| `node.js` | **WIRE-1/2/3, DOS-1, META-1** | **Three-way collision.** DOS-1 + META-1 both edit `acceptConnection` (`node.js:396-449`, HELLO at `:414`, peer alloc at `:435`) → **pair them into ONE lane**. WIRE edits the app layer (`onAppCipher`/`wireSend`/`attach`) → a **separate** lane that must not overlap in time with the accept-path lane. |
| `transport.js` | DOS-1, META-1 | Both edit `_acceptInbound`/`_peers`/`_accepted` → same lane as the node accept-path fix. |
| `invite.js` | META-1 | K_inv-proof helper — additive, low collision. |
| `group.js` | **GRP-1, GRP-2, GRP-3, GRP-4** | **Four-way collision, one file.** Run as **ONE group-hardening lane, fixes sequential** — they interact (GRP-2's every-survivor-rotate rides GRP-1's canonical order and GRP-4's keydist path). Do **not** fan these to parallel worktrees. |
| `transport-wss.js` + `webrtc.js` | DOS-1-WSS, BRW-4, BRW-5, BRW-1 | Browser-transport lane, isolated from the TUI hub files → parallel-safe vs the node/group lanes. |

**Recommended sequence (ranked; each ships through §6 CAG):**

1. **INST-1** (CRITICAL) — pin tag + verify signed source in **both** `init` and `init.ps1`. Effort **S–M** (~½–1 day; the real work is publishing a signed `SHASUMS`/tag in the release process). Parallel-safe. **Running now (inst1-harden lane).**
2. **WIRE-1/2/3** (HIGH) — authenticate the control plane (bind `type‖connId‖seq‖ack` into the DATA AEAD as AD, or MAC the header with a post-handshake key; move ack/close semantics into the Noise app layer). Effort **L** (~1–2 days; wire-format change → re-run TUI+browser+werift interop, and the werift gate self-skips without werift installed — re-run it, don't trust the old log). Highest-risk change. Edits `wire.js` + `node.js` app layer.
3. **DOS-1 + META-1 together** (HIGH) — one accept-path lane: cap + idle-evict pre-auth accepts, defer the peer record until handshake completes (DOS-1), and gate HELLO emission on a K_inv-authenticated probe in invite mode (META-1). Effort **M–L** (~1.5–2 days combined). Edits `node.js` `acceptConnection` + `transport.js` accept path + `invite.js`. **Must not run concurrently with the WIRE lane (both edit `node.js`).**
4. **GRP lane** (HIGH), sequential in `group.js`: **GRP-1** canonical root order — sort ops/roots by `opHash` so the fold is a pure function of the op set (effort **S**, ~½ day) → **GRP-3** sign KEYDIST bodies (or require `peer.key === body.s`) (effort **S–M**, ~½ day) → **GRP-2** every-survivor auto-rotate on an observed `remove` op (effort **M**, ~1 day; watch the n-1 rotate/keydist burst under CAG check 4) → **GRP-4/#32** confirm group-level delivery before marking `keyedTo`, or member-side pull (effort **M**, ~1 day). Whole lane ~3 days. Parallel-safe vs installer/wire/node lanes.
5. **Browser-transport lane** (HIGH reliability): **BRW-4** offer-expiry + `live` eviction (top priority — a live shipped bug), **DOS-1-WSS** cap/evict `accepted`, **BRW-5** reasm cap/TTL, **BRW-1** validated outbound lock. Effort **M** (~1–1.5 days). Edits `webrtc.js` + `transport-wss.js` + `browser/transport.js` — isolated from the TUI hub, so **fully parallel** with lanes 2–4. Add the BRW-4 soak test the fix needs anyway.
6. **NAT-1** (MED-HIGH, DESIGN divergence) — decide: fix roaming (needs an authenticated connId, i.e. depends on WIRE) or retract the D8/D9 claim. **Blocked on WIRE** if fixing; free if retracting.
7. **INST-2 (POSIX-only) / LIVE-1 / DHT-1 / MDNS-1** (MED) — per §4/§10.1.

**Leak-monitor assertions each lane must add (CAG check 6):** wire-header-authenticated (a forged ack/close/DATA is rejected); no-pre-auth-unbounded-allocation (UDP `_peers`/`_accepted` **and** WSS `accepted`); group non-admin-survivor-ejects-removed-member; no-IP-on-any-surface incl. **mDNS TXT in invite mode**; and — new — **bounded-RTCPeerConnection-count** for a long-lived browser listener (BRW-4 regression tripwire).

---

*End of sweep. Ranked: INST-1 (CRITICAL) · WIRE-1/2/3 · DOS-1 · META-1 · GRP-1/2/3/4 (HIGH) · NAT-1 (MED-HIGH divergence) · INST-2/LIVE-1/DHT-1/MDNS-1/BRW-1/BRW-2 (MED) · BRW-3/DOS-2/BURN-0 (LOW). Crypto core sound; the breaks are the layers around it. All fixes gate through the Complexity Adversarial Gate. Primary-source scope + UNVERIFIED items in §9.*
