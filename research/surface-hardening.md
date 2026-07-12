# p2p — Surface-Hardening Study: Surface Cycling (A) & Detail Sharding (B)

> **Research Lane: Surface Hardening (v2).** Owner: fire17. Status: **DECISION-GRADE DESIGN + ADVERSARIAL VERDICT** (design only — NO `src/` changes).
> **Date:** 2026-07-12. **Author:** surface-hardening lane (opus @ xhigh), adversarial review discipline.
> **Reads on top of:** `research/metadata-privacy.md` (v1 design, §8 threat table, §9 phases), `src/invite.js`, `src/rendezvous/{race,tracker,dht}.js`, `src/key.js`, `DESIGN.md`.
>
> **Reading contract:** a senior engineer reading ONLY this file can decide whether to build either proposal, holds the reliability proof for A and the three-axis refutation of B, and can run the "Complexity Adversarial Gate" on any future change. Every non-obvious claim carries reasoning or a code citation; anything not code/math-verified is marked **UNVERIFIED**.

---

## 0. The owner's words (the spec — quoted verbatim, sacred)

**PROPOSAL A — surface diversification / cycling:**
> "diversify… every public surface we touch we cycle and dont use again until we have no other reliable routes - so our traffic is even more disperced making it even harder to connect any two operations together even if the public surface we used is compromised… so maybe choose public surfaces randomly - (whatever we do we must make sure that the reliability of discovery is not effected)"

**PROPOSAL B — detail sharding:**
> "shard our details into different parts across several random surfaces - then the client could only decrypt the final details after all shards are found and used together correctly - does this strategy make sense and would harden us"

**STANDING PRINCIPLE (governs every verdict below):**
> every complexity must be constantly challenged/attacked to make it misbehave; every complexity adds attack surface; a change must harden security WITHOUT opening new attack angles; if hardening one aspect opens a window elsewhere it may not be worth it and staying simple is optimal — VERIFY completely; the weakest link is the only one that must break to leak metadata or data; always map/analyze/observe/monitor.

---

## 1. TL;DR — the two verdicts in twelve lines

1. **Proposal A (surface cycling): WORTH-IT-WITH-CONSTRAINTS, but modest and second-order — ship it AFTER v2 burn, not instead of it.** The literal "choose surfaces randomly" is **rejected** (independent per-peer randomness desyncs the two peers → breaks discovery). The safe realization is a **deterministic-to-both / pseudorandom-to-outsiders** selection: `π = keyed_shuffle(pool, HKDF(K_inv,"surface-sel",epoch))`; both peers derive the identical `π`; each uses a **prefix** and **monotonically expands** it under failure; the degenerate case is today's full fan-out. Reliability is then **provably equal to today** (§3.3). Benefit is real but bounded: single-operator op-coverage drops from 100% to ≈`k/N`; contact-pairing observers drop from `N` to ≈1. **Zero** benefit vs colluding operators or a global passive adversary, and **zero** effect on the dominant IP residual.
2. **Proposal B (detail sharding): NOT-WORTH-IT.** The candidate blob is **already AEAD-sealed** (`src/invite.js sealBlob`, 544 B, indistinguishable from random without `k_ip`). Splitting an already-encrypted blob across surfaces adds **no confidentiality** against the real adversary (a surface without `k_ip` already learns nothing from the *whole* blob, so a *fragment* learns nothing new). It **loses reliability** (`all-shards ⇒ P=∏P(up)`, the inverse of race-reads; no threshold setting beats replication) and **increases IP-correlation** (you must contact *all* `n` shard-surfaces → your source IP appears at `n` operators — the exact new attack angle the owner warned of). It fails the standing principle on three axes. **Burn-after-connect (v2 §9) dominates it** on the owner's own "hardens-without-new-window" test.
3. **Doctrine:** §6 gives the reusable **Complexity Adversarial Gate (CAG)** — 8 checks any future hardening change must pass before it ships — and §7 sketches the **standing leak-monitor** (generalizing `test/privacy.test.js`'s observer-capture into a continuous no-IP/no-marker assertion over every surface).
4. **No third option dominates both.** The recommendation is a *prioritization*, not a new mechanism: **v2 burn first** (simplest change, closes the most residual — the exposure *window*), **A-done-right** as an optional deterministic-prefix, tracker-pool-only refinement behind the CAG, and **v3 onion** as the only thing that closes the real IP residual.

---

## 2. The analysis frame — what a surface ACTUALLY sees today (invite mode)

Anchor every claim to the concrete per-op view of a single rendezvous surface in **invite mode** (v1, shipped):

| Datum on the wire | What it is | Leaks? |
|---|---|---|
| `rid_inv` / BEP44 `target` | `HKDF(K_inv,"p2p-rvk-<ch>-v1",epoch)` (20 B) → SHA1(bep_pk‖rid). Rotates **per invite × per epoch**. | Opaque. Unlinkable to non-holders; a non-holder cannot even *compute* it. |
| sealed candidate blob | `salt16 ‖ ChaCha20-Poly1305(pad512) ‖ tag16` = **544 B fixed** (`SEALED_LEN`). No IP/port/marker. | Ciphertext, indistinguishable from random without `k_ip`. Proven in `privacy.test.js`. |
| **your SOURCE IP** | the transport src of the packet/socket you open to the surface. | **LEAKS — unavoidable.** You are talking to them. Only v3 onion removes it (`metadata-privacy.md` §8 rows 2 & 6). |
| timing / cadence | when you announce/read | Traffic-analysis handle for a global adversary; padding+cadence blunt, don't erase. |

**The real residual metadata handle, stated exactly:** a single operator sees `(source IP X) interacted with (rid R) at (time T)`. `rid` rotation already breaks *rid*-linkage across invites — but the **IP** links your ops *at that one operator*, and a **global adversary links IP X across all surfaces**. Everything below is judged against how much of *this* it removes.

**One structural fact that pre-empts both proposals (from `metadata-privacy.md` §1):** *no free public channel offers read-side access control.* Both proposals try to buy privacy by manipulating *which* channel and *how much of the payload* rides it. Neither can change what a channel you *touch* sees at the transport layer (your IP). Keep that boundary in view — it is where both proposals hit their ceiling.

**What already cycles for free (a load-bearing finding):**
- **DHT storing nodes already rotate per invite/epoch.** In invite mode the BEP44 `target = SHA1(bep_pk ‖ rid)` and `rid = HKDF(K_inv, "dht", epoch)` (`src/rendezvous/dht.js` `announceBep44` + `src/invite.js` `bep44Target`). The 8 storing nodes are the 8 closest to that target — so they **change with every epoch and every invite by construction**, with zero new code. Proposal A's "diversify across the DHT" is **already realized**. *(UNVERIFIED that two epochs land on disjoint node sets in the live DHT — logically forced by target rotation, not live-measured.)*
- **mDNS is LAN-only** (`src/rendezvous/mdns.js`) — a broadcast segment, not a chooseable "public surface." Out of scope for internet-metadata cycling.
- **⇒ The ONLY surface where cycling is even applicable is the fixed WSS tracker list** — `TRACKERS = [openwebtorrent, webtorrent.dev, btorrent.xyz]`, and today `createTracker` opens a conn to **all three** on every announce (`tracker.js` `announce`: `trackers.map(...)`). So Proposal A concretely reduces to: **cycle the WSS-tracker pool instead of always publishing to all 3.**

---

## 3. Proposal A — surface cycling

### 3.1 The reliability crux (why the literal ask is unsafe)

The owner's literal phrasing — "choose public surfaces **randomly**" — if implemented as *each peer independently picks random surfaces*, **breaks discovery**: publisher Alice picks `{t1}`, reader Bob picks `{t2,t3}`, `P ∩ R = ∅`, they never meet. Discovery reliability is the owner's own hard constraint ("we must make sure that the reliability of discovery is not effected"), so independent randomness is a **non-starter** and is rejected.

The realization that *does* preserve reliability: selection must be **deterministic to both peers and pseudorandom only to outsiders**. Both hold `K_inv`; derive an identical permutation from it:

```
seed = HKDF(K_inv, salt="p2p-surface-sel-v1", info=epoch, L=32)     // both peers, same epoch ⇒ same seed
π    = keyed_shuffle(pool, seed)                                     // Fisher–Yates driven by a CSPRG stream from seed
```

- `pool` = the vetted WSS-tracker set (today N=3; grow+vet toward 8–10 for the benefit to matter, §3.4).
- Publisher announces to the **prefix** `P = π[0..a)`; reader reads the **prefix** `R = π[0..b)`.
- Under failure to meet, **both** expand their prefix monotonically (`a←a+1`, `b←b+1`) down the *same* `π`, capped at `N`. The cap = **full fan-out = today's behavior**.
- `π` is per-`(K_inv, epoch)`; the existing ±1-epoch read tolerance in `race.js` (`resolveEpochs`) already means both peers cover the same epochs, so both derive the same `π` for each epoch checked.

### 3.2 The desync trap, named precisely

Two peers desync **iff their prefixes stop sharing an up surface**. That happens only if a peer **skips or reorders** an element of `π` based on **local** state (e.g. "`π[i]` looks dead to me, I'll drop it"). Then Alice's set and Bob's set are no longer nested prefixes of one `π`, and they can miss each other even when a mutually-reachable surface exists. The fix is three guardrails:

- **G1 — `π` is seeded ONLY by `(K_inv, epoch)`**, never by local health, RTT, or load. Both peers compute byte-identical `π`.
- **G2 — selection is a PREFIX; expansion is MONOTONIC-ADD.** A peer may *add* `π[next]` when it hasn't connected yet; it may **never remove, skip, or reorder** a surface because of local health. Health can *trigger expansion*, never *reshape the order*.
- **G3 — both peers expand independently but deterministically toward the cap `N`;** the degenerate state is full fan-out.

Under G1–G3, every peer's selected set is a prefix of the *same* `π`, so any two selected sets are **nested** — their intersection is the shorter prefix, always non-empty. That is the whole reliability proof.

### 3.3 Reliability proof (quantified — not hand-waved)

**Setup.** Let `U ⊆ pool` be the surfaces that are up-and-mutually-reachable at rendezvous time. `P = π[0..a)`, `R = π[0..b)`, with `a,b` growing from `k0` to `N` under G2/G3.

**Lemma (shared-prefix).** Because `P` and `R` are prefixes of the *same* permutation `π`, `P ∩ R = π[0..min(a,b)) ⊇ {π[0]}` for all `a,b ≥ 1`. The intersection is never empty and grows monotonically as either prefix expands.

**Theorem (reliability preserved).** Meeting succeeds once the shared prefix intersects `U`. As `a,b → N`, the shared prefix → `pool`, so meeting succeeds **iff `U ≠ ∅`**. Today's full fan-out (`P = R = pool`) also succeeds **iff `U ≠ ∅`**. Therefore

```
P(eventual meet | cycling+monotonic-expansion) = P(U ≠ ∅) = P(eventual meet | today's fan-out).
```

Reliability (success probability) is **exactly preserved**. ∎

**What is NOT free — latency, not success.** If the first mutually-up surface sits at index `j` in `π`, cycling reaches it after `⌈(j+1−k0)/step⌉` expansion rounds, whereas fan-out reaches it in round 0. Expected extra latency = `rounds × expansion-cadence`. With trackers live-probed healthy (`U ≈ pool` most of the time), `j = 0` w.h.p., so **expected extra latency ≈ 0 in the common case**; the cost materializes only when top-of-`π` surfaces are down. The LAN "blazingly fast" path is **untouched** — mDNS is separate and never cycled (`race.js` phases mDNS ahead of the internet channels regardless). *(UNVERIFIED: expansion latency argued analytically, not benchmarked.)*

**Contrast with today, in one line:** today = *maximum-redundancy, zero-latency-penalty, maximum-per-operator-exposure.* Cycling = *same success probability, small latency penalty only under partial failure, reduced per-operator exposure.* The trade is exposure-for-latency-under-failure, with success probability held constant.

### 3.4 Security benefit — honest and bounded

Let `N = |pool|`, `k` = prefix length actually used in the common (all-up) case.

- **Single curious/compromised operator (non-colluding).** Operator `o ∈ pool` is in your first-`k` with prob ≈ `k/N` per invite (uniform `π`). So `o` sees ≈`k/N` of your invites instead of **100%** today. With the **default pool N=3, k=1 ⇒ 33%** (weak — still a third). Benefit needs a **larger vetted pool** (N=8–10 ⇒ 10–12%). This is the metadata analog of "spread across relays so no one relay sees all your traffic."
- **Contact-graph spread.** Today all `N` tracker operators see both `(IP_Alice, rid_R)` and `(IP_Bob, rid_R)` under one rid → **every** operator learns *Alice met Bob* (the `DESIGN.md` §3 / `metadata-privacy.md` residual). With cycling, only the operator(s) on the shared meeting prefix learn it → pairing-observers drop from `N` to **≈1**. **Floor: ≥1 operator ALWAYS learns each successful pairing** — inherent, because the two peers must meet *somewhere*. Cannot go below 1.
- **Global passive adversary / colluding operators:** **ZERO benefit.** They see all surfaces and your IP at each, regardless of which subset you chose (`metadata-privacy.md` §8 row 4). Cycling hides *nothing* from them.
- **The dominant IP residual (rows 2 & 6):** **ZERO effect.** Cycling changes *how many* surfaces see your IP, never *whether* the ones you touch see it. Only v3 onion removes that.

### 3.5 Red-team — does cycling open a new window? (net-attack-surface accounting)

New moving parts: (1) `keyed_shuffle(pool, HKDF(K_inv,…))`; (2) a prefix-expansion state machine on both publish and read sides.

| Attack | Analysis | Verdict |
|---|---|---|
| **Selection leaks `K_inv` / links invites** | An operator sees *which* surfaces you used = a sample of `π`. Recovering `K_inv` needs inverting HKDF-SHA256 (infeasible). Across invites `K_inv` differs ⇒ `π` independent ⇒ no cross-invite linkage from the selection. | **No leak.** |
| **Predictable schedule** | `π` is per-`(K_inv,epoch)`; predictable only to a `K_inv` holder. **Constraint:** cycle on `HKDF(K_inv,…)` only — **invite mode ONLY**. Reusable-`S` mode must stay full-fan-out (an `S`-holder could predict `HKDF(S,…)` and pre-position at your next surface). S-mode already forfeits privacy (`DESIGN.md` D2), so this costs nothing. | **Safe under the invite-mode-only constraint.** |
| **Enumeration via targeted DoS** | An adversary who DoSes your top-`π` surfaces forces expansion → over one invite's life, worst case you touch **all** of `pool`. Net exposure in that worst case = **full fan-out = today's baseline** — never below. The enumerated order `π` is per-invite and burned, so revealing it has **no reusable value**. | **Degrades to baseline, never below. Accept.** |
| **New weakest link?** | The weakest link stays your **source IP** at whichever surface you touch (rows 2 & 6). Cycling touches *fewer* surfaces normally, the *same* in the worst case, and introduces **no new secret and no new party** into the trust base. | **Weakest link unchanged.** |

**Net:** new attack surface ≈ 0 (bounded above by baseline exposure), *provided* G1–G3 and the invite-mode-only constraint hold. The subtle correctness risk is the **desync trap (§3.2)** — a reliability footgun, not a leak — which is why G2 is non-negotiable.

### 3.6 Verdict A — WORTH-IT-WITH-CONSTRAINTS (deferred behind v2 burn)

Ship **only** in this exact form, and **only after** v2 burn:

1. **Invite mode only.** Reusable-`S` mode stays full-fan-out (unchanged wire).
2. `π = keyed_shuffle(pool, HKDF(K_inv,"p2p-surface-sel-v1", epoch))`. Identical on both peers (G1).
3. **Prefix selection + monotonic expansion** (G2), degenerate case = full fan-out (G3).
4. **WSS-tracker pool only.** The DHT already rotates storing nodes by the `K_inv`-derived target (§2); mDNS is LAN. No cycling code for either.
5. **Grow + vet the tracker pool first.** At N=3 the coverage floor is 33% (marginal); the benefit is proportional to pool size, but a bigger pool also means more distinct operators to vet (each sees less — see the CAG check-3 tension).
6. **Reject** the literal independent-random selection (breaks G1 → breaks discovery).

**Minimal-risk entry point (a genuine sub-finding): ASYMMETRIC cycling.** Let the **dialer/reader** cycle a prefix while the **listener/publisher stays full-fan-out**. Reliability is then *trivially* safe with no state machine (the publisher is everywhere, so `π[0]` is always covered — the shared-prefix lemma holds with `a = N`), and it reduces the **dialer's** IP-spread with **zero desync risk**. It protects only one side, but the dialer is the party *initiating* contact and often the more sensitive one. This is the lowest-complexity way to bank part of A's benefit while the full mutual-cycling machine is still behind the CAG.

**Why deferred, honestly:** the benefit is second-order (doesn't touch the IP residual; 33% floor at the default pool), the desync discipline is subtle, and **burn (v2) is simpler and closes more** (the exposure *window*). Cycling is a *complement* to burn, not a substitute, and its complexity only earns its keep once the tracker pool is grown and burn is in place.

---

## 4. Proposal B — detail sharding

### 4.1 The central question, answered head-on

**"Split the details across surfaces so the client can only decrypt after all shards are found."** But the details are **already sealed**: `sealBlob` (`src/invite.js`) emits `salt16 ‖ AEAD(pad512) ‖ tag16` = 544 B, and `privacy.test.js` proves a surface holding the **whole** blob learns nothing — no IP, no port, no marker, indistinguishable from random without `k_ip`.

So: **what confidentiality does splitting an already-encrypted blob add?**

> **None.** Against the real adversary — a surface (or operator) *without `k_ip`* — the whole 544 B ciphertext already reveals nothing (confidentiality ≈ `2^-128`). A ciphertext **fragment** cannot reveal *less than nothing*; it reveals exactly what the whole revealed, which is nothing. "Decrypt only after all shards" is already true of the *single* blob: without `k_ip` you can't decrypt it whether you hold 1 byte or all 544. Splitting adds a reassembly step, not a confidentiality step.

The owner's intuition ("could only decrypt after all shards are used together") describes **exactly what AEAD already gives** — the blob is atomic and useless-until-you-hold-the-key. Sharding re-implements that property at the transport layer, worse.

### 4.2 The reliability cost (the killer)

- **All-shards-required:** `P(discovery) = ∏ᵢ P(surface_i up)` — **decreases** as you add surfaces (any one down ⇒ total failure). This is the **exact inverse** of race-reads robustness, where replicating the whole blob gives `1 − ∏ᵢ P(down_i)` → **1** as surfaces are added. Today's replication is effectively **1-of-n**: any single surface up ⇒ you get the whole blob.
- **Does threshold k-of-n (Shamir) rescue it?** `P(recover) = P(≥k of n up)`. By monotonicity, `P(≥k of n) ≤ P(≥1 of n)` for all `k ≥ 1`, with equality only at `k=1` — and `k=1` threshold **is** replication (= no sharding). **So no threshold setting beats replication on reliability; every `k>1` is strictly worse.** Sharding cannot satisfy the owner's hard reliability constraint. *(Standard probability; correct by monotonicity of the survival function.)*

### 4.3 The IP-correlation cost (the owner's exact worry, realized)

Placing `n` shards means you must **contact all `n` shard-surfaces to publish**, and the reader must contact all `n` (or ≥k) **to fetch** — so your **source IP appears at `n` operators per op, mandatorily**. That is *more* IP-correlation exposure, and it is the **direct opposite of Proposal A's goal**: A *reduces* surface-touches to spread your IP thinner; B *multiplies* them. B manufactures the new attack angle the standing principle warns against.

### 4.4 Steelman — the strongest version, then its death

1. **Defense-in-depth vs a crypto break / `k_ip` leak.** *If* ChaCha20-Poly1305 were broken (or `k_ip` leaked), a surface holding the full ciphertext could decrypt; a shard-holder couldn't (missing bytes). **Death:** this helps only against an adversary who breaks the AEAD **AND** is surface-limited (sees only some shards) — a narrow conjunction. A global observer or colluding operators reassemble and decrypt anyway. And you pay §4.2 reliability + §4.3 IP cost for that narrow, conditional hedge. Marginal, and the standing principle says a conditional hedge that opens two concrete windows is not worth it.
2. **Shard `K_inv` itself, not the blob.** **Death on contact:** `K_inv` is shared **out-of-band** (handed to the invitee directly). There is **nothing to place** on surfaces — the invitee already holds all of it. Sharding `K_inv` across surfaces would *add surfaces to the secret's trust base* (a surface compromise + the others ⇒ key recovery), which is **strictly worse** and destroys the "only the invitee, out-of-band" property that is the whole point of `K_inv`. Reject.
3. **Shard across TIME (publish parts at different times).** This **collapses into Proposal A** (surface/time cycling) plus reassembly fragility — not a distinct win. Judge it as A.

No steelman survives the reliability + IP cost.

### 4.5 Head-to-head vs staying simple (the owner's own test)

The residual sharding *gestures* at is **post-hoc capture** (someone stores the ciphertext, hopes to decrypt later — `metadata-privacy.md` §8 row 5). The **simpler** change that targets exactly that residual is already the v2 plan (`metadata-privacy.md` §9): **burn-after-connect + short TTL + `K_inv` retire**.

| | Sharding (B) | Burn (v2, already planned) |
|---|---|---|
| Confidentiality added | **0** (blob already sealed) | forward-secret metadata (retired `K_inv` ⇒ later key compromise reveals nothing) |
| Reliability | **worse** (`∏P(up)`) | **unchanged** |
| New surfaces touched | **+n** (more IP-correlation) | **0** |
| New secret / trust base | reassembly + placement | none |
| Closes the target residual? | no (adds nothing over AEAD) | **yes** (no lingering, replayable, later-decryptable route) |

Burn wins on every row. **Staying simple is optimal here** — precisely the owner's law.

### 4.6 Verdict B — NOT-WORTH-IT

Sharding the candidate blob **adds no confidentiality** (it is already AEAD-sealed), **loses reliability** (`∏P(up)` vs race-reads; no threshold beats replication), and **increases IP-correlation** (mandatory contact with all `n` shard-surfaces). It fails the standing principle on three axes at once. The one narrow steelman (defense-in-depth vs a crypto break) is conditional and dominated by burn. **Do not build it.** A NOT-WORTH-IT with airtight reasoning is the correct outcome here — the complexity does not pay.

---

## 5. Escalation check — is there a THIRD option that dominates both?

**No single new mechanism dominates.** The honest map:

- The **dominant residual** is your **source IP** at contacted surfaces + **timing** (global adversary). Neither A nor B touches it; **only v3 (Tor v3 onion, `metadata-privacy.md` §9) removes it**, because the onion address *is* a `K_inv`-derived key and the peer never learns your real IP.
- A (done right) buys a **modest, second-order** reduction in single-operator coverage. B buys **nothing** and costs reliability + IP.
- The **simplest high-value change** is **v2 burn** — it closes the exposure *window* with zero new surface.

**Recommended package (a prioritization, not a new primitive):**
1. **v2 burn** — build first. Highest residual-closed per unit complexity.
2. **A-done-right** — optional, deterministic-prefix, tracker-pool-only, invite-mode-only, behind the CAG (§6). Start with **asymmetric cycling** (§3.6) if any cycling ships. Grow the tracker pool first.
3. **v3 onion** — the only path that closes rows 2 & 6. Heavy dep; gate behind a flag.

Since the team brief already sketched the deterministic-prefix reinterpretation as the *intended* reading of A, this is a recommendation, **not** a blocking ambiguity — no STOP needed. The one item worth the owner's eye is the **asymmetric-cycling** minimal variant (§3.6): it banks part of A's benefit at near-zero complexity and risk, and may be the right *first* increment.

---

## 6. Doctrine — the Complexity Adversarial Gate (CAG)

A reusable, runnable checklist. **Every future hardening change carries a filled CAG block in its design doc or it does not ship.** Modeled on the "Verification status (honest)" discipline and the §8 threat table that conformance-reviewed v1.

| # | Check | Artifact it must produce | Fail ⇒ |
|---|---|---|---|
| 1 | **Residual-closed (net-positive)** | Name the exact residual it closes **and quantify** (which adversary, how much); name what it does **NOT** close. | Closes nothing measurable → STOP. |
| 2 | **Attack-surface enumeration** | List every new moving part; for each, an adversary who *tries to make it misbehave* + the airtight reason it fails (or the residual). "Every complexity adds attack surface — enumerate it or you didn't look." | Any unenumerated part → not reviewed. |
| 3 | **Weakest-link map** | Identify the post-change weakest link; prove it is **not weaker** than the current weakest link (the weakest link is the only one that must break to leak). | New weaker link → reject or redesign. |
| 4 | **Reliability proof (quantified)** | State `P(discovery)` before/after in closed form; prove **≥**. (The §3.3 prefix theorem is the template. No hand-waving; "still reliable" is not a proof.) | `P` drops → reject (owner's hard constraint). |
| 5 | **Degenerate-safe** | Under adversarial/failure conditions the change **degrades to current behavior, never below** (cycling → full fan-out; expansion cap = N). | Can go below baseline → reject. |
| 6 | **Monitoring hook** | A concrete assertion added to the standing leak-monitor (§7) that **fires** if the change regresses (leaks IP/port/marker, breaks unlinkability, changes blob length). | No hook → not shippable. |
| 7 | **Flag-gated + reversible** | Behind a flag, **default-OFF** until the gate passes on live surfaces; byte-identical wire when off. | Not reversible → reject. |
| 8 | **Simplicity dominance** | Is there a simpler change closing the same residual within a small factor? If yes, prefer it (owner's law: staying simple is optimal). | Dominated by a simpler option → prefer the simpler. |

**Worked example — this study run through the CAG:**
- **Proposal A** passes 2,3,5,7 cleanly; passes 4 via §3.3; passes 1 *modestly* (bounded benefit); needs 6 (add a "selection ⊆ pool ∧ reveals no `K_inv` bits" assertion); on 8 it is a *complement* to burn, not dominated. ⇒ **conditional ship.**
- **Proposal B** fails 1 (closes nothing over AEAD), fails 4 (`P` drops), and is dominated on 8 by burn. ⇒ **reject.** The CAG mechanically reproduces both verdicts.

---

## 7. The standing leak-monitor (map / analyze / observe / monitor)

Generalize `test/privacy.test.js`'s `SpyRelay` + `spyDhtBackend` — which already **record every byte a surface sees** — into a reusable **Observer** any surface plugs into, and run a fixed no-leak battery over it continuously.

**Shape.**
- `Observer.capture(bytesOrRecord)` — an interface every surface backend is wired to: tracker relay (SDP bytes), DHT storing node (BEP44 `put`/`get` value), mDNS segment (TXT records). The union of what all observers saw = the adversary's view.
- **Standing assertions**, over that union, for **every mode × every surface**, across a battery of synthetic candidate sets (IPv4, IPv6, LAN, relay):
  - **A** no plaintext IP of any candidate.
  - **B** no plaintext port.
  - **C** no marker/tell literal (`"p2p-blob"`, `"candidates"`, any `p2p-` string beyond what WebTorrent itself shares).
  - **D** every sealed value is exactly `SEALED_LEN` (544 B) — no length side-channel.
  - **E** unlinkability: rids for two invites (different `K_inv`) share no prefix; rids across epochs for one invite differ.
  - **F** *(cycling only)* selection set ⊆ pool, and is statistically uniform over the pool across many `K_inv` (reveals no `K_inv` bits).

**Two legs:**
1. **CI gate (always-on floor)** — deterministic, offline, extends the existing `privacy.test.js` suite. Every new surface or hardening MUST register an Observer and pass A–F before merge (this *is* CAG check 6).
2. **Live canary (the "observe real surfaces" leg the owner asked for)** — a throwaway invite run against real trackers/DHT with a passive local capture (in-process relay spy, or `tcpdump`/pcap on the loopback/uplink), asserting A–D on **real wire bytes**. Run on a schedule; a failure means a real surface is seeing something CI's mocks didn't model.

This turns the one-shot `privacy.test.js` observer-capture into a **continuous** "no IP / no marker / fixed-length / unlinkable" invariant that any future change is measured against — the owner's "always map/analyze/observe/monitor," made executable.

---

## 8. UNVERIFIED / hand-offs (honest list)

- **`keyed_shuffle` construction** — specified as Fisher–Yates seeded by an HKDF-CSPRG stream; **not yet implemented or tested**. The §3.3 reliability theorem is math-proven here but not code-verified.
- **Benefit percentages** (`k/N` single-operator coverage) assume a uniform `π` and independent operator selection; real tracker geo-reachability is **non-uniform** (some trackers unreachable from some networks), so actual coverage reduction may differ. **UNVERIFIED** against live tracker-reachability data.
- **"DHT storing nodes already rotate per invite/epoch"** — derived from `dht.js` (`target = SHA1(bep_pk‖rid)`, `rid = HKDF(K_inv,ch,epoch)`); logically forced by target rotation, but I have **not live-measured** that two epochs land on disjoint storing-node sets.
- **Expansion-latency cost** of cycling under partial failure — argued analytically (`rounds × cadence`); **not benchmarked**.
- **Shamir "strictly less robust than 1-of-n replication"** — by monotonicity of the survival function `P(≥k of n) ≤ P(≥1 of n)`, equality at `k=1`; correct, not separately cited.
- **Global-adversary "zero benefit from cycling"** assumes the adversary sees all surfaces AND your IP at each (`metadata-privacy.md` §8 row 4); consistent with the v1 model, not independently re-derived here.

---

*End of study. Verdicts: **A = WORTH-IT-WITH-CONSTRAINTS (deferred behind v2 burn; deterministic-prefix, tracker-pool-only, invite-mode-only; asymmetric cycling as the minimal entry)**; **B = NOT-WORTH-IT (adds no confidentiality, loses reliability, increases IP-correlation; burn dominates)**. Doctrine: the Complexity Adversarial Gate (§6) + the standing leak-monitor (§7). Primary sources: `research/metadata-privacy.md`, `src/invite.js`, `src/rendezvous/{race,tracker,dht}.js`, `src/key.js`, `DESIGN.md`. UNVERIFIED items in §8.*
