# Prepared brief for Zenith — p2p v1 build

## Objective
Implement `p2p` v1 exactly per `/Users/magic/Creations/p2p/DESIGN.md` (the D-table is
law; divergence = stop + escalate, per `docs/PREMORTEM.md`): a zero-dependency Node ≥22
ESM library + demo CLI where two processes exchange 26-char keys' first contact
(fetch→gate→Noise IK), then chat E2E-encrypted over the raced transport ladder.

## Context (read in this order)
1. `DESIGN.md` — decisions, protocol, module map, phases
2. `docs/PREMORTEM.md` — failure oracle, kill criteria, divergence rule
3. `research/crypto-firstcontact.md` §9–11 — handshake + key format, exact
4. `research/transport-nat.md` — ladder, STUN, keepalive numbers
5. `research/rendezvous.md` — channel specifics, bootstrap lists, live-probe log
6. `docs/API-SKETCH.md` — public API budget

## Deliverables
- P0 spikes FIRST (gate everything): (a) STUN+UDP punch spike, (b) public Mainline DHT
  announce/get_peers round-trip spike, (c) Noise IK vs official test vectors spike.
- `src/` modules per DESIGN §4 within LOC budget ±30%; `bin/p2p-chat.js` demo CLI.
- Test suite: unit (key encode/decode/checksum, noise vectors, wire ARQ under loss/reorder,
  bencode), integration (two local processes full first-contact + chat), live (real DHT +
  tracker announce), all runnable via `node --test` (zero test deps).
- README.md with quickstart (generate key on machine A, connect from machine B).

## Acceptance (all must hold, observed not claimed)
1. `node --test` green including Noise official vectors.
2. Two fresh processes on one machine: full protocol over loopback+mDNS — first ack
   proves gate+IK ran (log the commitment check + key confirmation) — 10/10 runs.
3. Two processes on DIFFERENT networks connect via public rendezvous + punch (or
   documented fallback rung) and chat realtime.
4. Wrong/typoed key: fails locally at checksum, zero network. Tampered pubkey in HELLO:
   gate drops it, logged.
5. Kill one side mid-chat, restart: reconnect + buffered resend works.
6. `du`-style honesty: total src LOC reported; zero entries in `package.json` deps.

## Guardrails
- NEVER invent crypto; implement exactly the cited specs; Noise vectors are the oracle.
- Zero npm deps anywhere (dev deps included). Node built-ins only.
- Tests: throwaway resources only; never touch other sessions' processes.
- Public infra: gentle rates (announce intervals per research/rendezvous.md), no floods.
- All workers report first line `MODEL: <id>`; opus or below, NEVER fable.
- Divergence rule: DESIGN/oracle contradicted by reality → STOP, write
  `docs/DIVERGENCES.md`, escalate. No improvising past a broken map.
