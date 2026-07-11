# p2p — file ownership map (SINGLE SOURCE OF TRUTH)

> 2026-07-11, set by main (Fable) after two orchestration paths (spike lanes + zenith
> build swarm) converged on the same files. This map is LAW. One writer per file. If a
> file you need isn't yours, STOP and message main — do not write it. Changing this map
> is main's call only.

## The shape

Two teams, disjoint by directory, working in parallel:

- **BUILDERS — the zenith swarm** (`zenith-lane` + `lane-*`, coordinated by `zenith-manager`).
  Own **all production `src/` code** + `package.json` + `README.md` fill. zenith-manager
  enforces single-writer-per-file AMONG its own workers.
- **GATE VALIDATORS — the spike lanes** (`spike-crypto`, `spike-transport`,
  `spike-rendezvous`, spawned by main). Own **`test/`** + the live-network gate proofs.
  They independently VALIDATE the builders' code — a stronger check than testing one's own.
- **SECURITY-CORE EXCEPTION:** `src/noise.js` + `test/vectors/` stay with `spike-crypto`
  (deepest context + the D5 assurance regime). Builders MUST NOT write `src/noise.js`.

## Ownership table

| Path | Owner | Notes |
|---|---|---|
| `src/noise.js` | **spike-crypto** | security core; builders never touch |
| `test/vectors/*`, `test/vectors/PROVENANCE.md` | **spike-crypto** | KAT vectors; re-verify after the 18:04 clobber |
| `test/noise.test.js`, `test/key.test.js` | **spike-crypto** | KAT + negative + gate |
| `src/key.js` | **zenith swarm** | builders |
| `src/wire.js` | **zenith swarm** | production version confirmed good by spike-transport |
| `src/transport.js` | **zenith swarm** | spike-transport HANDS OVER its STUN client + punch choreography to merge |
| `src/rendezvous/{bencode,dht,tracker,mdns,race}.js` | **zenith swarm** | spike-rendezvous hands over its working DHT client if stronger |
| `src/node.js`, `src/group.js`, `bin/p2p-chat.js` | **zenith swarm** | builders |
| `package.json`, `README.md` | **zenith swarm** | already committed by main; extend, don't recreate |
| `test/wire.test.js`, `test/stun.test.js`, `test/punch.test.js` | **spike-transport** | validate builders' transport+wire |
| `test/bencode.test.js`, `test/dht.test.js`, `test/tracker.test.js` | **spike-rendezvous** | validate builders' rendezvous + the live-DHT round-trip proof |
| `docs/*`, `DESIGN.md`, `research/*` | **main** | single-writer; workers read only |

## The P0 gates still gate everything (premortem kill-criteria)

Builders may write src/ in parallel NOW, but v1 is NOT "done" until the 3 gate proofs pass:
1. **Crypto gate** (spike-crypto): Noise IK passes official KAT vectors + negative suite fails closed + cross-impl interop (flynn/noise, CI-only).
2. **Transport gate** (spike-transport): real public STUN returns our address; ARQ delivers under loss/reorder; punch choreography 10/10.
3. **Rendezvous gate** (spike-rendezvous): live public Mainline DHT round-trip (A announces, B finds A) with a real measured success rate.

A GATE-FAIL reshapes the plan per `docs/PREMORTEM.md` — escalate to main, don't paper over.

## Handoffs in flight

- spike-transport → zenith-lane: STUN client + punch code, to merge into `src/transport.js`.
- spike-rendezvous → zenith swarm: working DHT client, if better than the swarm's.
- All handoffs go via message with the code inline; the RECEIVING owner integrates. The
  giver does not write the destination file.
