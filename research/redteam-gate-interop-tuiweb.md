# Redteam CAG Gate — 346be58 (tui↔web interop + glare commit-to-winner)

> **Lane:** redteam / CAG-gate (opus @ xhigh). Analysis + verification only.
> **Date:** 2026-07-12. **Isolation:** clean detached worktree @ 346be58 (parent 9a19b55).
> **Constraint honored:** in-process (mock MQTT broker) + loopback UDP only — no mDNS/LAN/live-infra.
> **Scope:** gated for what it DELIVERS (tui↔web + glare hardening). It does NOT claim to fix web↔web
> (the lane falsified that mechanism separately) — not gated as one.

## Verdict: **CONFIRMED-SHIP.** No DEVIATION; the security keystone (invite relay-exclusion) holds.

## What it does (7 files)
- `src/transport-node.js` (new): the node-side composite — UDP/ICE + the WSS relay behind node.js's
  endpoint seam. Now the DEFAULT endpoint `listen()` builds when no `opts.endpoint` (the TUI path).
- `src/compose.js` (new): ONE shared raced-composite (`composePunch`), used by both the browser and
  node composites; adds COMMIT-TO-WINNER / close-every-loser. `src/browser/transport.js` re-exports it.
- `src/node.js`: default endpoint = transport-node.js; passes peer S to `punch()` so a browser (zero
  UDP candidates) is dialable.

## My own test output
```
interop-tui-web.test.js + transport-glare.test.js + browser-raced-transport.test.js
  + transport-wss-dos.test.js                                       → 17/17 pass
node.test.js + invite-mode.test.js + burn.test.js + transport.test.js
  + race.test.js + dos-meta-harden.test.js (node-path regression)   → 52/52 pass
```
The default-endpoint swap (every node dial now runs through transport-node.js) did NOT regress invite
mode, burn, DOS-1/META-1, or the ARQ/handshake — 52/52. The browser composite is unchanged by the
compose.js refactor (browser-raced-transport green). DOS-1-WSS guards still green under the composed use.

## Gate angles

**(d) SECURITY-CRITICAL — invite mode is genuinely relay-excluded.** Verified at source AND by probe:
- Listener: `listen()` builds `createEndpoint({ …, wss: opts.wss !== false && !invite })` — when
  `invite` is truthy, `wss` is `false`, and `transport-node.js createEndpoint` returns the PLAIN UDP
  endpoint (`if (!wss || !S) return udp`) — no `createWssEndpoint`, so NOTHING subscribes the
  S-derived relay topic. My probe: `createEndpoint({S, wss:false}).wss === undefined` (no relay leg),
  vs `createEndpoint({S, wss:true}).wss` present. The META-1 UDP probe gate (`probeAuth`) is still
  installed on the invite endpoint.
- Dialer: `initiatorHandshake` passes `S: inv ? undefined : S` to `punch`; with `popts.S` undefined
  the composite synthesizes NO relay candidate (`if (!wssCands.length && popts.S)` is skipped), and
  the invite rendezvous produces no `wss`-proto candidates — so an invite DIAL has no relay leg either.
- Result: subscribing the reusable-S relay topic in invite mode would answer any S-holder and re-open
  the META-1 pubkey-harvest oracle OUTSIDE the probe gate and burn's go-dark — and it CANNOT happen:
  no invite endpoint ever stands up the relay. No accidental invite-over-relay path exists. ✓

**(a) node-side WSS default — no new pre-auth DOS surface.** The relay leg is `createWssEndpoint` from
`src/transport-wss.js` — the SAME transport already carrying the DOS-1-WSS guards (MAX_ACCEPTED cap,
token-bucket accept rate, idle-evict) gated in 6cd0c3c. The composite only adds an onConnection fan
(udp+wss) — each sub-transport enforces its own caps; a raced dial mints at most one udp + one wss
accept on the listener, both bounded/idle-swept, and node.js keys the peer by static pubkey so they
converge to ONE record (interop test asserts "one peer record each" over 10 raced dials).
transport-wss-dos.test.js green. No unbounded allocation introduced. ✓

**(b) src/compose.js shared — browser composite identical post-refactor.** `browser/transport.js`
re-exports `composePunch` from compose.js (the logic is the same race-to-first-frame + BRW-1 lock +
commit). `browser-raced-transport.test.js` is green — the browser composite behaves identically. ✓

**(c) commit-to-winner close-loser — cannot tear down the winning session.** `commit(winner)` closes
every sub `s !== winner` (the winner is explicitly excluded — never closed); a leg that comes up AFTER
`outbound` is set is closed on arrival and never wired in; only the FIRST well-formed frame commits
(`!outbound && decodeFrame(buf)` — BRW-1 preserved, a runt can't win the lock); the legs are
independent transports (a UDP socket vs a WSS socket) with no shared cipher/connId state, so closing a
loser touches nothing the winner needs. No merge of Noise states. transport-glare.test.js: 10/10, one
session per peer. ✓

## CAG §6
1. **Residual-closed:** tui↔web could not connect AT ALL (no shared transport); now the node composes
   the relay floor a browser can also speak — VERIFIED (interop test both directions; lane's live
   werift↔TUI over broker.emqx.io 3/3, cited). Glare waste (N half-open responders per raced dial)
   collapsed to one session.
2. **Attack-surface:** new parts = the composite (delegates every seam to UDP; only onConnection/punch
   composite), the relay leg (DOS-1-WSS-guarded), the S-in-punch. Each enumerated; invite mode excluded.
3. **Weakest-link:** unchanged — the relay is an untrusted floor (already the browser's floor); Noise
   IK/commitment remains the boundary; UDP keeps priority (700ms head start + first-real-frame lock),
   so a TUI pair never silently bounces off a public broker (test asserts relay.published===0 tui↔tui).
4. **Reliability:** UDP-first preserved; relay is a strictly-additive fallback; 52/52 node-path green.
5. **Degenerate-safe:** no WebSocket (Node<22) or `wss:false`/invite ⇒ plain UDP endpoint,
   byte-identical to v0.1.0.
6. **Monitor:** interop-tui-web + transport-glare tests are the standing assertions.
7. **Reversible:** `listen({wss:false})` restores the old endpoint; browser path (`opts.endpoint`)
   untouched (no double-WSS).
8. **Simplicity:** ONE shared composite (removed the duplicate); minimal 2-line touch of browser/
   transport.js (its suite green).

## Honest GAP (lane-flagged, I concur — UNVERIFIED, not run)
Real Chromium↔Chromium not exercised here; and per the owner-live-testing constraint I did NOT run the
live browser/relay paths (`browser-group-ui.mjs` / live-relay interop). The lane's live werift↔TUI proof
over `broker.emqx.io` (3/3 each way, 1.36s) is cited as its evidence; a real two-browser + real-relay
pass is the recommended post-bump confirmation. This is an interop-delivery gate, not a web↔web fix —
web↔web 50% remains open (tasks #7/#8), correctly out of scope here.

## Standing-resident
346be58 clear to ship (tui↔web + glare hardening). With the checksum re-gate (9a19b55), the dev.4 bundle
is gated. Resident.
