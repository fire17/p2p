# Redteam CAG Gate — 3540a56 (test/ real-egress sweep, #16 + 2 harnesses it caught)

> **Lane:** redteam / CAG-gate (opus @ xhigh). In-process only. Worktree @ 3540a56 (parent 7c26513).
> This is the readdir signature-sweep I recommended in the live-gate gate (#16) — and it caught exactly
> the whitelist-escape gap I flagged: 2 real ungated live harnesses. Rides the v0.3.3 batch.

## Verdict: **CONFIRMED-SHIP.** The sweep fires (my mutation + a 5-case self-test), zero false positives,
both harnesses gated + default-skipped, both audit layers kept. One documented residual noted.

## The closed loop
In the 170bc0b live-gate gate I flagged that the AUDIT was a hardcoded whitelist — it caught
gate-REMOVAL from a known test but a NEW ungated file escaped. #16 built the sweep, and it caught two
real files: `browser-tui-e2e.mjs:53` and `browser-group-tui.mjs:53` both do `wss.createEndpoint({S})`
on the REAL global WebSocket + default RELAYS with NO gate. They only LOOKED safe because playwright is
absent on this box (so the earlier "0 off-box connections" proof held BY LUCK); install playwright and
`node --test` would dial `broker.emqx.io` every run. Both now carry `skipLiveScript()`.

## Angle 1 — does the sweep FIRE? (my own mutation + the self-test)
- **The built-in self-test** (`AUDIT (sweep): the sweep BITES`) writes 5 throwaway files to a TEMP dir
  (hardcoded-host / uninjected-`createMdns` / gated-with-`liveOnly` / injected-seam-`createTracker` /
  a comment merely naming a host) and asserts `auditLiveTests(dir)` flags EXACTLY the first two —
  proving it bites on real egress AND ignores the gated/injected/documented cases. A real synthetic,
  not a strawman.
- **My own mutation on a REAL file:** removing BOTH the `skipLiveScript` import and its call from
  `browser-tui-e2e.mjs` → the real-tree sweep went **RED**: *"browser-tui-e2e.mjs — reaches the real
  public WSS relay with no injected seam and no live gate."* Restored → green. So the sweep has a
  genuine WSS-endpoint signature and names the offending file + reason. ✓

## Angle 2 — false-positive discipline (0 FP on 60 files)
The sweep imports the host lists FROM src (`RELAYS/TRACKERS/BOOTSTRAP/STUN_SERVERS`), so it self-updates
and a mere `import { RELAYS }` (data, opens no socket) is NOT a signature — only a literal hostname is.
Factory calls are flagged only WITHOUT their injection seam, and `INJECTS_WS = /WebSocket\s*[:,}]/`
accepts the ES6 shorthand (`createTracker({ trackers, WebSocket, codec })` — how the leak-monitor
injects a FakeWS — is exempt). The comment-stripper is STRING-AWARE (it must not eat the `//` in
`wss://`). The self-test's injected + documented files are NOT flagged, and the real-tree sweep is GREEN
(0 findings after both harnesses were gated). Spot-checked: the leak-monitor / mdns injected-seam tests
pass clean. ✓

## Angle 3 — the 2 harnesses are default-skipped but manually runnable
Both carry `if (skipLiveScript('…')) process.exit(0)` at the top (line 28/30). `skipLiveScript` returns
true only under the auto-runner (`NODE_TEST_CONTEXT` set), so `node --test` skips them while a direct
`node test/browser-tui-e2e.mjs` still runs — the owner's manual workflow intact. ✓

## Angle 4 — both audit layers kept (approved)
`live-gate.test.js` runs BOTH the whitelist (`AUDIT: every real-network test/harness still carries the
live gate` — catches gate-REMOVAL from a KNOWN test) and the sweep (`AUDIT (sweep): no file under test/
reaches the real network without the gate` — catches a NEW ungated file). Neither subsumes the other;
keeping both (≈9 lines) is the right call. ✓

## Honest residual (documented in-code; I concur) — the per-FILE token exemption
`GATED = /liveOnly|skipLiveScript|P2P_LIVE/` exempts a file if the token appears ANYWHERE in it. So a
file that IMPORTS `skipLiveScript` but gates only ONE of two egress paths — or imports it without
calling it — is exempted wholesale, and a second ungated egress in that file escapes the sweep (a false
negative). I demonstrated the boundary: my FIRST mutation removed only the call and left the import, and
the sweep still passed (the token was still present). This is stated in live-audit.mjs ("The exemption
is per FILE, not per test … a known limit") and is precisely why the whitelist is kept alongside. Not a
defect — a documented limitation with a rationale. Closing it fully would need per-test (block-scoped)
gate detection; **recommend a low-priority ticket** if per-file granularity ever proves insufficient.

## Standing-resident
3540a56 CONFIRMED-SHIP — the whitelist-escape gap I opened in the live-gate gate is now closed by the
sweep, and it caught 2 real ungated harnesses in the process. Resident.
