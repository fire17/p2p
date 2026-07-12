# Redteam CAG Gate (PROD) — d47a878 (boot guard + deploy-graph gate)

> **Lane:** redteam / CAG-gate (opus @ xhigh). PROD-FACING (resolves a live `/app/boot-guard.js` 404).
> Worktree @ d47a878 (parent 0a9820f). In-process only. Files: app/boot-guard.js (new),
> test/browser-deploy.test.js (new).

## Verdict: **CONFIRMED-SHIP.** Shipping the referenced file resolves the 404 + lands the safety net
that would have caught the Jekyll bug. Both deploy tripwires BITE (my own mutations).

## Angle 1 — CSP covers boot-guard.js with no importmap-hash change
`<script src="/app/boot-guard.js">` is a CLASSIC same-origin EXTERNAL script. CSP `script-src 'self'
'sha256-…'` — the `'sha256-…'` is the hash of the INLINE `<script type="importmap">` (inline scripts
need a hash; external same-origin scripts are covered by `'self'`). So boot-guard.js loads under `'self'`
and the importmap hash is untouched. The deploy test recomputes and asserts that hash separately (angle 3).
✓ Reasoning verified.

## Angle 2 — never interferes with a healthy boot
`booted()` = `window.__p2pBooted || !statusEl() || statusText !== 'booting…'`. Every `show()` re-checks
`if (booted()) return`, so it NEVER writes over a live app. It fires exactly once (a single
`setTimeout(…, 8000)`), so no double-write. A healthy boot moves off "booting…" sub-second (app.js writes
'going online…' the moment it lives), so the 8 s watchdog only trips a genuinely stuck/dead graph; a
slow-but-healthy boot that trips it gets a SOFT diagnostic that the app overwrites when it comes up
(self-correcting). It imports NOTHING (a bad import is the failure it exists to catch — the deploy test
asserts `!/^\s*import\s/m`). It cannot break the module graph (a classic script that only reads/writes the
status DOM + registers error listeners). ✓

## Angle 3 — the deploy gate FIRES (the whole point; my own mutations)
`test/browser-deploy.test.js` (3 tests) walks the REAL module graph from `app/index.html` (import map +
relative imports) via `fs.readFileSync`, and asserts: every file resolves + bare specifiers are mapped;
any `_`-prefixed file in the graph ⇒ `.nojekyll` must exist; boot-guard.js is referenced, exists, loads
BEFORE the module entry, imports nothing; and the CSP hash still equals the recomputed importmap hash.
**My mutations proved both tripwires bite:**
```
delete .nojekyll → "SERVABLE by GitHub Pages" test → RED, naming all 4:
   src/browser/vendor/hashes/_md.js, _u64.js, ciphers/_arx.js, _poly1305.js — ".nojekyll … is required, and is missing"
tamper the importmap (node:crypto→node:crypt0) → "boot guard wired + CSP hash" test → RED:
   "CSP script-src is missing the import map's hash (sha256-…) — recompute it"
```
The first is EXACTLY the failure that took the live site down while 308 unit tests passed — this gate
catches it. ✓ Intact suite: **3/3 pass.**

## CAG §6
1. Closes a live dangling 404 + the CLASS of "module graph dies, page lies 'booting…'" (boot guard) and
   "deploy drops a file / breaks CSP, unit tests still green" (deploy gate). 2. New parts: one classic
   guard script + a static graph-walk test — enumerated, no runtime/network surface. 3. Not weaker.
   4. Reliability: guard is a pure overlay; healthy boot unaffected. 5. Degenerate-safe (guard no-ops if
   the app is alive). 6. browser-deploy.test.js IS the monitor — bites (proven). 7. Reversible. 8. Minimal.

## Standing-resident
d47a878 CONFIRMED-SHIP — clear for the v0.3.2 push (resolves the 404 + ships the deploy safety net). Resident.
