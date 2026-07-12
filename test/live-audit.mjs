// test/live-audit.mjs — the STANDING sweep: no test may reach the real network without the gate.
//
// The audit this replaces was a hardcoded whitelist of the 7 files known to be live. A whitelist can
// only catch a gate being REMOVED from a file someone already thought about; it is blind to the
// failure that actually matters — someone ADDING a new test or harness that touches the wire and
// nobody noticing until it multicasts across the owner's LAN mid-session. `node --test` executes
// EVERY .js/.mjs under test/, so a new harness is auto-run the moment it lands.
//
// So the sweep is inverted: read every file under test/, look for evidence of REAL egress, and fail
// unless that file carries the gate. New file, new author, no ceremony — it fails automatically.
//
// WHAT COUNTS AS EVIDENCE (two classes, because they fail differently):
//
//  1. A REAL PUBLIC HOST, as a literal. The host lists are IMPORTED from src, not copied here, so
//     adding a relay/tracker/bootstrap/STUN server to src automatically widens the sweep. A file that
//     merely imports the RELAYS constant is NOT flagged (that is data — createWssRendezvous, for one,
//     is pure computation and opens no socket); only a hardcoded hostname is.
//
//  2. A REAL-NETWORK FACTORY CALLED WITHOUT ITS INJECTION SEAM. Every network module in src takes a
//     seam precisely so tests can drive it with a fake (createMdns ← socketFactory, createTracker ←
//     WebSocket, createDht ← dht, the WSS endpoint ← WebSocket). Calling one WITHOUT its seam means
//     the real thing: real multicast, real brokers, real DHT. Same for STUN — stunAny()/ep.stun() hit
//     the public servers and have no seam at all — and for a bare `listen(id)`, which stands up the
//     entire default rendezvous stack (mDNS + DHT + trackers) on the LAN and the internet.
//
// A file is EXEMPT when it carries the gate (liveOnly / skipLiveScript / P2P_LIVE) — the audit is
// "gated or inert", never "inert only". The exemption is per FILE, not per test: a file that gates
// one live test and leaves another ungated passes the sweep. That is a known limit, and it is why
// live-gate.test.js ALSO keeps its anchored per-test assertions. The two catch different mistakes and
// neither subsumes the other.
//
// ESCAPE HATCH, deliberately narrow: `live-audit: safe — <reason>` anywhere in the file waives it.
// A waiver must say why. It exists so a legitimate pattern the regexes cannot see does not tempt
// anyone into deleting the sweep — the standing failure mode of every tripwire.

import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { RELAYS } from '../src/transport-wss.js'
import { TRACKERS } from '../src/rendezvous/tracker.js'
import { BOOTSTRAP } from '../src/rendezvous/dht.js'
import { STUN_SERVERS } from '../src/transport.js'

/** 'wss://broker.emqx.io:8084/mqtt' -> 'broker.emqx.io' */
const hostOf = (u) => String(u).replace(/^\w+:\/\//, '').split('/')[0].split(':')[0]

/** Every real host this codebase knows how to talk to — derived from src, so it self-updates. */
export const PUBLIC_HOSTS = [
  ...RELAYS.map(hostOf),
  ...TRACKERS.map(hostOf),
  ...BOOTSTRAP.map((b) => b.host),
  ...STUN_SERVERS.map((s) => s.host),
]

/** The mDNS multicast group. Not exported by src/rendezvous/mdns.js, so it is asserted there too. */
export const MCAST_ADDR = '224.0.0.251'

/** The gate, in either of its two shapes (test option object / harness early-exit). */
const GATED = /liveOnly|skipLiveScript|P2P_LIVE/
const WAIVED = /live-audit:\s*safe\s*[—-]\s*\S/

/**
 * Calling one of these WITHOUT its seam means the real network. `needs` is the injection point src
 * exposes for exactly this purpose; `null` means the call has no seam and is live by definition.
 */
// `needs` accepts the ES6 SHORTHAND too — `createTracker({ trackers, WebSocket, codec })` is how the
// leak-monitor injects its FakeWS, and a seam regex that only knew `WebSocket:` called it live.
const INJECTS_WS = /WebSocket\s*[:,}]/

const FACTORIES = [
  { what: 'real LAN multicast (mDNS)', call: /createMdns\s*\(/, needs: /socketFactory\s*[:,}]/ },
  { what: 'real public WSS trackers', call: /createTracker\s*\(/, needs: INJECTS_WS },
  { what: 'real Mainline DHT', call: /createDht\s*\(/, needs: /\bdht\s*[:,}]/ },
  {
    what: 'real public STUN servers',
    call: /stunAny\s*\(|\.stun\s*\(/,
    // An explicit ARRAY of servers is a hand-written (loopback) list — that is the seam. Passing the
    // real constant (`servers: STUN_SERVERS`) is NOT: it names an identifier, not hosts, so it trips.
    needs: /servers\s*:\s*\[/,
  },
  {
    what: 'the real public WSS relay',
    call: /(?:createEndpoint|wssEndpoint|createWssEndpoint)\s*\(/,
    needs: INJECTS_WS,
    // Only when the WSS/composite endpoint is in play: src/transport.js's createEndpoint is UDP and
    // binds locally, which is not traffic (a loopback bind emits nothing off-box).
    when: /from\s+'[^']*transport-(?:wss|node)\.js'/,
  },
  {
    what: 'the real default rendezvous stack (mDNS + DHT + trackers)',
    // `listen(id)` with no opts: no deps, no endpoint, no injection — the real thing, on the LAN.
    call: /\blisten\s*\(\s*[A-Za-z_$][\w$.]*\s*\)/,
    needs: null,
    when: /from\s+'[^']*\/node\.js'/,
  },
]

/**
 * Strip comments, keeping string literals intact — the sweep must read CODE, not prose. Without this
 * a file that merely DOCUMENTS a live path ("the CLI's `listen(id)`", "we never dial broker.emqx.io")
 * is flagged, and a tripwire that cries wolf gets deleted. String-aware on purpose: a naive
 * comment-stripper eats the '//' inside 'wss://…' and blinds the sweep to the very hosts it hunts.
 * @param {string} s @returns {string} the same source with every comment blanked out
 */
export function code(s) {
  let out = ''
  let i = 0
  let quote = null                                   // ' " ` when inside a string
  while (i < s.length) {
    const c = s[i], d = s[i + 1]
    if (quote) {
      if (c === '\\') { out += c + (d ?? ''); i += 2; continue }
      if (c === quote) quote = null
      out += c; i++; continue
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; out += c; i++; continue }
    if (c === '/' && d === '/') { while (i < s.length && s[i] !== '\n') i++; continue }
    if (c === '/' && d === '*') { i += 2; while (i < s.length && !(s[i] === '*' && s[i + 1] === '/')) i++; i += 2; continue }
    out += c; i++
  }
  return out
}

/** Every .js/.mjs under test/ — the exact set `node --test` will execute. */
export function testFiles(root) {
  return readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile() && /\.(js|mjs)$/.test(d.name))
    .map((d) => relative(root, join(d.parentPath || d.path, d.name)))
    .sort()
}

/**
 * @param {string} root  the test/ directory
 * @param {string[]} [skip]  files the sweep must not audit (the auditor itself: it names the hosts)
 * @returns {{file:string, why:string}[]} one finding per ungated real-network signature
 */
export function auditLiveTests(root, skip = []) {
  const findings = []
  for (const file of testFiles(root)) {
    if (skip.includes(file)) continue
    const raw = readFileSync(join(root, file), 'utf8')
    const src = code(raw)                                  // signatures are read from CODE, never prose
    if (WAIVED.test(raw)) continue                         // the waiver IS a comment — read it from raw
    if (GATED.test(src)) continue                          // ...but a COMMENT must never gate a file

    for (const host of PUBLIC_HOSTS) {
      if (src.includes(host)) findings.push({ file, why: `hardcodes the real host ${host}` })
    }
    if (src.includes(MCAST_ADDR)) findings.push({ file, why: `hardcodes the mDNS multicast group ${MCAST_ADDR}` })

    for (const f of FACTORIES) {
      if (f.when && !f.when.test(src)) continue
      if (!f.call.test(src)) continue
      if (f.needs && f.needs.test(src)) continue          // driven by an injected fake — inert
      findings.push({ file, why: `reaches ${f.what} with no injected seam and no live gate` })
    }
  }
  return findings
}

export default { auditLiveTests, testFiles, PUBLIC_HOSTS, MCAST_ADDR }
