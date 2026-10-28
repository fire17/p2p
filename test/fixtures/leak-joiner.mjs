// test/fixtures/leak-joiner.mjs — the JOINER side of test/tunnel-socket-leak.test.js, run as its own
// process (under node AND bun) so its file descriptors can be counted from outside with lsof.
//
// Stands up the real src/transport-wss.js endpoint (listener inbox + a fresh dial every second, the
// shape of a `tunnel join` daemon) against the relay URLs in LEAK_RELAYS, wraps the WebSocket ctor to
// count every socket constructed / not yet closed, and prints one JSON line per sample on stdout.
// Works against the PRE-FIX module too (relayStats is optional) — that is what the sabotage run uses.
import * as wss from '../../src/transport-wss.js'
import { readdirSync } from 'node:fs'
import { generateIdentity } from '../../src/key.js'

if (!process.env.LEAK_RELAYS) process.exit(0)        // picked up bare by `node --test`: nothing to do
const relays = process.env.LEAK_RELAYS.split(',')
let made = 0, open = 0
class CountingWS extends globalThis.WebSocket {
  constructor(...a) {
    super(...a); made++; open++
    let counted = true
    this.addEventListener('close', () => { if (counted) { counted = false; open-- } })
  }
}
const ep = wss.createEndpoint({ S: generateIdentity().S, relays, WebSocket: CountingWS,
  backoffMinMs: 200, backoffMaxMs: 1000, connectTimeoutMs: 1500 })
ep.onConnection(() => {})
const dial = setInterval(() => {
  ep.punch([{ proto: 'wss', topic: 'p2p1/nobody-' + Math.random().toString(16).slice(2) }])
    .then((s) => setTimeout(() => s.close(), 700)).catch(() => {})
}, 1000)
const sample = setInterval(() => {
  let fds = -1; try { fds = readdirSync('/dev/fd').length } catch { /* */ }
  const handles = (process.getActiveResourcesInfo?.() || []).filter((n) => /TCP/.test(n)).length
  const rs = wss.relayStats?.() || null
  process.stdout.write(JSON.stringify({ t: Date.now(), made, open, fds, handles, relay: rs }) + '\n')
}, 250)
process.stdin.on('data', () => {})
process.stdin.on('end', () => { clearInterval(dial); clearInterval(sample); ep.close(); setTimeout(() => process.exit(0), 300) })
