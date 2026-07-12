// scratch/leak-canary.mjs — the OPT-IN LIVE-WIRE leak canary (§7 leg 2).
//
// ⚠ HITS LIVE INFRA (public WSS trackers + the mainline DHT). It is DELIBERATELY NOT in the default
// test suite. Run it by hand when you want to confirm a REAL surface leaks nothing the CI mocks might
// not model:
//
//   node scratch/leak-canary.mjs                 # both surfaces
//   P2P_CANARY=dht node scratch/leak-canary.mjs  # dht only   (tracker | dht | both; default both)
//   P2P_CANARY_TIMEOUT_MS=12000 node scratch/leak-canary.mjs
//
// It mints a REAL one-time invite, seals a REAL candidate set, publishes it, and captures the ACTUAL
// bytes that leave this process (tracker: every SDP the client sends; DHT: every BEP44 value put),
// then runs the SAME assertNoLeak() battery the CI monitor uses. A surface it can't reach → SKIP
// (offline), never a false FAIL. Exit non-zero only on a real leak.

import { createTracker, TRACKERS } from '../src/rendezvous/tracker.js'
import { createDht, DHT } from '../src/rendezvous/dht.js'
import { createInvite, generateInviteSecret } from '../src/invite.js'
import { Observer, assertNoLeak, CAND_SETS } from '../test/observer.js'

const WHICH = (process.env.P2P_CANARY || 'both').toLowerCase()
const TIMEOUT = Number(process.env.P2P_CANARY_TIMEOUT_MS || 8000)
const EPOCH = new Date().toISOString().slice(0, 10)
const CANDS = CAND_SETS.ipv4                                    // a realistic, greppable candidate set
const withTimeout = (p, ms, tag) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`${tag} timed out after ${ms}ms`)), ms).unref?.())])

let failed = 0
const report = (surface, status, detail = '') => {
  const icon = { PASS: '🟢', FAIL: '🔴', SKIP: '⚪' }[status]
  console.log(`${icon} ${surface.padEnd(8)} ${status}${detail ? ' — ' + detail : ''}`)
  if (status === 'FAIL') failed++
}

// ── tracker: capture every SDP this client actually sends to the real relay ────────────────────────
async function tracker() {
  const inv = createInvite(generateInviteSecret())
  const rid = inv.rid('tracker', EPOCH, 20)
  const observer = new Observer('tracker-live')
  class CapWS extends WebSocket {
    send(data) {
      observer.text(data)
      for (const m of String(data).matchAll(/a=[a-z]{8}:([A-Za-z0-9+/=]+)/g)) { try { observer.bytes(Buffer.from(m[1], 'base64')) } catch { /* not our blob */ } }
      super.send(data)
    }
  }
  const alice = createTracker({ trackers: TRACKERS, WebSocket: CapWS, codec: inv.codec })
  alice.announce(rid, { candidates: CANDS })
  // give the client time to connect + emit the announce offer(s) to the real relays
  await withTimeout(new Promise((res) => {
    const iv = setInterval(() => { if (observer.sealed().length) { clearInterval(iv); res() } }, 100)
  }), TIMEOUT, 'tracker announce')
  alice.close()
  assertNoLeak(observer, CANDS)
  report('tracker', 'PASS', `${observer.sealed().length} sealed SDP blob(s) captured, all clean & ${observer.sealed()[0].length}B`)
}

// ── dht: capture the real BEP44 value put on the mainline DHT ───────────────────────────────────────
async function dht() {
  const inv = createInvite(generateInviteSecret())
  const rid = inv.rid('dht', EPOCH, 20)
  const observer = new Observer('dht-live')
  const real = new DHT()
  const rec = {                                                // record every put value, delegate the rest
    bep44Put: (it) => { observer.bytes(it.v); return real.bep44Put(it) },
    bep44Get: (t) => real.bep44Get(t),
    getPeers: (...a) => real.getPeers(...a),
    close: () => real.close(),
  }
  const ch = createDht({ dht: rec, invite: inv })
  ch.announce(rid, { candidates: CANDS })
  await withTimeout(new Promise((res) => {
    const iv = setInterval(() => { if (observer.sealed().length) { clearInterval(iv); res() } }, 100)
  }), TIMEOUT, 'dht announce')
  ch.close()
  assertNoLeak(observer, CANDS)
  report('dht', 'PASS', `BEP44 value captured, clean & ${observer.sealed()[0].length}B`)
}

console.log(`leak-canary — LIVE wire (${WHICH}), epoch ${EPOCH}, timeout ${TIMEOUT}ms\n`)
for (const [name, fn] of [['tracker', tracker], ['dht', dht]]) {
  if (WHICH !== 'both' && WHICH !== name) continue
  try { await fn() }
  catch (e) {
    // a leak assertion carries "leaked on the wire"; anything else is unreachable-infra → SKIP.
    if (/leaked on the wire|not the fixed|blob structure|attribute tell/.test(e.message)) report(name, 'FAIL', e.message)
    else report(name, 'SKIP', e.message)
  }
}
console.log(failed ? `\n${failed} surface(s) LEAKED. 🔴` : '\nNo leaks on any reached surface. 🟢')
process.exit(failed ? 1 : 0)
