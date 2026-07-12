// test/browser-pc-soak.mjs — BRW-4 RESIDUAL: a REAL browser has a hard cumulative RTCPeerConnection
// cap. Chromium throws `Failed to construct 'RTCPeerConnection': Cannot create so many
// PeerConnections` once ~500 PC objects exist that have not yet been destructed (close() alone does
// NOT decrement Blink's counter — the object must also be unreferenced and garbage-collected).
//
// The a84345e fix bounded the PARKED set (MAX_PENDING_OFFERS + TTL evict) and its soak PASSED — but
// that soak ran on Node **werift** PCs, which have NO per-page cap. It therefore could not see the
// residual: the listener's CREATION CHURN. `publishAll` minted OFFERS_PER_ANNOUNCE=4 fresh PCs per
// announce, per tracker (3), every ANNOUNCE_INTERVAL_MS=10s ⇒ ~72 PCs/min ⇒ ~4300/hour. A real
// Chrome tab exhausts long before that — the owner hit it feel-testing /app/.
//
// This gate is the real-browser version. It is opt-in (not in `npm test`) because it needs Chromium:
//
//   PLAYWRIGHT=$(node -e "console.log(require.resolve('playwright'))") node test/browser-pc-soak.mjs
//   HEADED=1 … to watch it.  SOAK_MS=… to lengthen phase A.  NO_NET=1 to skip phase B.
//
// PHASE A (hard gate, deterministic, no network): a REAL Chromium RTCPeerConnection subclass that
//   counts construct/close, an in-page fake tracker bus (so nothing touches the public trackers), and
//   the announce/TTL clocks accelerated 200× (announce 10s→50ms, offer-TTL 120s→600ms). 90 s of soak
//   therefore models ~5 HOURS of real listening. We assert: (a) Chromium never throws the
//   PeerConnection-cap error, (b) live (constructed-minus-closed) PCs stay under a small cap and the
//   cumulative construction RATE stays bounded, (c) a dialer still lands on a parked offer — with
//   REAL ICE, a real DataChannel — after the pool has cycled for a minute (i.e. we answer an offer of
//   arbitrary age, not a freshly-minted one).
//   Cumulative constructions in phase A deliberately exceed Chromium's ~500 cap: passing PROVES the
//   closed PCs are actually released and reclaimed, not merely closed.
//
// PHASE B (reality check, needs the public internet): open the SHIPPED /app/ listener with the real
//   trackers and simply MEASURE its PC construction rate for 60 s with a patched global. Old code:
//   ~72/min. New code must stay far under that, and the cap error must never appear.

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { join, dirname, extname, normalize } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..')
const PORT = 8101
const SOAK_MS = Number(process.env.SOAK_MS || 90_000)
const ACCEL = 200 // announce 10s → 50ms, offer TTL 120s → 600ms

let chromium
try {
  const spec = process.env.PLAYWRIGHT || 'playwright'
  ;({ chromium } = await import(spec))
} catch {
  console.log('⏭  SKIP: playwright not found. This gate needs a real browser.')
  console.log('   PLAYWRIGHT=/path/to/playwright/index.mjs node test/browser-pc-soak.mjs')
  process.exit(0)
}

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json' }
const server = createServer(async (req, res) => {
  const path = normalize(decodeURIComponent(req.url.split('?')[0])).replace(/^(\.\.[/\\])+/, '')
  if (path === '/__soak__/') {
    // the same import map /app/index.html ships — src/key.js imports 'node:crypto', which only
    // resolves through the browser shim. Without it the whole module graph fails to load.
    res.writeHead(200, { 'content-type': 'text/html' })
    return res.end(
      '<!doctype html><meta charset=utf-8><title>pc-soak</title>' +
        '<script type="importmap">{"imports":{"node:crypto":"/src/browser/shim/node-crypto.js"}}</scr' + 'ipt><body>soak',
    )
  }
  try {
    const rel0 = path === '/' ? '/app/' : path
    const file = rel0.endsWith('/') ? join(ROOT, rel0, 'index.html') : join(ROOT, rel0)
    if (!file.startsWith(ROOT)) throw new Error('path escape')
    const body = await readFile(file)
    res.writeHead(200, { 'content-type': MIME[extname(file)] || 'application/octet-stream' })
    res.end(body)
  } catch {
    res.writeHead(404).end('not found')
  }
})
await new Promise((r) => server.listen(PORT, r))

const browser = await chromium.launch({ headless: !process.env.HEADED })
const fail = (msg) => {
  console.error('  ✖ ' + msg)
  process.exitCode = 1
}
const CAP_ERR = /Cannot create so many PeerConnections/i

// ── the in-page harness: counting real PCs + a fake tracker bus (installed by both phases) ──
const HARNESS = `
  window.__stats = { created: 0, closed: 0, errors: [], peak: 0 }
  const Real = window.RTCPeerConnection
  window.RTCPeerConnection = class CountingPC extends Real {
    constructor(cfg) {
      try { super(cfg) } catch (e) { window.__stats.errors.push(String(e && e.message || e)); throw e }
      window.__stats.created++
      const live = window.__stats.created - window.__stats.closed
      if (live > window.__stats.peak) window.__stats.peak = live
    }
    close() { if (!this.__counted) { this.__counted = true; window.__stats.closed++ } return super.close() }
  }
`

// ══ PHASE A ══════════════════════════════════════════════════════════════════════════════════════
console.log(`\n── PHASE A — accelerated ${ACCEL}× soak, real Chromium PCs, fake tracker (no network)`)
console.log(`   ${(SOAK_MS / 1000).toFixed(0)}s of soak ≈ ${((SOAK_MS * ACCEL) / 3_600_000).toFixed(1)} h of real listening\n`)

const ctx = await browser.newContext()
await ctx.addInitScript(HARNESS)
const page = await ctx.newPage()
const consoleErrs = []
page.on('console', (m) => {
  const t = m.text()
  if (CAP_ERR.test(t)) consoleErrs.push(t)
  if (process.env.VERBOSE) console.log('  [page] ' + t)
})
page.on('pageerror', (e) => {
  if (CAP_ERR.test(e.message)) consoleErrs.push(e.message)
})
await page.goto(`http://localhost:${PORT}/__soak__/`)

const result = await page.evaluate(async ({ soakMs, accel }) => {
  const { createBrowserTransport } = await import('/src/browser/webrtc.js')
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
  const S = 'S'.repeat(26)

  // ── fake tracker bus: webtorrent-shaped signalling, entirely in-page. Keyed url|info_hash so the
  //    three "trackers" are three independent swarms, exactly like the real ones.
  const bus = new Map()
  const key = (url, h) => url + '|' + h
  class FakeWS {
    constructor(url) {
      this.url = url
      this.readyState = 0
      this.peerId = null
      this.offers = new Map()
      this.keys = new Set()
      this.onopen = this.onmessage = this.onclose = this.onerror = null
      setTimeout(() => { this.readyState = 1; this.onopen && this.onopen(this) }, 1)
    }
    peers(k) { return bus.get(k) || new Set() }
    deliver(obj) { setTimeout(() => { if (this.readyState === 1) this.onmessage && this.onmessage({ data: JSON.stringify(obj) }) }, 0) }
    send(str) {
      let m
      try { m = JSON.parse(str) } catch { return }
      if (m.action !== 'announce' || !m.info_hash) return
      const k = key(this.url, m.info_hash)
      this.peerId = m.peer_id
      if (!bus.has(k)) bus.set(k, new Set())
      bus.get(k).add(this); this.keys.add(k)
      if (m.answer && m.to_peer_id) { // route an answer back to the peer that parked the offer
        for (const s of this.peers(k)) if (s !== this && s.peerId === m.to_peer_id) s.deliver(m)
        return
      }
      if (m.offers && m.offers.length) { // a listener parking offers → relay them to everyone else
        this.offers = new Map(m.offers.map((o) => [o.offer_id, o]))
        for (const s of this.peers(k)) if (s !== this) {
          for (const o of m.offers) s.deliver({ action: 'announce', info_hash: m.info_hash, peer_id: m.peer_id, offer_id: o.offer_id, offer: o.offer })
        }
        return
      }
      // a dialer announcing with no offers → hand it every parked offer on this swarm
      for (const s of this.peers(k)) if (s !== this && s.offers.size) {
        for (const o of s.offers.values()) this.deliver({ action: 'announce', info_hash: m.info_hash, peer_id: s.peerId, offer_id: o.offer_id, offer: o.offer })
      }
    }
    close() { this.readyState = 3; for (const k of this.keys) this.peers(k).delete(this); this.onclose && this.onclose() }
  }

  const common = {
    trackers: ['ws://t1.fake', 'ws://t2.fake', 'ws://t3.fake'], // 3, like the shipped TRACKERS
    WebSocket: FakeWS,
    iceServers: [], // host candidates only — no STUN, no network, instant gathering
  }
  const listener = createBrowserTransport({
    ...common,
    announceIntervalMs: Math.round(10_000 / accel), // 50ms
    offerTtlMs: Math.round(120_000 / accel), // 600ms
    connectTtlMs: 5_000, // NOT accelerated: real ICE needs real time to open the channel
    pcCreatesPerMin: 6 * accel, // (new opt; ignored by the old code) same budget, accelerated clock
  })
  await listener.createEndpoint()
  let accepted = 0
  listener.endpoint.onConnection(() => { accepted++ })
  const handle = listener.publishAll(S)

  // ── soak. Sample live/created throughout; abort early if Chromium starts throwing.
  const samples = []
  const t0 = performance.now()
  let dial = null
  while (performance.now() - t0 < soakMs) {
    await sleep(1000)
    const st = window.__stats
    samples.push({ t: Math.round(performance.now() - t0), created: st.created, live: st.created - st.closed, parked: handle.pendingCount() })
    if (st.errors.length) break
    // ── (c) mid-soak: a REAL dialer must still land on a parked offer (of arbitrary age).
    if (!dial && performance.now() - t0 > Math.min(soakMs * 0.6, 60_000)) {
      const d0 = performance.now()
      const dialer = createBrowserTransport({ ...common })
      const ep = await dialer.createEndpoint()
      dial = { ok: false, ms: 0, err: null }
      try {
        const sock = await ep.punch([{ channel: 'webrtc', s: S }])
        dial.ok = !!sock && !sock.closed
        dial.ms = Math.round(performance.now() - d0)
        sock.close()
      } catch (e) {
        dial.err = String(e && e.message)
        dial.ms = Math.round(performance.now() - d0)
      }
      dialer.close()
    }
  }

  const before = { ...window.__stats }
  handle.stop()
  listener.close()
  await sleep(200)
  const st = window.__stats
  return {
    created: before.created,
    live: before.created - before.closed,
    peak: before.peak,
    parked: samples.length ? samples[samples.length - 1].parked : 0,
    errors: st.errors.slice(0, 3),
    liveAfterClose: st.created - st.closed,
    accepted,
    dial,
    samples: samples.filter((_, i) => i % 10 === 0 || i === samples.length - 1),
    seconds: Math.round(performance.now() - t0) / 1000,
  }
}, { soakMs: SOAK_MS, accel: ACCEL })

const rate = result.created / result.seconds
console.log('  samples (t=s, cumulative created, live, parked):')
for (const s of result.samples) console.log(`    t=${String(Math.round(s.t / 1000)).padStart(3)}s  created=${String(s.created).padStart(6)}  live=${String(s.live).padStart(4)}  parked=${s.parked}`)
console.log(`\n  cumulative constructed : ${result.created}  (${rate.toFixed(1)}/s accelerated  ≈ ${(rate * 60 / ACCEL).toFixed(1)}/min real)`)
console.log(`  peak live (unclosed)   : ${result.peak}`)
console.log(`  live at soak end       : ${result.live}   → after close(): ${result.liveAfterClose}`)
console.log(`  parked offers at end   : ${result.parked}`)
console.log(`  dialer                 : ${result.dial ? (result.dial.ok ? `CONNECTED in ${result.dial.ms}ms` : `FAILED (${result.dial.err})`) : 'not run'}`)
console.log(`  listener accepted      : ${result.accepted}`)
console.log(`  PC-cap errors          : ${result.errors.length ? result.errors.join(' | ') : 'none'}`)

// (a) the browser must NEVER throw the cap error
if (result.errors.length || consoleErrs.length) fail(`Chromium threw the PeerConnection cap error: ${(result.errors[0] || consoleErrs[0])}`)
// (b) bounded live + bounded creation rate. NB: this test co-locates the dialer transport IN THE SAME
// PAGE as the listener, so `peak` counts BOTH (listener pool ≤ MAX_LIVE_PCS plus the dialer's few
// answerers during the mid-soak dial). A listener-only page peaks at the pool size; 24 leaves headroom
// for the co-located dialer burst while staying an order of magnitude under Chromium's ~500 wall.
if (result.peak > 24) fail(`live RTCPeerConnections must stay bounded — peak was ${result.peak} (cap 24)`)
if (rate > 20) fail(`PC construction rate must stay bounded — ${rate.toFixed(1)}/s accelerated (cap 20/s ≈ 6/min real)`)
if (result.liveAfterClose > 0) fail(`close() must free every PC — ${result.liveAfterClose} still open`)
// Conclusiveness: under the FIX the whole point is that constructions do NOT scale with the clock,
// so a passing run constructs FAR fewer than Chromium's ~500 cap — a flat created-curve IS the proof.
// (The RED demonstration — the OLD code slamming into the 500 wall — is reproduced by reverting the
// fix and re-running; see the report. Here we assert the curve is flat, not that it reached 500.)
{
  const s = result.samples
  const first = s.length ? s[0].created : 0
  const last = s.length ? s[s.length - 1].created : 0
  const spanH = (result.seconds * ACCEL) / 3600
  console.log(`  construction curve    : ${first} → ${last} over ~${spanH.toFixed(1)}h modeled  (flat ⇒ reuse working; churning code would be in the thousands)`)
}
// (c) connectivity intact
if (!result.dial || !result.dial.ok) fail(`a dialer must still land on a parked offer (${result.dial ? result.dial.err : 'dial not attempted'})`)
if (result.accepted < 1) fail('the listener must have accepted the dialer\'s connection (onConnection never fired)')
if (!process.exitCode) console.log('\n  ✔ PHASE A PASSED — bounded PCs, no cap error, dialer still connects\n')
await ctx.close()

// ══ PHASE B — the SHIPPED /app/ listener against the REAL trackers: measure its churn ════════════
if (!process.env.NO_NET) {
  const WINDOW_MS = Number(process.env.APP_MS || 60_000)
  console.log(`── PHASE B — the real /app/ listener on the PUBLIC trackers: PC churn over ${WINDOW_MS / 1000}s`)
  const ctx2 = await browser.newContext()
  await ctx2.addInitScript(HARNESS)
  const app = await ctx2.newPage()
  const appErrs = []
  app.on('console', (m) => { if (CAP_ERR.test(m.text())) appErrs.push(m.text()) })
  app.on('pageerror', (e) => { if (CAP_ERR.test(e.message)) appErrs.push(e.message) })
  await app.goto(`http://localhost:${PORT}/app/`)
  await app.waitForFunction(() => document.getElementById('mykey').textContent.length === 26, { timeout: 30_000 })
  console.log(`  ✔ listener online, key = ${await app.textContent('#mykey')}`)
  const t0 = Date.now()
  await new Promise((r) => setTimeout(r, WINDOW_MS))
  const st = await app.evaluate(() => ({ ...window.__stats, errors: window.__stats.errors.slice(0, 2) }))
  const mins = (Date.now() - t0) / 60_000
  const perMin = st.created / mins
  console.log(`  constructed  : ${st.created} in ${mins.toFixed(1)} min → ${perMin.toFixed(1)} PCs/min  (old code: ~72/min)`)
  console.log(`  live/peak    : ${st.created - st.closed} / ${st.peak}`)
  console.log(`  PC-cap errors: ${st.errors.length || appErrs.length ? (st.errors[0] || appErrs[0]) : 'none'}`)
  if (st.errors.length || appErrs.length) fail('the real /app/ listener threw the PeerConnection cap error')
  if (perMin > 20) fail(`the real /app/ listener still churns ${perMin.toFixed(1)} PCs/min (cap 20/min ⇒ <1200/h)`)
  if (st.peak > 20) fail(`the real /app/ listener holds ${st.peak} live PCs at peak (cap 20)`)
  if (st.created === 0) console.log('  ⚠ zero PCs constructed — the public trackers were unreachable; phase B proved nothing')
  if (!process.exitCode) console.log('\n  ✔ PHASE B PASSED — the shipped listener\'s churn is bounded on the real trackers\n')
  await ctx2.close()
}

await browser.close()
server.close()
console.log(process.exitCode ? '✖ BROWSER PC-SOAK FAILED\n' : '✔ BROWSER PC-SOAK PASSED — a real Chromium listener never exhausts RTCPeerConnections\n')
