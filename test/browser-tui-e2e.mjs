// test/browser-tui-e2e.mjs — THE interop gate: browser ↔ TUI, zero backend, over the WSS relay.
//
// A browser peer cannot speak the TUI's UDP transport (no raw sockets, ever). The zero-dep bridge
// is src/transport-wss.js: both a Node process (the "TUI") and a browser dial OUT to the same public
// MQTT-over-WSS relay, and node.js runs the identical HELLO → commitment gate → Noise IK over it.
// This proves browser↔TUI works with NO dependency on either side and NO server of ours — the
// owner's requirement #2/#3. The relay is blind (opaque topic + Noise ciphertext), so security is
// == the TUI (research/browser-client.md §6.3/§8).
//
// The Node side here is exactly what a TUI does: node.listen() with the WSS endpoint + rendezvous.
// The browser side is the shipped client (src/browser/), whose raced transport includes WSS.
//
// Run: PLAYWRIGHT=/path/to/playwright/index.mjs node test/browser-tui-e2e.mjs
// Honest scope: single host, real public relays — proves the code path + live relay interop, not
// two distinct networks (the WSS relay traverses NAT by construction, so network-independence is
// inherent to the transport, unlike the UDP path).

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { join, dirname, extname, normalize } from 'node:path'
import { identity as nodeIdentity, listen as nodeListen } from '../src/node.js'
import * as wss from '../src/transport-wss.js'

let chromium
try {
  ;({ chromium } = await import(process.env.PLAYWRIGHT || 'playwright'))
} catch {
  console.log('⏭  SKIP: playwright not found (set PLAYWRIGHT=/path/to/playwright/index.mjs)')
  process.exit(0)
}

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json' }
const server = createServer(async (req, res) => {
  try {
    const p = normalize(decodeURIComponent(req.url.split('?')[0])).replace(/^(\.\.[/\\])+/, '')
    const f = p.endsWith('/') ? join(ROOT, p, 'index.html') : join(ROOT, p)
    if (!f.startsWith(ROOT)) throw 0
    const b = await readFile(f)
    res.writeHead(200, { 'content-type': MIME[extname(f)] || 'application/octet-stream' }).end(b)
  } catch {
    res.writeHead(404).end('nf')
  }
})
await new Promise((r) => server.listen(8096, r))

let failed = false
const fail = (m) => { console.error('✖ ' + m); failed = true }

// ── the "TUI": a Node peer on the WSS relay (exactly how a CLI would opt into the relay) ──
const tuiId = await nodeIdentity()
const tuiEp = wss.createEndpoint({ S: tuiId.S })
const tuiRv = wss.createWssRendezvous()
const tui = await nodeListen(tuiId, { endpoint: tuiEp, deps: { resolve: tuiRv.resolve, publishAll: tuiRv.publishAll } })
let tuiGot = null
tui.on('message', (_p, buf) => { tuiGot = Buffer.from(buf).toString('utf8') })
tui.on('peer', (p) => console.log('  ✔ TUI: verified peer', p.key))
console.log('  TUI (node) online on the WSS relay, key =', tuiId.S)

const browser = await chromium.launch({ headless: !process.env.HEADED })
try {
  const page = await (await browser.newContext()).newPage()
  page.on('pageerror', (e) => fail('browser page error: ' + e.message))
  if (process.env.VERBOSE) page.on('console', (m) => console.log('  [browser]', m.text()))
  await page.goto('http://localhost:8096/app/')
  await page.waitForFunction(() => document.getElementById('mykey').textContent.length === 26, { timeout: 30_000 })
  const browserKey = await page.textContent('#mykey')
  console.log('  Browser online, key =', browserKey)

  // ── browser dials the TUI over the relay ──
  console.log(`\n  → browser dials the TUI (${tuiId.S}) over the WSS relay…`)
  const t0 = Date.now()
  await page.fill('#peerkey', tuiId.S)
  await page.click('#connect')
  await page.waitForFunction(() => /secure channel established/.test(document.getElementById('log').textContent), { timeout: 90_000 })
  console.log(`  ✔ browser↔TUI verified Noise IK over the relay in ${((Date.now() - t0) / 1000).toFixed(1)}s`)

  // ── browser → TUI ──
  await page.fill('#msg', 'hello TUI, this is the browser')
  await page.click('#send')
  await page.waitForFunction(() => document.getElementById('log').textContent.includes('this is the browser'), { timeout: 10_000 }).catch(() => {})
  for (let i = 0; i < 40 && tuiGot === null; i++) await new Promise((r) => setTimeout(r, 250))
  if (tuiGot !== 'hello TUI, this is the browser') fail('TUI did not receive the browser message, got: ' + JSON.stringify(tuiGot))
  else console.log('  ✔ browser → TUI message delivered (E2E over the blind relay)')

  // ── TUI → browser ──
  const tuiPeer = tui.peers().find((p) => p.key === browserKey)
  if (!tuiPeer) fail('TUI has no peer handle for the browser')
  else {
    await tuiPeer.send('hello browser, this is the TUI')
    await page.waitForFunction(() => document.getElementById('log').textContent.includes('this is the TUI'), { timeout: 10_000 })
    console.log('  ✔ TUI → browser message delivered')
  }

  if (!failed) console.log('\n✔ BROWSER↔TUI PASSED — interoperable over the zero-dep WSS relay, no backend of ours\n')
} catch (e) {
  fail(e.message)
} finally {
  await browser.close()
  tui.close()
  server.close()
  process.exitCode = failed ? 1 : 0
}
