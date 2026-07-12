// test/browser-group-tui.mjs — FRESH-WITNESS (requested by browser-build): a real BROWSER member in
// a 3-party SENDER-KEYS group with two Node peers. Closes the last unverified corner of P3 — the
// secure-group crypto was verified on browser primitives, but never with a real browser in the mesh.
//
// Topology: nodeA (admin) + nodeB, both Node on the WSS relay; browserC, a real Chromium peer on the
// raced transport (WSS leg). All share a 32-byte group secret G. Sender keys distributed over the
// authenticated pairwise Noise links; each message is ChaCha20-Poly1305 under a per-sender ratchet
// and Ed25519-signed by its author. We assert the browser can SEND to the group (both nodes receive
// + attribute authorship to the browser) and RECEIVE from a node — all E2E, infra blind.
//
// Run: PLAYWRIGHT=/path/to/playwright/index.mjs node test/browser-group-tui.mjs
// Honest scope: single host, real public relays — proves the code path + browser-in-mesh, not two
// networks.

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { join, dirname, extname, normalize } from 'node:path'
import { identity as nodeIdentity, listen as nodeListen } from '../src/node.js'
import { createSecureGroup } from '../src/group.js'
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
    const f = join(ROOT, p)
    if (!f.startsWith(ROOT)) throw 0
    res.writeHead(200, { 'content-type': MIME[extname(f)] || 'application/octet-stream' }).end(await readFile(f))
  } catch {
    res.writeHead(404).end('nf')
  }
})
await new Promise((r) => server.listen(8095, r))

let failed = false
const fail = (m) => { console.error('✖ ' + m); failed = true }
const wait = (ms) => new Promise((r) => setTimeout(r, ms))

// ── two Node "TUI" peers on the WSS relay ──
const mkNode = async () => {
  const id = await nodeIdentity()
  const ep = wss.createEndpoint({ S: id.S })
  const rv = wss.createWssRendezvous()
  const node = await nodeListen(id, { endpoint: ep, deps: { resolve: rv.resolve, publishAll: rv.publishAll } })
  return { id, node }
}
const A = await mkNode() // admin
const B = await mkNode()
console.log('  nodeA(admin)', A.id.S, '\n  nodeB       ', B.id.S)

const browser = await chromium.launch({ headless: !process.env.HEADED })
try {
  const page = await (await browser.newContext()).newPage()
  page.on('pageerror', (e) => fail('browser: ' + e.message))
  if (process.env.VERBOSE) page.on('console', (m) => console.log('  [browser]', m.text()))
  await page.goto('http://localhost:8095/src/browser/index.html')
  await page.waitForFunction(() => document.getElementById('mykey').textContent.length === 26, { timeout: 30_000 })
  const C = await page.textContent('#mykey')
  console.log('  browserC    ', C)

  // shared group secret (base64), known to all three out-of-band
  const G = randomBytes(32).toString('base64')

  // received-message sinks on the Node side
  const rx = { A: [], B: [] }
  const gA = createSecureGroup(A.node, A.id, { secret: Buffer.from(G, 'base64'), members: [B.id.S, C], create: true })
  const gB = createSecureGroup(B.node, B.id, { secret: Buffer.from(G, 'base64') })
  gA.on('message', (from, d) => rx.A.push({ from, text: Buffer.from(d).toString('utf8') }))
  gB.on('message', (from, d) => rx.B.push({ from, text: Buffer.from(d).toString('utf8') }))

  // Sender-keys mesh ordering (mirrors group-secure.test.js): everyone CREATES first (so they can
  // receive ops), the ADMIN joins first to propagate the membership chain + its key, THEN the
  // others join — now they know the members and distribute their own sender keys to them.
  console.log('\n  → all three join the sender-keys group over the relay…')
  await page.evaluate((g) => window.__secureGroupCreate(g), G) // browser creates (message sink wired)
  await gA.join(); await wait(1500) // admin first: propagate the chain + admin's sender key
  await Promise.all([page.evaluate(() => window.__secureGroupJoin()), gB.join()])
  await wait(2000) // let the browser's + B's sender keys reach everyone

  // ── browser → group: both nodes must receive it AND attribute it to the browser ──
  await page.evaluate(() => window.__secureGroupSend('hello group, from the browser'))
  for (let i = 0; i < 40 && !(rx.A.some((m) => m.text.includes('from the browser')) && rx.B.some((m) => m.text.includes('from the browser'))); i++) await wait(250)
  const inA = rx.A.find((m) => m.text.includes('from the browser'))
  const inB = rx.B.find((m) => m.text.includes('from the browser'))
  if (!inA) fail('nodeA did not receive the browser group message')
  else if (inA.from !== C) fail(`nodeA mis-attributed authorship: ${inA.from} != ${C}`)
  else console.log('  ✔ browser → group: nodeA received + attributed authorship to the browser')
  if (!inB) fail('nodeB did not receive the browser group message')
  else if (inB.from !== C) fail(`nodeB mis-attributed authorship: ${inB.from} != ${C}`)
  else console.log('  ✔ browser → group: nodeB received + attributed authorship to the browser')

  // ── node → group: the browser must receive it ──
  await gA.send('hello group, from admin nodeA'); await wait(1500)
  const rxC = await page.evaluate(() => window.__secureRx)
  const got = rxC.find((m) => m.text.includes('from admin nodeA'))
  if (!got) fail('browser did not receive the admin group message: ' + JSON.stringify(rxC))
  else if (got.from !== A.id.S) fail(`browser mis-attributed authorship: ${got.from} != ${A.id.S}`)
  else console.log('  ✔ nodeA → group: browser received + attributed authorship to nodeA')

  if (!failed) console.log('\n✔ BROWSER-IN-GROUP PASSED — real browser in a 3-party sender-keys group, E2E, over the relay\n')
} catch (e) {
  fail(e.message)
} finally {
  await browser.close()
  A.node.close(); B.node.close()
  server.close()
  process.exitCode = failed ? 1 : 0
}
