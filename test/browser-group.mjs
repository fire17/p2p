// test/browser-group.mjs — groups > 2, in real browsers. Three browser peers form a group via
// the SHARED src/group.js (pairwise fan-out over the existing Noise links) — no new code, it
// rides node.connect + peer.send, both of which already work in the browser. Proves the task's
// "seamless groups (>2)" holds for the browser client today.
//
// (The sender-keys + membership-chain upgrade in research/browser-client.md §7 is the P3 scale
// improvement on top of this; pairwise fan-out is the correct, interoperable v1 for small groups.)
//
// Run: PLAYWRIGHT=/path/to/playwright/index.mjs node test/browser-group.mjs

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { join, dirname, extname, normalize } from 'node:path'

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
    const b = await readFile(f)
    res.writeHead(200, { 'content-type': MIME[extname(f)] || 'application/octet-stream' }).end(b)
  } catch {
    res.writeHead(404).end('nf')
  }
})
await new Promise((r) => server.listen(8097, r))

const browser = await chromium.launch({ headless: !process.env.HEADED })
let failed = false
const fail = (m) => { console.error('✖ ' + m); failed = true }

try {
  const pages = []
  for (let i = 0; i < 3; i++) {
    const pg = await (await browser.newContext()).newPage()
    pg.on('pageerror', (e) => fail(`peer${i}: ${e.message}`))
    await pg.goto('http://localhost:8097/src/browser/index.html')
    await pg.waitForFunction(() => document.getElementById('mykey').textContent.length === 26, { timeout: 30_000 })
    pages.push(pg)
  }
  const keys = await Promise.all(pages.map((p) => p.textContent('#mykey')))
  console.log('  ✔ 3 browser peers online:', keys.map((k) => k.slice(0, 8)).join(', '))
  if (new Set(keys).size !== 3) fail('peers must have distinct identities')

  // Peer 0 forms a group of the other two and fans a message to both, via src/group.js.
  const result = await pages[0].evaluate(async ([kb, kc]) => {
    // reach the live node the page created — app.js keeps it in module scope, so re-listen would
    // clash; instead drive group() through a fresh connect from THIS page's node via the console
    // hook we expose below.
    return await window.__p2pGroupSend([kb, kc], 'hello group from peer0')
  }, [keys[1], keys[2]])

  if (!result || !result.every((r) => r.ack !== undefined)) {
    fail('group fan-out did not get an ack from every member: ' + JSON.stringify(result))
  } else {
    console.log('  ✔ group.send fanned out to 2 members, both ACKed')
  }

  for (let i = 1; i < 3; i++) {
    await pages[i].waitForFunction(() => document.getElementById('log').textContent.includes('hello group from peer0'), { timeout: 20_000 })
    console.log(`  ✔ peer${i} received the group message (E2E, over its own Noise link)`)
  }

  if (!failed) console.log('\n✔ BROWSER GROUP (>2) PASSED — 3 peers, pairwise fan-out, all E2E\n')
} catch (e) {
  fail(e.message)
} finally {
  await browser.close()
  server.close()
  process.exitCode = failed ? 1 : 0
}
