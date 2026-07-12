// test/browser-e2e.mjs — G2 + G3: the browser client, in a REAL browser, end to end.
//
// Not a unit test and not in the default `npm test` run (it needs a browser + the live public
// internet). This is the acceptance gate for the browser client:
//
//   G2  two browser contexts find each other over the REAL public WSS trackers, using rids
//       derived from the 26-char key — our existing rendezvous, no infrastructure of ours.
//   G3  they open a real WebRTC DataChannel (ICE + free public STUN), run HELLO -> commitment
//       gate -> Noise IK over it, and exchange chat messages both ways.
//
// Passing this means the whole stack works in a browser: the vendored crypto, the Buffer/crypto
// shims, the SHARED protocol source (src/key.js, src/noise.js, src/wire.js, src/node.js), the
// tracker signaling, and the WebRTC transport.
//
// Run:  node test/browser-e2e.mjs            (headless)
//       HEADED=1 node test/browser-e2e.mjs   (watch it happen)
//
// Honest scope: both peers run on THIS machine, so this proves the code path and the live
// tracker rendezvous — it does NOT prove traversal between two different NATs. That needs two
// real networks (see research/browser-client.md §12).

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { join, dirname, extname, normalize } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..')
const PORT = 8099

// Playwright is a TEST-ONLY tool and this repo is zero-dependency — so we do NOT add it to
// package.json. Point PLAYWRIGHT at an existing install (npx cache, a global, or a local one):
//   PLAYWRIGHT=$(node -e "console.log(require.resolve('playwright'))") node test/browser-e2e.mjs
// If it isn't there, this gate SKIPS loudly rather than failing the build.
let chromium
try {
  const spec = process.env.PLAYWRIGHT || 'playwright'
  ;({ chromium } = await import(spec))
} catch {
  console.log('⏭  SKIP: playwright not found. This gate needs a browser.')
  console.log('   PLAYWRIGHT=/path/to/playwright/index.js node test/browser-e2e.mjs')
  process.exit(0)
}

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json' }

// Serve the repo. http://localhost is a secure context, so WebCrypto/IndexedDB work.
const server = createServer(async (req, res) => {
  try {
    const path = normalize(decodeURIComponent(req.url.split('?')[0])).replace(/^(\.\.[/\\])+/, '')
    const file = join(ROOT, path === '/' ? '/src/browser/index.html' : path)
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
  console.error('\n✖ ' + msg)
  process.exitCode = 1
}

try {
  // Two independent browser contexts = two independent origins-with-storage = two real peers.
  const alice = await (await browser.newContext()).newPage()
  const bob = await (await browser.newContext()).newPage()
  for (const [name, page] of [['alice', alice], ['bob', bob]]) {
    page.on('console', (m) => process.env.VERBOSE && console.log(`  [${name}] ${m.text()}`))
    page.on('pageerror', (e) => fail(`[${name}] page error: ${e.message}`))
  }

  const url = `http://localhost:${PORT}/src/browser/index.html`
  await alice.goto(url)
  await bob.goto(url)

  // ── both come online (identity + tracker announce) ──
  for (const [name, page] of [['alice', alice], ['bob', bob]]) {
    await page.waitForFunction(() => document.getElementById('mykey').textContent.length === 26, { timeout: 30_000 })
    const key = await page.textContent('#mykey')
    console.log(`  ✔ ${name} online, key = ${key}`)
  }

  const aliceKey = await alice.textContent('#mykey')
  const bobKey = await bob.textContent('#mykey')
  if (aliceKey === bobKey) fail('the two contexts minted the SAME identity — storage is not isolated')

  // ── G2 + G3: bob dials alice's key. Rendezvous over the real public trackers, then WebRTC. ──
  console.log(`\n  → bob dials alice (${aliceKey}) over the public trackers…`)
  const t0 = Date.now()
  await bob.fill('#peerkey', aliceKey)
  await bob.click('#connect')

  // The 'peer' event fires ONLY after the Noise IK first-ack — the MITM proof.
  const verified = /secure channel established/
  await bob.waitForFunction(() => /secure channel established/.test(document.getElementById('log').textContent), { timeout: 90_000 })
  await alice.waitForFunction(() => /secure channel established/.test(document.getElementById('log').textContent), { timeout: 90_000 })
  console.log(`  ✔ G2+G3: verified Noise IK channel over WebRTC in ${((Date.now() - t0) / 1000).toFixed(1)}s`)

  const aliceLog = await alice.textContent('#log')
  const bobLog = await bob.textContent('#log')
  if (!verified.test(aliceLog) || !verified.test(bobLog)) fail('both sides must report a verified channel')
  // each side must have learned the OTHER's real 26-char key from the handshake
  if (!bobLog.includes(aliceKey)) fail("bob did not learn alice's key from the handshake")
  if (!aliceLog.includes(bobKey)) fail("alice did not learn bob's key from the handshake")

  // ── chat, both directions ──
  await bob.fill('#msg', 'hello from bob')
  await bob.click('#send')
  await alice.waitForFunction(() => document.getElementById('log').textContent.includes('hello from bob'), { timeout: 20_000 })
  console.log('  ✔ bob -> alice message delivered (E2E encrypted, ACKed)')

  await alice.fill('#msg', 'hi bob, alice here')
  await alice.click('#send')
  await bob.waitForFunction(() => document.getElementById('log').textContent.includes('hi bob, alice here'), { timeout: 20_000 })
  console.log('  ✔ alice -> bob message delivered')

  // ── the gate must REJECT a key that is not a commitment to the peer's real pubkeys ──
  // (a typo'd/forged key must never produce a channel — fail closed)
  const bogus = 'ZZZZZZZZZZZZZZZZZZZZZZZZZZ'
  const rejected = await bob.evaluate(async (k) => {
    try {
      const { key } = await import('./p2p.js')
      key.decodeKey(k)
      return 'accepted'
    } catch (e) {
      return e.name // TypoError — caught locally, before any network traffic
    }
  }, bogus)
  if (rejected !== 'TypoError') fail(`a bogus key must be rejected by the checksum, got: ${rejected}`)
  console.log('  ✔ bogus key rejected locally by the checksum (no network touched)')

  if (!process.exitCode) console.log('\n✔ BROWSER E2E PASSED — G2 (tracker rendezvous) + G3 (WebRTC + Noise IK + chat)\n')
} catch (err) {
  fail(err.message)
} finally {
  await browser.close()
  server.close()
}
