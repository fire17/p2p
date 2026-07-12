// test/browser-group-ui.mjs — the SHIPPED group UX, driven through the actual /app/ buttons (not the
// programmatic hooks). Two real browsers: one CREATES a group + adds the other by key; the other JOINS
// with the group code; both send group messages and see each other's, E2E over public infrastructure.
// This is the acceptance for "a stranger can feel-test group chat at p2p.akeyo.io/app/".
//
// Run: PLAYWRIGHT=/path/to/playwright/index.mjs node test/browser-group-ui.mjs

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
    const f = p.endsWith('/') ? join(ROOT, p, 'index.html') : join(ROOT, p)
    if (!f.startsWith(ROOT)) throw 0
    res.writeHead(200, { 'content-type': MIME[extname(f)] || 'application/octet-stream' }).end(await readFile(f))
  } catch {
    res.writeHead(404).end('nf')
  }
})
await new Promise((r) => server.listen(8091, r))

const browser = await chromium.launch({ headless: !process.env.HEADED })
let failed = false
const fail = (m) => { console.error('✖ ' + m); failed = true }
const wait = (ms) => new Promise((r) => setTimeout(r, ms))

async function open() {
  const pg = await (await browser.newContext()).newPage()
  pg.on('pageerror', (e) => fail('page error: ' + e.message))
  if (process.env.VERBOSE) pg.on('console', (m) => console.log('  [b]', m.text()))
  await pg.goto('http://localhost:8091/app/')
  await pg.waitForFunction(() => document.getElementById('mykey').textContent.length === 26, { timeout: 30_000 })
  await pg.waitForFunction(() => /online/.test(document.getElementById('statusText').textContent), { timeout: 30_000 })
  return pg
}

try {
  const alice = await open()
  const bob = await open()
  const aliceKey = await alice.textContent('#mykey')
  const bobKey = await bob.textContent('#mykey')
  console.log('  alice', aliceKey, '\n  bob  ', bobKey)

  // Alice: switch to Group, LIST Bob's key, and create the group (members set at creation — the
  // reliable, proven path: the admin lists everyone; they join with the code).
  await alice.click('#tabGroup')
  await alice.fill('#groupSeed', bobKey)
  await alice.click('#groupNew')
  // the real signal that creation completed is #groupCopy becoming enabled (enableGroupChat ran)
  await alice.waitForFunction(() => !document.getElementById('groupCopy').disabled, { timeout: 20_000 })
  const groupCode = await alice.textContent('#groupCode')
  console.log('  ✔ alice created a group (with bob listed) via the UI, code =', groupCode.slice(0, 16) + '…')

  // Bob: switch to Group, paste the code, JOIN via the button.
  await bob.click('#tabGroup')
  await bob.fill('#groupSecret', groupCode)
  await bob.click('#groupJoin')
  // the real signal bob's join completed is #groupCopy becoming enabled (enableGroupChat ran).
  // (the message box is always typeable now — send is gated on the group existing, not the input.)
  await bob.waitForFunction(() => !document.getElementById('groupCopy').disabled, { timeout: 20_000 })
  console.log('  ✔ bob joined via the UI with the group code')
  // wait for the admin's periodic re-sync to pull bob in (he joined after the admin) — poll until
  // bob's group shows 2 members, then a beat for the sender keys to settle both ways.
  await bob.waitForFunction(() => /2 member/.test(document.getElementById('groupMembers').textContent), { timeout: 30_000 })
    .catch(() => fail('bob never reached full membership (re-sync did not pull him in)'))
  console.log('  ✔ bob reached full membership via the admin re-sync')
  await wait(2500)

  // Bob → group, via the UI.
  await bob.fill('#groupMsg', 'hi group — bob here, from the browser UI')
  await bob.click('#groupSend')
  await alice.waitForFunction(() => document.getElementById('grouplog').textContent.includes('bob here'), { timeout: 20_000 })
    .catch(() => fail('alice did not receive bob\'s group message through the UI'))
  if (!failed) console.log('  ✔ bob → group message shown in alice\'s group log')

  // Alice → group, via the UI.
  await alice.fill('#groupMsg', 'welcome bob — alice, admin')
  await alice.click('#groupSend')
  await bob.waitForFunction(() => document.getElementById('grouplog').textContent.includes('welcome bob'), { timeout: 20_000 })
    .catch(() => fail('bob did not receive alice\'s group message through the UI'))
  if (!failed) console.log('  ✔ alice → group message shown in bob\'s group log')

  if (!failed) console.log('\n✔ BROWSER GROUP UI PASSED — create + add + join + chat, all through the shipped /app/ buttons\n')
} catch (e) {
  fail(e.message)
} finally {
  await browser.close()
  server.close()
  process.exitCode = failed ? 1 : 0
}
