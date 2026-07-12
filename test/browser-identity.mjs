// test/browser-identity.mjs — multiple identities in ONE browser, in a REAL browser, end to end.
//
// The bug this proves fixed (owner hit it live): the browser client stored ONE identity per origin,
// so two normal tabs/windows shared the SAME key — they were the same peer and a message to "the
// other tab" went to yourself. The only workaround was incognito. This gate proves the fix:
//
//   I1  two pages in ONE browser context (SHARED IndexedDB — the exact failing case) pick different
//       identity SLOTS (#id=alice vs #id=bob) and get DISTINCT 26-char keys.
//   I2  those two distinct identities complete a real browser↔browser WebRTC + Noise IK chat.
//   I3  the "＋ New identity" button opens a new window that is a NEW peer (distinct key).
//   I4  dialing your OWN key is refused with a clear inline message (no dial attempted).
//   I5  BRW-2: two pages first-run CONCURRENTLY on the SAME slot both end with the SAME persisted,
//       consistent identity (no last-write-wins clobber) — and it survives reload.
//
// Not in the default `npm test` run (needs a browser + the live public internet), same as
// browser-e2e.mjs. Run:
//   PLAYWRIGHT=/path/to/playwright/index.mjs node test/browser-identity.mjs
//   HEADED=1 ... to watch it.

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
const PORT = 8097
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json' }
const server = createServer(async (req, res) => {
  try {
    const p = normalize(decodeURIComponent(req.url.split('?')[0])).replace(/^(\.\.[/\\])+/, '')
    const rel = p === '/' ? '/app/' : p
    const f = rel.endsWith('/') ? join(ROOT, rel, 'index.html') : join(ROOT, rel)
    if (!f.startsWith(ROOT)) throw 0
    res.writeHead(200, { 'content-type': MIME[extname(f)] || 'application/octet-stream' }).end(await readFile(f))
  } catch {
    res.writeHead(404).end('nf')
  }
})
await new Promise((r) => server.listen(PORT, r))

const URL = `http://localhost:${PORT}/app/`
const browser = await chromium.launch({ headless: !process.env.HEADED })
let failed = false
const fail = (m) => { console.error('✖ ' + m); failed = true }

// Open a page on a slot and wait until it is online (identity minted + tracker announce done).
async function online(ctx, hash = '') {
  const pg = await ctx.newPage()
  pg.on('pageerror', (e) => fail('page error: ' + e.message))
  if (process.env.VERBOSE) pg.on('console', (m) => console.log('  [pg]', m.text()))
  await pg.goto(URL + hash)
  await pg.waitForFunction(() => document.getElementById('mykey').textContent.length === 26, { timeout: 30_000 })
  return pg
}
const keyOf = (pg) => pg.textContent('#mykey')

try {
  // ── I1: two pages, ONE context, distinct slots → distinct keys (shared storage, the failing case) ──
  const ctx = await browser.newContext()
  const alice = await online(ctx, '#id=alice')
  const bob = await online(ctx, '#id=bob')
  const aliceKey = await keyOf(alice)
  const bobKey = await keyOf(bob)
  console.log('  alice(#id=alice)', aliceKey, '\n  bob  (#id=bob)  ', bobKey)
  if (aliceKey === bobKey) fail('I1: two tabs in ONE context got the SAME key — the slot mechanism did not isolate them')
  else console.log('  ✔ I1: two tabs in ONE shared-storage context are DISTINCT identities')
  // the active identity name is surfaced in the UI
  if ((await alice.textContent('#idname')) !== 'alice') fail('I1: alice tab does not show its identity name')

  // ── I3: the "＋ New identity" button opens a new window that is a NEW peer ──
  const [popup] = await Promise.all([ctx.waitForEvent('page'), alice.click('#newId')])
  await popup.waitForFunction(() => document.getElementById('mykey').textContent.length === 26, { timeout: 30_000 })
  const popupKey = await keyOf(popup)
  if (popupKey === aliceKey || popupKey === bobKey) fail('I3: ＋ New identity did not mint a distinct key')
  else console.log('  ✔ I3: ＋ New identity opened a new window with a distinct key', popupKey)
  await popup.close()

  // ── I4: dialing your OWN key is refused ──
  await alice.waitForFunction(() => /online/.test(document.getElementById('statusText').textContent), { timeout: 90_000 })
  await alice.fill('#peerkey', aliceKey)
  await alice.click('#connect')
  await alice.waitForFunction(() => /own key/i.test(document.getElementById('log').textContent), { timeout: 5_000 })
    .catch(() => fail('I4: dialing your own key did not show the own-key guard message'))
  if (/dialing/i.test(await alice.textContent('#log'))) fail('I4: the own-key dial was attempted anyway (no "dialing" line should appear)')
  if (!failed) console.log('  ✔ I4: dialing your own key is refused with a clear message, no dial attempted')

  // ── I2: the two distinct identities complete a real browser↔browser chat ──
  await bob.waitForFunction(() => /online/.test(document.getElementById('statusText').textContent), { timeout: 90_000 })
  console.log('\n  → bob dials alice over the public trackers…')
  const t0 = Date.now()
  await bob.fill('#peerkey', aliceKey)
  await bob.click('#connect')
  const verified = /secure channel established/
  await bob.waitForFunction(() => /secure channel established/.test(document.getElementById('log').textContent), { timeout: 90_000 })
  await alice.waitForFunction(() => /secure channel established/.test(document.getElementById('log').textContent), { timeout: 90_000 })
  console.log(`  ✔ I2: verified Noise IK channel over WebRTC in ${((Date.now() - t0) / 1000).toFixed(1)}s`)
  if (!verified.test(await alice.textContent('#log')) || !verified.test(await bob.textContent('#log'))) fail('I2: both sides must report a verified channel')

  await bob.fill('#msg', 'hi alice — this is bob, a SECOND identity in the same browser')
  await bob.click('#send')
  await alice.waitForFunction(() => document.getElementById('log').textContent.includes('a SECOND identity'), { timeout: 20_000 })
    .catch(() => fail('I2: alice did not receive bob\'s message'))
  await alice.fill('#msg', 'got it — two peers, one browser, no incognito needed')
  await alice.click('#send')
  await bob.waitForFunction(() => document.getElementById('log').textContent.includes('one browser'), { timeout: 20_000 })
    .catch(() => fail('I2: bob did not receive alice\'s message'))
  if (!failed) console.log('  ✔ I2: browser↔browser chat works BOTH ways between the two same-browser identities')
  await ctx.close()

  // ── I5: BRW-2 — two pages first-run CONCURRENTLY on the SAME (default) slot end consistent ──
  const ctx2 = await browser.newContext() // fresh, empty storage
  const [p1, p2] = await Promise.all([online(ctx2), online(ctx2)]) // race the first-run create
  const k1 = await keyOf(p1)
  const k2 = await keyOf(p2)
  console.log('\n  BRW-2 concurrent first-run: p1', k1, '\n                              p2', k2)
  if (k1 !== k2) fail('I5/BRW-2: concurrent first-run minted DIFFERENT keys (last-write-wins clobber)')
  else console.log('  ✔ I5: concurrent first-run on the same slot → ONE consistent identity (no clobber)')
  // and it is truly PERSISTED (survives reload — the loser is not running an unsaved identity)
  await p1.reload()
  await p1.waitForFunction(() => document.getElementById('mykey').textContent.length === 26, { timeout: 30_000 })
  if ((await keyOf(p1)) !== k1) fail('I5/BRW-2: the identity was not persisted (changed on reload)')
  else console.log('  ✔ I5: the identity is persisted (unchanged after reload)')
  await ctx2.close()

  if (!failed) console.log('\n✔ BROWSER IDENTITY PASSED — multi-identity slots (I1) + browser↔browser chat (I2) + ＋New (I3) + own-key guard (I4) + BRW-2 (I5)\n')
} catch (e) {
  fail(e.message)
} finally {
  await browser.close()
  server.close()
  process.exitCode = failed ? 1 : 0
}
