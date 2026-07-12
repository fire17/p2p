// Real-keyboard typing guard for the /app/ chat inputs.
//
// Why this exists: every other browser test drives the inputs with playwright fill() or the
// window.__ hooks, which set .value directly and never dispatch key events. That masked a real
// bug — `$('msg').onkeydown = (e) => e.key === 'Enter' && send()` returns FALSE for every
// non-Enter key, and a DOM0 onkeydown returning false calls preventDefault(), cancelling the
// keystroke, so nothing could be typed. This test presses ACTUAL keys and asserts they land.
//
// Not in the default `npm test` (needs a browser). Run:
//   PLAYWRIGHT=/path/to/playwright/index.mjs node test/browser-typing.mjs
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { join, dirname, extname, normalize } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..') // repo root — Pages serves this; /app/ + /src/ resolve here

const PW = process.env.PLAYWRIGHT
if (!PW) { console.log('⏭  SKIP: browser-typing needs playwright (set PLAYWRIGHT=/path/to/playwright/index.mjs)'); process.exit(0) }
const { chromium } = await import(PW)

const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.css': 'text/css' }
const server = createServer(async (req, res) => {
  try {
    let p = normalize(decodeURIComponent(req.url.split('?')[0]))
    if (p.endsWith('/')) p += 'index.html'
    const abs = join(ROOT, p)
    if (!abs.startsWith(ROOT)) { res.writeHead(403).end(); return }
    const body = await readFile(abs)
    res.writeHead(200, { 'content-type': MIME[extname(abs)] || 'application/octet-stream' }).end(body)
  } catch { res.writeHead(404).end('not found') }
})
await new Promise((r) => server.listen(0, '127.0.0.1', r))
const url = `http://127.0.0.1:${server.address().port}/app/`

let failed = false
const fail = (m) => { console.error('✖ ' + m); failed = true }
const browser = await chromium.launch()
try {
  const p = await (await browser.newContext()).newPage()
  p.on('pageerror', (e) => fail('page error: ' + e.message))
  await p.goto(url, { waitUntil: 'load' })
  await p.waitForFunction(() => document.getElementById('mykey').textContent.length === 26, { timeout: 30_000 })

  // PAIR box — type real keys, assert they register
  await p.click('#msg')
  await p.keyboard.type('real keys pair', { delay: 8 })
  const pair = await p.evaluate(() => document.getElementById('msg').value)
  pair === 'real keys pair' ? console.log('  ✔ #msg accepts real keyboard typing') : fail(`#msg did not register keystrokes (got "${pair}") — onkeydown may be cancelling default`)

  // GROUP box — same
  await p.click('#tabGroup')
  await p.click('#groupMsg')
  await p.keyboard.type('real keys group', { delay: 8 })
  const grp = await p.evaluate(() => document.getElementById('groupMsg').value)
  grp === 'real keys group' ? console.log('  ✔ #groupMsg accepts real keyboard typing') : fail(`#groupMsg did not register keystrokes (got "${grp}")`)

  // Direct guard on the exact bug class: a non-Enter keydown must NOT be defaultPrevented.
  const prevented = await p.evaluate(() => {
    const e = new KeyboardEvent('keydown', { key: 'x', cancelable: true, bubbles: true })
    document.getElementById('msg').dispatchEvent(e)
    return e.defaultPrevented
  })
  prevented && fail('a non-Enter keydown on #msg was defaultPrevented (the onkeydown-returns-false bug)')
  if (!prevented) console.log('  ✔ non-Enter keydown is not cancelled (regression guard)')

  console.log(failed ? '\n✖ BROWSER TYPING FAILED\n' : '\n✔ BROWSER TYPING PASSED — real keystrokes land in both chat boxes\n')
} finally {
  await browser.close(); server.close()
}
process.exit(failed ? 1 : 0)
