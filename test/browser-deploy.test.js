// test/browser-deploy.test.js — the app that CI tests must be the app the browser can actually LOAD.
//
// The bug this exists for: GitHub Pages runs Jekyll, and Jekyll silently drops every `_`-prefixed
// file. Our vendored noble imports ./_arx.js, ./_poly1305.js, ./_md.js, ./_u64.js — so those four
// 404'd on the live site, the ES module graph failed to resolve, app.js never evaluated, and the page
// sat on "booting…" forever with no error anywhere but the console. Every unit test still passed:
// Node resolved the files from disk, and nothing in the suite ever asked what the SERVER would return.
//
// So this test walks the REAL module graph the browser walks — from app/index.html's module entry,
// through the import map, across every relative import — and asserts the three things that decide
// whether that graph can load at all:
//   1. every module in it exists,
//   2. nothing in it is unservable by our host (Jekyll's `_` rule ⇒ .nojekyll must exist),
//   3. every BARE specifier in it is resolvable by the import map (the browser has no node_modules).
// Plus: the boot guard is wired, so a future load failure SAYS so instead of lying "booting…".

import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const html = fs.readFileSync(path.join(ROOT, 'app/index.html'), 'utf8')

const importMap = JSON.parse(html.match(/<script type="importmap">([\s\S]*?)<\/script>/)[1]).imports
const entry = html.match(/<script type="module" src="([^"]+)"/)[1]

/** Resolve a specifier the way the browser will: import map for bare, path-relative otherwise. */
function resolve(spec, fromAbs) {
  if (spec.startsWith('.')) return path.resolve(path.dirname(fromAbs), spec)
  if (spec.startsWith('/')) return path.join(ROOT, spec)
  const mapped = importMap[spec]
  if (!mapped) return { unmapped: spec } // a bare specifier with no import-map entry — fatal in a browser
  return path.join(ROOT, mapped)
}

/** The whole module graph the browser fetches, starting at index.html's entry point. */
function graph() {
  const seen = new Set()
  const unmapped = []
  const missing = []
  const walk = (abs) => {
    if (seen.has(abs)) return
    seen.add(abs)
    if (!fs.existsSync(abs)) { missing.push(abs); return }
    const src = fs.readFileSync(abs, 'utf8')
    // static `… from '<spec>'` (import and re-export) — the only forms this codebase uses.
    for (const m of src.matchAll(/(?:^|\n)\s*(?:import|export)[\s\S]{0,300}?\sfrom\s+['"]([^'"]+)['"]/g)) {
      const r = resolve(m[1], abs)
      if (r.unmapped) { unmapped.push({ spec: r.unmapped, from: abs }); continue }
      walk(r)
    }
  }
  walk(path.join(ROOT, entry))
  return { files: [...seen], unmapped, missing }
}

test('the browser module graph resolves completely (no missing file, no unmapped bare specifier)', () => {
  const g = graph()
  assert.deepEqual(g.missing.map((f) => path.relative(ROOT, f)), [], 'a module the browser imports does not exist')
  assert.deepEqual(
    g.unmapped.map((u) => `${u.spec} (from ${path.relative(ROOT, u.from)})`),
    [],
    'a BARE specifier is not in the import map — the browser cannot resolve it, and the whole graph dies',
  )
  assert.ok(g.files.length > 10, 'graph walk found suspiciously few modules — the walker is broken')
})

test('every module in the graph is SERVABLE by GitHub Pages (Jekyll drops `_`-prefixed paths)', () => {
  const { files } = graph()
  const underscored = files
    .map((f) => path.relative(ROOT, f))
    .filter((rel) => rel.split(path.sep).some((seg) => seg.startsWith('_')))

  if (underscored.length) {
    // Jekyll treats `_x` as its own internals and does not publish them: they 404, the module graph
    // fails, and the app hangs on "booting…". `.nojekyll` turns Jekyll off — that is the whole fix.
    assert.ok(
      fs.existsSync(path.join(ROOT, '.nojekyll')),
      `the module graph imports \`_\`-prefixed files that GitHub Pages/Jekyll will NOT serve `
      + `(${underscored.join(', ')}) — a \`.nojekyll\` file at the repo root is required, and is missing`,
    )
  }
})

test('the boot guard is wired, and the import-map CSP hash still matches the map', () => {
  assert.match(html, /<script src="\/app\/boot-guard\.js"><\/script>/, 'boot-guard.js must load, or a boot failure is silent')
  // Compare the TAGS, not the first mention of each path — both files are named in the comments above.
  assert.ok(
    html.indexOf('<script src="/app/boot-guard.js">') < html.indexOf('<script type="module"'),
    'the guard must load BEFORE the module it guards',
  )
  assert.ok(fs.existsSync(path.join(ROOT, 'app/boot-guard.js')), 'app/boot-guard.js is referenced but does not exist')
  assert.doesNotMatch(fs.readFileSync(path.join(ROOT, 'app/boot-guard.js'), 'utf8'), /^\s*import\s/m,
    'the boot guard must not import anything — a failed import is exactly what it exists to report')

  // The CSP allows the inline import map by hash. If the map is edited without recomputing the hash,
  // the browser blocks it, `node:crypto` becomes unresolvable, and we are back to a silent dead app.
  const map = html.match(/<script type="importmap">([\s\S]*?)<\/script>/)[1]
  const want = 'sha256-' + createHash('sha256').update(map).digest('base64')
  assert.ok(html.includes(`'${want}'`), `CSP script-src is missing the import map's hash (${want}) — recompute it`)
})
