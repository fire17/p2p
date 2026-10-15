// Windows PowerShell 5.1 reads a BOM-less `-File` script (the join line runs the
// hash-pinned init.ps1 that way) and a charset-less `irm` body as ANSI/Latin-1:
// UTF-8 punctuation turns into smart quotes and the script stops parsing.
// Every PowerShell script this repository ships must therefore be pure ASCII.
// The PowerShell-side parse gate (cp1252/cp1255 + the real 5.1 loader) is test/ps1-encoding.ps1.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateIdentity } from '../src/key.js'
import { renderJoin } from '../tools/render-join.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const scripts = []
const walk = dir => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue
    const path = join(dir, entry.name)
    if (entry.isDirectory()) walk(path)
    else if (/\.ps1(\.in)?$/.test(entry.name)) scripts.push(path)
  }
}
walk(root)

test('every shipped PowerShell script is pure ASCII', () => {
  for (const required of ['init.ps1', 'join.ps1', 'tools/join-bootstrap.ps1.in']) {
    assert.ok(scripts.some(path => relative(root, path).split('\\').join('/') === required), 'missing ' + required)
  }
  for (const path of scripts) {
    const bytes = readFileSync(path)
    const at = bytes.findIndex(byte => byte > 0x7f)
    const line = at < 0 ? 0 : bytes.subarray(0, at).toString('latin1').split('\n').length
    assert.equal(at, -1, relative(root, path) + ': non-ASCII byte on line ' + line)
  }
})

test('the per-key PowerShell renderer emits pure ASCII', () => {
  const rendered = renderJoin(generateIdentity().S, 'ps1')
  assert.match(rendered, /^[\x00-\x7f]*$/)
  assert.ok(rendered.includes('\\u2713'), 'the helper keeps its check mark as a JS escape')
})
