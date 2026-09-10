// POSIX installer + actual portable Bun bootstrap; no global runtime/profile edits.
// Supply P2P_TEST_BUN and optionally P2P_TEST_BUN_ARCHIVE (the official host ZIP).
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, copyFileSync, symlinkSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname, basename } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createHash } from 'node:crypto'

const repo = fileURLToPath(new URL('..', import.meta.url))
const bun = process.env.P2P_TEST_BUN
const archive = process.env.P2P_TEST_BUN_ARCHIVE
const posix = process.platform !== 'win32'
function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'p2p bun installer '))
  const source = join(root, 'source'), home = join(root, 'state'), bin = join(root, 'bin')
  mkdirSync(join(source, 'bin'), { recursive: true })
  mkdirSync(bin, { recursive: true })
  writeFileSync(join(source, 'package.json'), JSON.stringify({ name: 'installer-runtime-fixture', version: '0.0.1', type: 'module' }))
  writeFileSync(join(source, 'bin', 'p2p.js'), 'console.log(JSON.stringify({bun:process.versions.bun||null,args:process.argv.slice(2)}))\n')
  const env = { ...process.env, PATH: `${bin}:${dirname(bun)}:${process.env.PATH}`, P2P_HOME: home, P2P_BIN_DIR: bin,
    P2P_SRC: source, P2P_RUNTIME: 'bun', P2P_FORCE_BUN_BOOTSTRAP: '0', P2P_BUN_DIST: 'file:///network-disabled', P2P_NODE_DIST: 'file:///node-must-not-be-downloaded' }
  return { root, home, source, bin, env }
}
function install(f) {
  return spawnSync('sh', [join(repo, 'init')], { env: f.env, encoding: 'utf8', timeout: 60000 })
}
function verifyShim(f) {
  assert.equal(readFileSync(join(f.home, 'runtime.kind'), 'utf8').trim(), 'bun')
  // A stale Node runtime must not override the selected Bun runtime.
  mkdirSync(join(f.home, 'runtime', 'bin'), { recursive: true })
  symlinkSync(process.execPath, join(f.home, 'runtime', 'bin', 'node'))
  const args = ['hello with spaces', 'שלום 🌻', '"quoted"', 'back\\slash']
  const result = spawnSync(join(f.bin, 'p2p'), args, { env: f.env, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  const observed = JSON.parse(result.stdout)
  assert.ok(observed.bun, 'generated shim must really execute Bun')
  assert.deepEqual(observed.args, args)
  writeFileSync(join(f.home, 'runtime.path'), join(f.root, 'missing runtime') + '\n')
  const missing = spawnSync(join(f.bin, 'p2p'), [], { env: f.env, encoding: 'utf8' })
  assert.notEqual(missing.status, 0)
  assert.match(missing.stderr, /selected runtime is missing/)
}

test('Bun installer: discover existing Bun, preserve arguments, and refuse silent Node fallback', { skip: !posix || !bun }, () => {
  const f = fixture()
  try {
    const result = install(f)
    assert.equal(result.status, 0, result.stdout + result.stderr)
    delete f.env.P2P_RUNTIME
    const update = install(f)
    assert.equal(update.status, 0, update.stdout + update.stderr)
    assert.equal(readFileSync(join(f.home, 'runtime.kind'), 'utf8').trim(), 'bun', 'later installs retain the selected Bun runtime')
    verifyShim(f)
    assert.equal(existsSync(join(f.home, 'bun-runtime')), false, 'existing Bun needs no bootstrap')
  } finally { rmSync(f.root, { recursive: true, force: true }) }
})

test('Bun installer: bootstrap the actual portable runtime only after a matching SHA256', { skip: !posix || !bun || !archive, timeout: 90000 }, () => {
  const f = fixture()
  try {
    const dist = join(f.root, 'dist')
    mkdirSync(dist)
    const name = basename(archive).replace(/^bun-1\.4\.2-/, 'bun-')
    copyFileSync(archive, join(dist, name))
    const sum = createHash('sha256').update(readFileSync(archive)).digest('hex')
    writeFileSync(join(dist, 'SHASUMS256.txt'), `${sum}  ${name}\n`)
    f.env.P2P_FORCE_BUN_BOOTSTRAP = '1'
    f.env.P2P_BUN_DIST = pathToFileURL(dist).href
    const good = install(f)
    assert.equal(good.status, 0, good.stdout + good.stderr)
    assert.equal(readFileSync(join(f.home, 'runtime.path'), 'utf8').trim(), join(f.home, 'bun-runtime', 'bun'))
    verifyShim(f)
    // Repeat into a fresh installation with a false manifest: no app/runtime runs.
    f.home = join(f.root, 'refused state')
    f.env.P2P_HOME = f.home
    writeFileSync(join(dist, 'SHASUMS256.txt'), `${'0'.repeat(64)}  ${name}\n`)
    const bad = install(f)
    assert.notEqual(bad.status, 0)
    assert.match(bad.stdout + bad.stderr, /Bun checksum MISMATCH/)
    assert.equal(existsSync(join(f.home, 'app')), false)
    assert.equal(existsSync(join(f.home, 'bun-runtime')), false)
    assert.equal(existsSync(join(f.home, 'runtime.kind')), false)
  } finally { rmSync(f.root, { recursive: true, force: true }) }
})
