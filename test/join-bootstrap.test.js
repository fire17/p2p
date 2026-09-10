import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { mkdtempSync, mkdirSync, cpSync, readFileSync, writeFileSync, existsSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateIdentity } from '../src/key.js'
import { renderJoin, INSTALLERS } from '../tools/render-join.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const cli = join(root, 'bin', 'p2p.js'), helper = join(root, 'tools', 'join-client.mjs')
const bun = process.env.P2P_TEST_BUN || (process.versions.bun ? process.execPath : null)
const run = (exe, args, env = {}, stdin = '', timeout = 55000) => new Promise((resolve, reject) => {
  const child = spawn(exe, args, { env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true })
  let out = '', err = ''
  const timer = setTimeout(() => { child.kill(); reject(new Error('join fixture timed out: ' + out + err)) }, timeout)
  child.stdout.on('data', chunk => { out += chunk }); child.stderr.on('data', chunk => { err += chunk })
  child.once('error', error => { clearTimeout(timer); reject(error) })
  child.once('close', code => { clearTimeout(timer); resolve({ code, out, err }) })
  child.stdin.end(stdin)
})
const command = (home, args, env = {}) => run(process.execPath, [cli, 'tunnel', ...args], { P2P_HOME: home, P2P_RENDEZVOUS_DIR: '', ...env })
const status = async (home, name) => {
  const result = await command(home, ['status', '--name', name])
  assert.equal(result.code, 0, result.out + result.err)
  return JSON.parse(result.out)
}
function installFixture(home) {
  mkdirSync(join(home, 'app'), { recursive: true })
  for (const entry of ['src', 'bin', 'package.json']) cpSync(join(root, entry), join(home, 'app', entry), { recursive: true })
}
async function fixture(fn) {
  const temp = mkdtempSync(join(tmpdir(), 'p2p join fixture ')), host = join(temp, 'host'), home = join(temp, 'client שלום with spaces'), board = join(temp, 'board')
  let key
  try {
    installFixture(home)
    const listening = await command(host, ['listen', '--name', 'host', '--profile', 'fixture-host', '--rendezvous-dir', board])
    assert.equal(listening.code, 0, listening.out + listening.err)
    key = (await status(host, 'host')).self
    await fn({ temp, host, home, key, env: { P2P_HOME: home, P2P_RENDEZVOUS_DIR: board } })
  } finally {
    if (key) await command(home, ['stop', '--name', 'join-' + key])
    await command(home, ['stop', '--name', 'default'])
    await command(host, ['stop', '--name', 'host'])
    rmSync(temp, { recursive: true, force: true })
  }
}

test('join route generation validates canonical keys and typo checksum before rendering', () => {
  const key = generateIdentity().S
  for (const invalid of ['', '../' + key, key.toLowerCase(), key + "';touch owned", key.slice(0, -1) + (key.endsWith('0') ? '1' : '0')]) {
    assert.throws(() => renderJoin(invalid, 'sh'))
    assert.throws(() => renderJoin(invalid, 'ps1'))
  }
  for (const platform of ['sh', 'ps1']) {
    const rendered = renderJoin(key, platform)
    assert.ok(rendered.includes(key))
    assert.ok(rendered.includes(INSTALLERS[platform].sha256))
    assert.equal(rendered.includes('@@'), false)
  }
})

test('join fixture runtime is available when CI requires it', () => {
  if (process.env.P2P_REQUIRE_JOIN_BUN === '1') assert.ok(bun, 'Set P2P_TEST_BUN to the installed official Bun executable')
  if (bun) assert.equal(spawnSync(bun, ['-e', "process.exit(process.versions.bun?0:1)"], { timeout: 15000 }).status, 0)
})

test('join helper: real encrypted connection, acknowledged identity, same-session rerun, stable restart, older default reuse', { skip: !bun, timeout: 90000 }, async () => {
  await fixture(async ({ host, home, key, env }) => {
    const launch = () => run(bun, [helper, key, home], env)
    let result = await launch()
    assert.equal(result.code, 0, result.out + result.err)
    assert.match(result.out, /Terminal activation is separate/)
    const first = await status(home, 'join-' + key)
    const messages = await command(host, ['recv', '--name', 'host', '--all'])
    const rows = messages.out.trim().split('\n').map(JSON.parse)
    const identity = rows.find(row => row.text.startsWith('connected: '))
    assert.ok(identity, messages.out + messages.err)
    assert.equal(identity.from, first.self)
    const details = JSON.parse(identity.text.split('\n')[1])
    assert.ok(details.MACHINE && details.USER && details.OS && details.ARCH)
    assert.equal(details.AGENT, 'bootstrap')
    assert.match(details.RUNTIME, /^bun /)
    assert.equal(readdirSync(home).some(name => name.startsWith('.join-')), false, 'identity staging file is removed')
    result = await launch()
    assert.equal(result.code, 0, result.out + result.err)
    const again = await status(home, 'join-' + key)
    assert.equal(again.pid, first.pid)
    assert.equal(again.id, first.id)
    assert.equal(again.self, first.self)
    assert.equal((await command(home, ['stop', '--name', 'join-' + key])).code, 0)
    result = await launch()
    assert.equal(result.code, 0, result.out + result.err)
    const restarted = await status(home, 'join-' + key)
    assert.notEqual(restarted.id, first.id)
    assert.equal(restarted.self, first.self, 'saved profile preserves the authenticated machine identity')
    assert.equal((await command(home, ['stop', '--name', 'join-' + key])).code, 0)
    result = await command(home, ['join', key, '--profile', 'join-' + key, '--say', 'older prompt', '--connect-timeout', '5'], env)
    assert.equal(result.code, 0, result.out + result.err)
    const older = await status(home, 'default')
    result = await launch()
    assert.equal(result.code, 0, result.out + result.err)
    assert.match(result.out, /--name default/)
    assert.equal((await status(home, 'default')).pid, older.pid)
    assert.equal(existsSync(join(older.dir, 'term-owner.lock')), false)
  })
})

const shells = []
if (process.platform !== 'win32') shells.push({ label: 'POSIX sh', exe: '/bin/sh', args: [], platform: 'sh' })
for (const exe of process.platform === 'win32' ? ['powershell.exe', 'pwsh'] : ['pwsh']) {
  const found = spawnSync(exe, ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.ToString()'], { encoding: 'utf8', timeout: 45000 })
  if (process.env.P2P_REQUIRE_WINDOWS_SHELLS === '1') {
    assert.equal(process.platform, 'win32', 'Required Windows shells must run on actual Windows')
    assert.match(found.stdout || '', exe === 'powershell.exe' ? /^5\.1\./ : /^7\./, exe + ' version requirement')
  }
  if (found.status === 0) shells.push({ label: exe, exe, args: ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Invoke-Expression ([Console]::In.ReadToEnd())'], platform: 'ps1' })
  else if (process.env.P2P_REQUIRE_WINDOWS_SHELLS === '1') throw new Error('Required Windows shell is unavailable: ' + exe + ': ' + (found.error || found.stderr))
}

for (const shell of shells) test(`join bootstrap ${shell.label}: HTTP integrity gate, actual Bun/chat, rerun, child failure`, { skip: !bun, timeout: 90000 }, async () => {
  await fixture(async ({ temp, home, key, env }) => {
    const marker = join(temp, 'installer-executed')
    const installer = shell.platform === 'sh'
      ? '#!/bin/sh\nset -eu\nprintf yes > "$P2P_JOIN_FIXTURE_MARKER"\nif [ "${P2P_JOIN_FIXTURE_FAIL:-0}" = 1 ]; then exit 7; fi\nprintf bun > "$P2P_HOME/runtime.kind"\nprintf "%s" "$P2P_TEST_BUN" > "$P2P_HOME/runtime.path"\n'
      : "$ErrorActionPreference='Stop'\n[IO.File]::WriteAllText($env:P2P_JOIN_FIXTURE_MARKER,'yes')\nif($env:P2P_JOIN_FIXTURE_FAIL -eq '1') { exit 7 }\n[IO.File]::WriteAllText((Join-Path $env:P2P_HOME 'runtime.kind'),'bun')\n[IO.File]::WriteAllText((Join-Path $env:P2P_HOME 'runtime.path'),$env:P2P_TEST_BUN,(New-Object Text.UTF8Encoding($false)))\n"
    let servedScript = ''
    const server = createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'application/octet-stream' }); res.end(req.url.startsWith('/join/') ? servedScript : installer) })
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
    const url = 'http://127.0.0.1:' + server.address().port + '/init'
    const sha256 = createHash('sha256').update(installer).digest('hex')
    const fixtureEnv = { ...env, P2P_TEST_BUN: bun, P2P_JOIN_FIXTURE_MARKER: marker, P2P_REF: 'fixture-original', TMPDIR: temp, TEMP: temp, TMP: temp }
    const entryUrl = 'http://127.0.0.1:' + server.address().port + '/join/' + key + (shell.platform === 'ps1' ? '.ps1' : '')
    const invoke = async (script, extraEnv = {}) => {
      servedScript = script
      const args = shell.platform === 'sh' ? ['-c', "curl -fsSL '" + entryUrl + "' | sh"]
        : ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', "$PSNativeCommandUseErrorActionPreference=$true; try { irm '" + entryUrl + "' | iex } finally { if($env:P2P_REF -ne 'fixture-original') { throw 'Caller environment was not restored' } }"]
      return run(shell.exe, args, { ...fixtureEnv, ...extraEnv })
    }
    try {
      const bad = renderJoin(key, shell.platform, { url, sha256: '0'.repeat(64) })
      let result = await invoke(bad)
      assert.notEqual(result.code, 0, result.out + result.err)
      assert.match(result.err + result.out, /SHA256 mismatch/)
      assert.equal(existsSync(marker), false, 'unverified installer must never execute')
      const good = renderJoin(key, shell.platform, { url, sha256 })
      result = await invoke(good)
      assert.equal(result.code, 0, result.out + result.err)
      assert.ok(existsSync(marker))
      const first = await status(home, 'join-' + key)
      result = await invoke(good)
      assert.equal(result.code, 0, result.out + result.err)
      assert.equal((await status(home, 'join-' + key)).pid, first.pid)
      result = await invoke(good, { P2P_JOIN_FIXTURE_FAIL: '1' })
      assert.notEqual(result.code, 0, result.out + result.err)
      assert.equal((await status(home, 'join-' + key)).pid, first.pid, 'installer failure preserves the active daemon')
      assert.equal(readdirSync(temp).some(name => name.startsWith('p2p-join.')), false)
      assert.equal(readdirSync(temp).some(name => name.startsWith('p2p-join-')), false)
    } finally { await new Promise(resolve => server.close(resolve)) }
  })
})
