import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { mkdtempSync, mkdirSync, cpSync, readFileSync, writeFileSync, existsSync, readdirSync, rmSync, realpathSync, openSync, closeSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname, isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateIdentity } from '../src/key.js'
import { renderJoin, INSTALLERS } from '../tools/render-join.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const cli = join(root, 'bin', 'p2p.js'), helper = join(root, 'tools', 'join-client.mjs')
const requestedBun = process.env.P2P_TEST_BUN || (process.versions.bun ? process.execPath : null)
// CI may supply the PATH command `bun`. runtime.path is the real installer's
// absolute executable pin, so the minimal installer fixture must write one too.
let bun = null
if (requestedBun) {
  const probe = spawnSync(requestedBun, ['-e', 'process.stdout.write(JSON.stringify({bun:process.versions.bun,path:process.execPath}))'], { encoding: 'utf8', timeout: 15000 })
  assert.equal(probe.status, 0, 'Cannot resolve the requested Bun executable: ' + (probe.error || probe.stderr))
  const info = JSON.parse(probe.stdout)
  assert.ok(info.bun && isAbsolute(info.path) && existsSync(info.path), 'The fixture requires an actual Bun executable with an absolute path')
  bun = info.path
}
const run = (exe, args, env = {}, stdin = '', timeout = 55000, outputFiles = null) => new Promise((resolve, reject) => {
  const childEnv = { ...process.env, ...env }
  // PowerShell sanitizes module paths for direct PS5 children, but that does not
  // survive CI's pwsh -> Node -> PS5 chain (PowerShell/PowerShell#27774). Let this
  // isolated PS5 child construct its native defaults; never alter the caller.
  if (process.platform === 'win32' && /(?:^|[\\/])powershell\.exe$/i.test(exe)) {
    for (const key of Object.keys(childEnv)) if (key.toUpperCase() === 'PSMODULEPATH') delete childEnv[key]
  }
  // PS5's .NET child launch may leave the parent's stdout handle inherited by
  // a detached daemon, even after PS5 has returned and exited successfully.
  // Capture this invocation in owned files: command completion still requires
  // the actual child exit, while output never depends on the daemon's pipe EOF.
  let child
  const handles = []
  try {
    if (outputFiles) for (const file of outputFiles) handles.push(openSync(file, 'wx'))
    child = spawn(exe, args, { env: childEnv, stdio: outputFiles ? ['pipe', ...handles] : ['pipe', 'pipe', 'pipe'], windowsHide: true })
  } finally { for (const fd of handles) closeSync(fd) }
  const captured = () => outputFiles
    ? { out: readFileSync(outputFiles[0], 'utf8'), err: readFileSync(outputFiles[1], 'utf8') }
    : { out, err }
  let out = '', err = '', processExit = null
  child.once('exit', (code, signal) => { processExit = { code, signal } })
  const timer = setTimeout(() => {
    const state = { processExit, stdoutEnded: child.stdout?.readableEnded, stderrEnded: child.stderr?.readableEnded }
    const output = captured()
    child.kill(); reject(new Error('join fixture timed out ' + JSON.stringify(state) + ': ' + output.out + output.err))
  }, timeout)
  child.stdout?.on('data', chunk => { out += chunk }); child.stderr?.on('data', chunk => { err += chunk })
  child.once('error', error => { clearTimeout(timer); reject(error) })
  child.once('close', code => { clearTimeout(timer); resolve({ code, ...captured() }) })
  child.stdin.end(stdin)
})
const command = (home, args, env = {}) => run(process.execPath, [cli, 'tunnel', ...args], { P2P_HOME: home, P2P_RENDEZVOUS_DIR: '', ...env })
const status = async (home, name) => {
  const result = await command(home, ['status', '--name', name])
  assert.equal(result.code, 0, result.out + result.err)
  return JSON.parse(result.out)
}
function installFixture(home, physicalHome) {
  mkdirSync(join(home, 'app'), { recursive: true })
  // Node22's native cpSync fast path can silently skip Unicode destinations
  // (nodejs/node#61878). A filter selects its Unicode-safe JS traversal.
  for (const entry of ['src', 'bin', 'package.json']) cpSync(join(root, entry), join(home, 'app', entry), { recursive: true, filter: () => true })
  for (const file of ['src/key.js', 'bin/p2p.js', 'package.json']) {
    assert.deepEqual(readFileSync(join(home, 'app', file)), readFileSync(join(root, file)), 'Installed fixture bytes: ' + file)
    assert.deepEqual(readFileSync(join(physicalHome, 'app', file)), readFileSync(join(root, file)), 'Canonical temporary-path bytes: ' + file)
  }
}
async function fixture(fn) {
  // Keep the original Windows TEMP alias and Hebrew/space suffix as the actual
  // installation input; independently verify bytes through the physical path.
  const temp = mkdtempSync(join(tmpdir(), 'p2p join fixture '))
  const host = join(temp, 'host'), home = join(temp, 'client שלום with spaces'), physicalHome = join(realpathSync.native(temp), 'client שלום with spaces'), board = join(temp, 'board')
  let key
  try {
    installFixture(home, physicalHome)
    const listening = await command(host, ['listen', '--name', 'host', '--profile', 'fixture-host', '--rendezvous-dir', board])
    assert.equal(listening.code, 0, listening.out + listening.err)
    key = (await status(host, 'host')).self
    await fn({ temp, host, home, physicalHome, key, env: { P2P_HOME: home, P2P_RENDEZVOUS_DIR: board } })
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
  await fixture(async ({ temp, host, home, physicalHome, key, env }) => {
    const launch = () => run(bun, [helper, key, home], env)
    let result = await launch()
    if (result.code !== 0 && process.platform === 'win32') {
      // Capture loader-vs-filesystem evidence on the actual Windows runner. This
      // is diagnostic only: neither production nor the test retries a failed join.
      const probe = join(temp, 'module-diagnostic.mjs')
      writeFileSync(probe, "import {readFileSync,realpathSync,readdirSync} from 'node:fs';import {dirname} from 'node:path';import {pathToFileURL} from 'node:url';const reports=[];for(const file of process.argv.slice(2)){const r={file,nativeSame:realpathSync.native===realpathSync};try{r.appNative=realpathSync.native(dirname(dirname(file)))}catch(e){r.nativeError=e.message}try{r.parent=readdirSync(dirname(file));r.bytes=readFileSync(file).length;r.realpath=realpathSync(file);for(const [kind,spec] of [['fileURL',pathToFileURL(r.realpath).href],['filesystem',r.realpath]]){try{r[kind]=typeof(await import(spec)).decodeKey}catch(e){r[kind]=e.message}}}catch(e){r.fsError=e.message}reports.push(r)}console.log(JSON.stringify(reports))\n")
      const keyFile = join(home, 'app', 'src', 'key.js'), physical = realpathSync.native(keyFile)
      const evidence = await run(bun, [probe, keyFile, physical, join(physicalHome, 'app', 'src', 'key.js')], env)
      result.err += '\nWindows Node fixture: ' + JSON.stringify({ physical, bytes: readFileSync(keyFile).length, app: readdirSync(join(home, 'app')), src: readdirSync(join(home, 'app', 'src')) })
      result.err += '\nWindows Bun module diagnostics: ' + evidence.out + evidence.err
    }
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
    let invocation = 0
    const invoke = async (script, extraEnv = {}, callerExit = null) => {
      servedScript = script
      const expression = "try { irm '" + entryUrl + "' | iex; Write-Output 'JOIN_FIXTURE_RETURNED' } finally { if($env:P2P_REF -ne 'fixture-original') { throw 'Caller environment was not restored' } }"
      const psCommand = callerExit === null ? '$PSNativeCommandUseErrorActionPreference=$true; ' + expression
        : 'function Invoke-JoinFixture { $LASTEXITCODE=' + callerExit + '; $PSNativeCommandUseErrorActionPreference=$false; try { ' + expression + ' } finally { Write-Output "CALLER_EXIT=$LASTEXITCODE GLOBAL_EXIT=$global:LASTEXITCODE" } }; Invoke-JoinFixture'
      const args = shell.platform === 'sh' ? ['-c', "curl -fsSL '" + entryUrl + "' | sh"]
        : ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', psCommand]
      const capture = shell.platform === 'ps1'
        ? ['stdout', 'stderr'].map(stream => join(temp, 'ps-' + invocation + '-' + stream + '.txt')) : null
      invocation++
      return run(shell.exe, args, { ...fixtureEnv, ...extraEnv }, '', 55000, capture)
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
      if (shell.platform === 'ps1') assert.match(result.out, /JOIN_FIXTURE_RETURNED/, 'The owner shell must return from the bootstrap')
      const first = await status(home, 'join-' + key)
      result = await invoke(good)
      assert.equal(result.code, 0, result.out + result.err)
      assert.equal((await status(home, 'join-' + key)).pid, first.pid)
      result = await invoke(good, { P2P_JOIN_FIXTURE_FAIL: '1' })
      assert.notEqual(result.code, 0, result.out + result.err)
      assert.equal((await status(home, 'join-' + key)).pid, first.pid, 'installer failure preserves the active daemon')
      if (shell.platform === 'ps1') {
        result = await invoke(good, { P2P_JOIN_FIXTURE_FAIL: '1' }, 0)
        assert.notEqual(result.code, 0, result.out + result.err)
        assert.match(result.err + result.out, /Verified installer failed \(exit 7\)/)
        assert.match(result.out, /CALLER_EXIT=0 GLOBAL_EXIT=7/)
        const validator = join(home, 'app', 'src', 'key.js'), original = readFileSync(validator)
        try {
          writeFileSync(validator, "throw new Error('fixture-helper-failure')\n")
          result = await invoke(good, {}, 0)
          assert.notEqual(result.code, 0, result.out + result.err)
          assert.match(result.err + result.out, /Agent Tunnel join failed \(exit 2\)/)
          assert.match(result.out, /CALLER_EXIT=0 GLOBAL_EXIT=2/)
        } finally { writeFileSync(validator, original) }
        result = await invoke(good, {}, 7)
        assert.equal(result.code, 0, result.out + result.err)
        assert.match(result.out, /CALLER_EXIT=7 GLOBAL_EXIT=0/)
        assert.equal((await status(home, 'join-' + key)).pid, first.pid)
      }
      assert.equal(readdirSync(temp).some(name => name.startsWith('p2p-join.')), false)
      assert.equal(readdirSync(temp).some(name => name.startsWith('p2p-join-')), false)
    } finally { await new Promise(resolve => server.close(resolve)) }
  })
})
