// Embedded by render-join.mjs after the SHA-pinned installer succeeds.
// Only chat operations: local terminal permission is never requested or enabled here.
import { spawnSync } from 'node:child_process'
import { readdirSync, writeFileSync, unlinkSync, realpathSync, existsSync } from 'node:fs'
import { hostname, userInfo, platform, arch } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

async function main() {
const [key, home] = process.argv.slice(2)
const fail = (message, code = 2) => { throw Object.assign(new Error(message), { exitCode: code }) }
if (!/^0[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{25}$/.test(key || '')) fail('invalid listener key')
if (!home) fail('installation home is missing')
if (!process.versions.bun) fail('the selected runtime is not Bun')
// Windows temp/home paths can contain 8.3 aliases. Resolve the actual installed
// location before module loading and CLI launch, while preserving Unicode names.
let app
try { app = realpathSync(join(resolve(home), 'app')) }
catch (error) { fail('cannot locate the installed application: ' + error.message) }
let keyModule
const keyFile = join(app, 'src', 'key.js')
try { keyModule = await import(pathToFileURL(realpathSync(keyFile)).href) }
catch (error) { fail('cannot load the installed key validator (file exists: ' + existsSync(keyFile) + '): ' + error.message) }
try { keyModule.decodeKey(key) }
catch (error) { fail('listener key checksum is invalid: ' + error.message) }
const name = 'join-' + key
const bin = join(app, 'bin', 'p2p.js')
const env = { ...process.env, P2P_HOME: resolve(home) }
function cli(args, timeout = 45000) {
  const result = spawnSync(process.execPath, [bin, 'tunnel', ...args], {
    env, encoding: 'utf8', timeout, maxBuffer: 1024 * 1024,
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  })
  if (result.error) fail('CLI failed: ' + result.error.message, 3)
  return { code: result.status ?? 3, out: result.stdout || '', err: result.stderr || '' }
}
function status(sessionName) {
  const result = cli(['status', '--name', sessionName], 15000)
  if (result.code === 5) return null
  if (result.code !== 0) fail('cannot inspect session ' + sessionName + ': ' + result.err, result.code)
  try { return JSON.parse(result.out) } catch { fail('invalid daemon status for ' + sessionName, 3) }
}

// Reuse an existing authenticated connection, including one made by the older
// two-command prompt. A rerun must not replace its identity or start a second peer.
let names = []
try { names = readdirSync(join(home, 'tunnel'), { withFileTypes: true })
  .filter(entry => entry.isDirectory() && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(entry.name)).map(entry => entry.name) }
catch (error) { if (error.code !== 'ENOENT') fail('cannot inspect existing tunnel sessions: ' + error.message, 3) }
if (names.length > 256) fail('too many local tunnel sessions; inspect them before joining', 2)
let selected = null
for (const candidate of [...new Set([name, 'default', ...names])]) {
  const state = status(candidate)
  if (!state?.alive) continue
  if (state.connected && state.peerKey === key) { selected = { name: candidate, state }; break }
  if (candidate === name) fail('this listener session already has a running daemon that is not connected to the requested peer; inspect it with p2p tunnel status --name ' + name, 2)
}

const clean = value => String(value).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 200)
let username = 'unknown'
try { username = userInfo().username } catch {}
const identity = 'connected: ' + clean(hostname()) + ' ' + clean(username) + '\n' +
  JSON.stringify({ MACHINE: clean(hostname()), USER: clean(username), OS: platform(), ARCH: arch(), AGENT: 'bootstrap', RUNTIME: 'bun ' + process.versions.bun })
if (!selected) {
  // --profile is essential: the CLI otherwise creates an ephemeral identity on
  // each fresh session, which an already-bound host would correctly reject.
  const result = cli(['join', key, '--name', name, '--profile', name,
    '--say', 'Agent Tunnel connected; machine identification follows.', '--connect-timeout', '30'])
  if (result.code !== 0) fail(result.err.trim() || result.out.trim() || 'connection failed; the listener may be offline or already paired with another machine', result.code)
  const state = status(name)
  if (!state?.alive || !state.connected || state.peerKey !== key) fail('the requested peer did not become connected', 3)
  selected = { name, state }
}
// --file avoids PowerShell native argv quoting and never treats machine metadata
// or remote messages as shell syntax. Wait for a delivery acknowledgment.
const messageFile = join(resolve(home), '.join-' + process.pid + '-' + Date.now() + '.txt')
try {
  writeFileSync(messageFile, identity, { mode: 0o600, flag: 'wx' })
  const result = cli(['send', '--file', messageFile, '--name', selected.name, '--wait', '10'], 15000)
  if (result.code !== 0) fail('connected, but machine identification was not acknowledged; rerun to retry. ' + result.err.trim(), result.code)
} finally { try { unlinkSync(messageFile) } catch {} }
console.log('Agent Tunnel connected to ' + key + ' as ' + selected.state.self + '.')
console.log('Chat daemon is running in the background (PID ' + selected.state.pid + '). It does not start automatically after a reboot.')
console.log('Status: p2p tunnel status --name ' + selected.name)
console.log('Messages: p2p tunnel recv --name ' + selected.name + ' --wait 60')
console.log('Stop: p2p tunnel stop --name ' + selected.name)
console.log('Terminal activation is separate. This join line does not grant remote command execution.')
}
try { await main() } catch (error) { console.error('Agent Tunnel: ' + error.message); process.exitCode = error.exitCode || 3 }
