import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

// A `tunnel serve` daemon that receives SIGTERM/SIGINT/SIGHUP must EXIT, not merely mark itself stopped.
// 2026-09-13: on v0.3.7 the handlers ran shutdown() (state.stopped + owner release) and set process.exitCode,
// then the process lingered for good on the relay's WebSocket — systemd stop hit its 90 s TimeoutStopSec and
// lm-tunnels relaunch needed SIGKILL. The `stop` verb path already calls process.exit(); signals now do the same.
const bin = fileURLToPath(new URL('../bin/p2p.js', import.meta.url))
const run = (home, args, timeout = 15000) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, [bin, 'tunnel', ...args], { env: { ...process.env, P2P_HOME: home, P2P_RENDEZVOUS_DIR: '' }, stdio: ['ignore', 'pipe', 'pipe'] })
  let out = '', err = ''
  child.stdout.on('data', d => { out += d }); child.stderr.on('data', d => { err += d })
  const timer = setTimeout(() => { child.kill(); reject(new Error('CLI timeout: ' + args.join(' ') + '\n' + out + err)) }, timeout)
  child.on('error', reject)
  child.on('exit', code => { clearTimeout(timer); resolve({ code, out, err }) })
})
const state = (home, name) => {
  const root = join(home, 'tunnel', name), { id } = JSON.parse(readFileSync(join(root, 'current.json')))
  return JSON.parse(readFileSync(join(root, id, 'state.json')))
}
const alive = pid => { try { process.kill(pid, 0); return true } catch { return false } }
const sleep = ms => new Promise(r => setTimeout(r, ms))

for (const [signal, code] of [['SIGTERM', 143], ['SIGINT', 130], ['SIGHUP', 129]]) {
  test(`tunnel serve exits within 3 s of ${signal} (state.stopped written, code ${code})`, { timeout: 40000 }, async () => {
    const home = mkdtempSync(join(tmpdir(), 'p2p-signal-'))
    try {
      const started = await run(home, ['listen', '--name', 'sig', '--profile', 'tunnel-sig'])
      assert.equal(started.code, 0, started.err)
      const { pid } = state(home, 'sig')
      assert.ok(alive(pid), 'daemon is running before the signal')
      await sleep(3000)   // the linger needs the relay WebSocket OPEN (close() then awaits a close handshake); signalled at once, even v0.3.7 exits
      process.kill(pid, signal)
      const t0 = Date.now()
      while (alive(pid) && Date.now() - t0 < 3000) await sleep(100)
      assert.ok(!alive(pid), `daemon still alive 3 s after ${signal} (pid ${pid}) — the signal handler did not exit the process`)
      assert.ok(state(home, 'sig').stopped, 'shutdown ran: state.stopped stamped before exit')
    } finally { rmSync(home, { recursive: true, force: true }) }
  })
}
