// Cross-runtime proof: two real, detached CLI daemons, using disposable homes and
// loopback discovery. Run with P2P_TEST_BUN=/absolute/path/to/bun node --test ...
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const bin = fileURLToPath(new URL('../bin/p2p.js', import.meta.url))
const bun = process.env.P2P_TEST_BUN
const node = process.env.P2P_TEST_NODE || process.execPath
const rows = text => text.trim().split('\n').filter(Boolean).map(JSON.parse)
function cli(runtime, home, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(runtime, [bin, 'tunnel', ...args], {
      env: { ...process.env, P2P_HOME: home, P2P_RENDEZVOUS_DIR: '' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let out = '', err = ''
    child.stdout.on('data', b => { out += b })
    child.stderr.on('data', b => { err += b })
    const timer = setTimeout(() => { child.kill(); reject(new Error(`timeout: ${runtime} ${args[0]}\n${out}${err}`)) }, 15000)
    child.on('error', error => { clearTimeout(timer); reject(error) })
    child.on('exit', code => { clearTimeout(timer); resolve({ code, out, err }) })
  })
}
function state(home) {
  const root = join(home, 'tunnel', 'default')
  const { id } = JSON.parse(readFileSync(join(root, 'current.json')))
  return JSON.parse(readFileSync(join(root, id, 'state.json')))
}

for (const hostIsBun of [false, true]) {
  test(`detached tunnel: ${hostIsBun ? 'Bun host / Node peer' : 'Node host / Bun peer'}`, { skip: !bun, timeout: 45000 }, async () => {
    const root = mkdtempSync(join(tmpdir(), 'p2p-runtime-interop-'))
    const host = join(root, 'host'), peer = join(root, 'peer'), board = join(root, 'board')
    const hostRuntime = hostIsBun ? bun : node, peerRuntime = hostIsBun ? node : bun
    const run = async (runtime, home, args) => {
      const result = await cli(runtime, home, args)
      assert.equal(result.code, 0, `${runtime} ${args[0]}: ${result.out}${result.err}`)
      return result.out
    }
    try {
      const invitation = await run(hostRuntime, host, ['invite', '--ephemeral', '--rendezvous-dir', board])
      const share = invitation.match(/tunnel join ([A-Z0-9]+-[A-Z0-9]+)/i)?.[1]
      assert.ok(share, invitation)
      const hello = 'Bun ↔ Node: שלום 🌻'
      await run(peerRuntime, peer, ['join', share, '--say', hello, '--rendezvous-dir', board, '--connect-timeout', '5'])
      const first = rows(await run(hostRuntime, host, ['recv', '--wait', '5']))[0]
      assert.equal(first.text, hello)
      assert.equal(first.from, state(peer).self)
      const reply = 'cross-runtime \\ " \n 🌻 שלום '.repeat(1000)
      const delivery = rows(await run(hostRuntime, host, ['send', reply, '--wait', '5'])).at(-1)
      assert.equal(delivery.delivered, true)
      const received = rows(await run(peerRuntime, peer, ['recv', '--wait', '5']))[0]
      assert.equal(received.text, reply)
      assert.equal(received.from, state(host).self)
    } finally {
      await Promise.all([cli(hostRuntime, host, ['stop']), cli(peerRuntime, peer, ['stop'])])
      rmSync(root, { recursive: true, force: true })
    }
  })
}
