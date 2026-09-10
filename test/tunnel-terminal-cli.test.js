// Actual encrypted loopback tunnel and real CLI client. The owner service is
// invoked directly only inside this disposable fixture; production CLI consent
// stays gated on the owner's local TTY, with no test/environment bypass.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, appendFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { serveTerminal } from '../src/tunnel-terminal-server.js'
import { readRows } from '../bin/p2p-tunnel.js'

const bin = fileURLToPath(new URL('../bin/p2p.js', import.meta.url))
const name = 'terminal-fixture'
function run(runtime, home, args, timeout = 15000) {
  return new Promise((resolve, reject) => {
    const child = spawn(runtime, [bin, 'tunnel', ...args, '--name', name], { env: { ...process.env, P2P_HOME: home, P2P_RENDEZVOUS_DIR: '' }, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = '', err = ''
    const timer = setTimeout(() => { child.kill(); reject(new Error('terminal CLI timeout: ' + out + err)) }, timeout)
    child.stdout.on('data', bytes => { out += bytes }); child.stderr.on('data', bytes => { err += bytes })
    child.once('error', error => { clearTimeout(timer); reject(error) })
    child.once('close', code => { clearTimeout(timer); resolve({ code, out, err }) })
  })
}
function state(home) {
  const root = join(home, 'tunnel', name), pointer = JSON.parse(readFileSync(join(root, 'current.json'), 'utf8'))
  const dir = join(root, pointer.id)
  return { dir, ...JSON.parse(readFileSync(join(dir, 'state.json'), 'utf8')) }
}
const rows = out => out.trim().split('\n').filter(Boolean).map(JSON.parse)
function command(script) {
  const quote = value => process.platform === 'win32' ? "'" + value.replaceAll("'", "''") + "'" : "'" + value.replaceAll("'", "'\\''") + "'"
  return (process.platform === 'win32' ? '& ' : '') + quote(process.execPath) + ' -e ' + quote(script)
}
const runtimes = [...new Set([process.execPath, process.env.P2P_TEST_BUN].filter(Boolean))]
for (const runtime of runtimes) {
  test(`terminal CLI: encrypted Node host / ${runtime === process.execPath ? 'Node' : 'Bun'} client exec, consent boundary, and simultaneous chat`, { timeout: 60000 }, async () => {
    const root = mkdtempSync(join(tmpdir(), 'p2p-terminal-encrypted-'))
    const host = join(root, 'host'), client = join(root, 'client'), board = join(root, 'board')
    const controller = new AbortController()
    let service
    try {
      const invite = await run(process.execPath, host, ['invite', '--ephemeral', '--rendezvous-dir', board])
      assert.equal(invite.code, 0, invite.out + invite.err)
      const share = invite.out.match(/tunnel join ([A-Z0-9]+-[A-Z0-9]+)/i)?.[1]
      assert.ok(share)
      const joined = await run(runtime, client, ['join', share, '--say', 'chat before terminal', '--rendezvous-dir', board, '--connect-timeout', '5'])
      assert.equal(joined.code, 0, joined.out + joined.err)
      const chatBefore = await run(process.execPath, host, ['recv', '--wait', '3'])
      assert.equal(rows(chatBefore.out)[0].text, 'chat before terminal')
      const forbidden = join(root, 'must-not-execute-before-consent')
      const absent = await run(runtime, client, ['exec', command(`require('node:fs').writeFileSync(${JSON.stringify(forbidden)},'bad')`), '--timeout', '0.2'])
      assert.equal(absent.code, 124, absent.out + absent.err)
      assert.equal(existsSync(forbidden), false)
      // The actual CLI must reject non-TTY owner enablement, even with a valid key.
      const nonOwner = await run(process.execPath, host, ['terminal', '--allow', state(client).self])
      assert.notEqual(nonOwner.code, 0)
      assert.match(nonOwner.err + nonOwner.out, /TTY|owner|local terminal/i)
      assert.equal(existsSync(join(state(host).dir, 'term-owner.lock')), false)

      const initial = state(host)
      let serviceReady, serviceError
      service = serveTerminal({ session: { dir: initial.dir, id: initial.id,
        requireLive: () => {
          const current = state(host)
          if (current.stopped || current.error) throw new Error('fixture tunnel stopped')
          process.kill(current.pid, 0)
          return current
        }, readRows, appendOutbox: row => appendFileSync(join(initial.dir, 'outbox.jsonl'), JSON.stringify(row) + '\n') },
        allowKey: state(client).self, shell: process.platform === 'win32' ? 'pwsh' : '/bin/sh', cwd: root,
        signal: controller.signal, io: { stdout: { write() {} } }, onReady: value => { serviceReady = value } })
      service.catch(error => { serviceError = error })
      const readyDeadline = Date.now() + 5000
      while (!serviceReady) {
        if (serviceError) throw serviceError
        if (Date.now() > readyDeadline) throw new Error('fixture owner service did not become ready')
        await new Promise(resolve => setTimeout(resolve, 10))
      }
      const executed = await run(runtime, client, ['exec', command("console.log('encrypted-terminal-proof');process.exit(6)"), '--timeout', '5'])
      assert.equal(executed.code, 6, executed.out + executed.err)
      const events = rows(executed.out)
      assert.ok(events.filter(event => event.type === 'data').map(event => event.text).join('').includes('encrypted-terminal-proof'))
      assert.equal(events.at(-1).code, 6)
      const sent = await run(runtime, client, ['send', 'chat while terminal remains enabled', '--wait', '3'])
      assert.equal(sent.code, 0, sent.out + sent.err)
      const received = await run(process.execPath, host, ['recv', '--wait', '3'])
      assert.equal(received.code, 0, received.out + received.err)
      assert.deepEqual(rows(received.out).map(row => row.text), ['chat while terminal remains enabled'])
      const history = await run(process.execPath, host, ['recv', '--all'])
      assert.deepEqual(rows(history.out).map(row => row.text), ['chat before terminal', 'chat while terminal remains enabled'])
      assert.equal(rows(history.out).some(row => row.channel === 'term'), false)
      const stop = await run(process.execPath, host, ['terminal', 'stop'])
      assert.equal(stop.code, 0, stop.out + stop.err)
      await service
      assert.equal((await run(process.execPath, host, ['status'])).code, 0, 'owner terminal stop leaves chat daemon alive')
      assert.equal((await run(runtime, client, ['status'])).code, 0)
    } finally {
      controller.abort()
      await service?.catch(() => {})
      await Promise.all([run(process.execPath, host, ['stop']), run(runtime, client, ['stop'])])
      rmSync(root, { recursive: true, force: true })
    }
  })
}
