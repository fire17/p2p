import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtempSync, mkdirSync, cpSync, readFileSync, writeFileSync, existsSync, renameSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateIdentity } from '../src/key.js'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const bun = process.env.P2P_TEST_BUN || (process.versions.bun ? process.execPath : null)
const cli = join(root, 'bin', 'p2p.js'), helper = join(root, 'tools', 'join-client.mjs')
const run = (exe, args, env) => new Promise((resolve, reject) => {
  const child = spawn(exe, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })
  let out = '', err = ''
  const timer = setTimeout(() => { child.kill(); reject(new Error('legacy fixture timed out')) }, 45000)
  child.stdout.on('data', bytes => { out += bytes }); child.stderr.on('data', bytes => { err += bytes })
  child.once('error', error => { clearTimeout(timer); reject(error) })
  child.once('close', code => { clearTimeout(timer); resolve({ code, out, err }) })
})

async function fixture(fn) {
  const temp = mkdtempSync(join(tmpdir(), 'p2p legacy fixture '))
  const home = join(temp, 'client שלום with spaces'), host = join(temp, 'host'), board = join(temp, 'board')
  const command = (base, args) => run(process.execPath, [cli, 'tunnel', ...args], { P2P_HOME: base, P2P_RENDEZVOUS_DIR: board })
  const state = async (base, name) => {
    const result = await command(base, ['status', '--name', name])
    assert.equal(result.code, 0, result.out + result.err)
    return JSON.parse(result.out)
  }
  let key, name
  try {
    mkdirSync(join(home, 'app'), { recursive: true })
    for (const entry of ['src', 'bin', 'package.json']) cpSync(join(root, entry), join(home, 'app', entry), { recursive: true })
    const listen = await command(host, ['listen', '--name', 'host', '--profile', 'legacy-fixture-host'])
    assert.equal(listen.code, 0, listen.out + listen.err)
    key = (await state(host, 'host')).self; name = 'join-' + key
    const launch = () => run(bun, [helper, key, home], { P2P_HOME: home, P2P_RENDEZVOUS_DIR: board })
    const legacy = async profile => {
      const result = await command(home, ['join', key, '--say', 'legacy fixture', '--connect-timeout', '5', ...(profile ? ['--profile', profile] : [])])
      assert.equal(result.code, 0, result.out + result.err)
      // Wait for acknowledged traffic, which distinguishes a real old pairing
      // from a later rejected connection attempt to the same listener.
      const delivered = await command(home, ['send', 'legacy proof', '--wait', '5'])
      assert.equal(delivered.code, 0, delivered.out + delivered.err)
      return state(home, 'default')
    }
    await fn({ home, name, key, launch, legacy, state: sessionName => state(home, sessionName),
      stop: sessionName => command(home, ['stop', '--name', sessionName]) })
  } finally {
    if (name) await command(home, ['stop', '--name', name])
    await command(home, ['stop', '--name', 'default'])
    await command(host, ['stop', '--name', 'host'])
    rmSync(temp, { recursive: true, force: true })
  }
}
const options = { skip: !bun, timeout: 90000 }

test('legacy join: a real ephemeral old prompt is reused alive, then refused without replacement after stop', options, async () => {
  await fixture(async f => {
    const old = await f.legacy()
    const sessionFile = join(old.dir, 'session.json'), originalSession = readFileSync(sessionFile)
    assert.equal(JSON.parse(originalSession).ephemeral, true)
    const reused = await f.launch()
    assert.equal(reused.code, 0, reused.out + reused.err)
    assert.match(reused.out, /legacy ephemeral identity.*daemon is alive/)
    assert.equal((await f.state('default')).pid, old.pid)
    assert.equal(existsSync(join(f.home, f.name + '.json')), false)
    await f.stop('default')
    const result = await f.launch()
    assert.equal(result.code, 2, result.out + result.err)
    assert.match(result.err, /ephemeral identity.*fresh listener/)
    assert.equal(existsSync(join(f.home, f.name + '.json')), false, 'no replacement identity is created')
    assert.equal(existsSync(join(f.home, 'tunnel', f.name)), false, 'no replacement session is created')
    assert.deepEqual(readFileSync(sessionFile), originalSession, 'historical session remains intact')
  })
})

test('legacy join: a stopped persistent default preserves its differently named identity across restarts', options, async () => {
  await fixture(async f => {
    const old = await f.legacy('my-existing-machine')
    await f.stop('default')
    const first = await f.launch()
    assert.equal(first.code, 0, first.out + first.err)
    assert.equal((await f.state(f.name)).self, old.self)
    assert.equal(existsSync(join(f.home, f.name + '.json')), false, 'the old profile is reused, not replaced')
    const session = JSON.parse(readFileSync(join((await f.state(f.name)).dir, 'session.json'), 'utf8'))
    assert.equal(session.profile, 'my-existing-machine')
    await f.stop(f.name)
    const restart = await f.launch()
    assert.equal(restart.code, 0, restart.out + restart.err)
    assert.equal((await f.state(f.name)).self, old.self)
  })
})

test('legacy join: missing, mismatched, or invalid saved profile refuses without changing historical sessions', options, async () => {
  await fixture(async f => {
    const old = await f.legacy('my-existing-machine')
    await f.stop('default')
    const profile = join(f.home, 'my-existing-machine.json'), sessionFile = join(old.dir, 'session.json')
    const originalSession = readFileSync(sessionFile)
    renameSync(profile, profile + '.fixture-backup')
    let result = await f.launch()
    assert.equal(result.code, 2, result.out + result.err)
    assert.match(result.err, /saved identity.*missing/)
    assert.equal(existsSync(profile), false)
    const other = generateIdentity()
    writeFileSync(profile, JSON.stringify({ S: other.S, edPub: other.edPub.toString('hex'), xPub: other.xPub.toString('hex') }))
    result = await f.launch()
    assert.equal(result.code, 2, result.out + result.err)
    assert.match(result.err, /does not match the previous session/)
    assert.deepEqual(readFileSync(sessionFile), originalSession)
    const invalid = JSON.parse(originalSession); invalid.profile = '../outside-identity'
    writeFileSync(sessionFile, JSON.stringify(invalid))
    result = await f.launch()
    assert.equal(result.code, 2, result.out + result.err)
    assert.match(result.err, /identity metadata is invalid/)
    assert.equal(JSON.parse(readFileSync(sessionFile, 'utf8')).profile, '../outside-identity')
    assert.equal(existsSync(join(f.home, f.name + '.json')), false)
    assert.equal(existsSync(join(f.home, 'tunnel', f.name)), false)
  })
})

test('legacy join: new bootstrap profile still preserves identity after stop and restart', options, async () => {
  await fixture(async f => {
    let result = await f.launch()
    assert.equal(result.code, 0, result.out + result.err)
    const first = await f.state(f.name)
    assert.equal(existsSync(join(f.home, f.name + '.json')), true)
    await f.stop(f.name)
    result = await f.launch()
    assert.equal(result.code, 0, result.out + result.err)
    const restarted = await f.state(f.name)
    assert.equal(restarted.self, first.self)
    assert.notEqual(restarted.id, first.id)
  })
})
