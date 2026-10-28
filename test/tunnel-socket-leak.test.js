// test/tunnel-socket-leak.test.js — the Windows joiner socket leak (15,948 TCP sockets held by one
// bun joiner: 13,371 Bound + 2,596 CloseWait → WSAENOBUFS), reproduced as a DESCRIPTOR COUNT on
// this machine and proven flat.
//
// A real local WebSocket "relay" (RFC 6455 handshake + just enough MQTT: CONNACK/SUBACK/PINGRESP)
// is driven through cycles of HOLD (accept, stay up) → DROP (destroy every live socket, then
// accept-and-destroy newcomers: the relay/peer dying) → REFUSE (listener closed: port refused).
// The joiner (test/fixtures/leak-joiner.mjs) runs as a separate process under node AND bun and is
// measured from outside with `lsof -p PID`, plus its own constructed/still-open WebSocket counts.
// Pre-fix, every drop fired onerror AND onclose → two redials, the extra socket orphaned open:
// sockets doubled per drop. Post-fix the count after the last HOLD equals the count after the first.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createSocketGuard, socketCounts } from '../bin/lib.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const joiner = fileURLToPath(new URL('./fixtures/leak-joiner.mjs', import.meta.url))
const bin = fileURLToPath(new URL('../bin/p2p.js', import.meta.url))
const which = (cmd) => { try { return execFileSync('/usr/bin/which', [cmd], { encoding: 'utf8' }).trim() || null } catch { return null } }
const LSOF = process.platform !== 'win32' ? which('lsof') : null
const lsofCount = (pid) => {
  try { return execFileSync(LSOF, ['-n', '-P', '-p', String(pid)], { encoding: 'utf8' }).trim().split('\n').length - 1 } catch { return -1 }
}
const lsofTcp = (pid) => {
  try { return execFileSync(LSOF, ['-n', '-P', '-a', '-i', 'TCP', '-p', String(pid)], { encoding: 'utf8' }).trim().split('\n').length - 1 } catch { return 0 }
}

/** A one-port WebSocket MQTT relay whose mode the test flips: 'hold' | 'drop' | 'refuse'. */
function flakyRelay() {
  const live = new Set()
  let mode = 'hold', port = 0
  const frame = (u8) => Buffer.concat([Buffer.from([0x82, u8.length]), Buffer.from(u8)])
  const server = createServer((_, res) => { res.statusCode = 426; res.end() })
  server.on('upgrade', (req, sock) => {
    if (mode !== 'hold') { sock.destroy(); return }
    const accept = createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
    sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
      'Sec-WebSocket-Accept: ' + accept + '\r\nSec-WebSocket-Protocol: mqtt\r\n\r\n')
    live.add(sock)
    sock.on('close', () => live.delete(sock)); sock.on('error', () => {})
    let buf = Buffer.alloc(0)
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d])
      while (buf.length >= 2) {
        let len = buf[1] & 127, off = 2
        if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4 }
        if (buf.length < off + 4 + len) return
        const mask = buf.subarray(off, off + 4), body = Buffer.from(buf.subarray(off + 4, off + 4 + len))
        for (let i = 0; i < body.length; i++) body[i] ^= mask[i & 3]
        const op = buf[0] & 15
        buf = buf.subarray(off + 4 + len)
        if (op === 8) { sock.destroy(); return }
        const type = body[0] >> 4
        if (type === 1) sock.write(frame([0x20, 2, 0, 0]))                 // CONNECT → CONNACK
        else if (type === 8) sock.write(frame([0x90, 3, body[2], body[3], 0])) // SUBSCRIBE → SUBACK
        else if (type === 12) sock.write(frame([0xd0, 0]))                  // PINGREQ → PINGRESP
      }
    })
  })
  const listen = () => new Promise((r) => server.listen(port, '127.0.0.1', () => { port = server.address().port; r() }))
  return {
    get port() { return port }, live,
    start: listen,
    async set(m) {
      if (mode === 'refuse' && m !== 'refuse') await listen()
      mode = m
      if (m === 'drop' || m === 'refuse') for (const s of live) s.destroy()
      if (m === 'refuse') await new Promise((r) => server.close(() => r()))
    },
    async stop() { for (const s of live) s.destroy(); if (mode !== 'refuse') await new Promise((r) => server.close(() => r())) },
  }
}

/**
 * Drive `cycles` of hold/drop/refuse against a joiner running under `runtime`; return the samples.
 * @returns {Promise<{first:object, last:object, peak:object, lines:string[]}>}
 */
export async function leakRun(runtime, { cycles = 6, holdMs = 2500, dropMs = 1200, refuseMs = 1200 } = {}) {
  const relay = flakyRelay()
  await relay.start()
  const url = `ws://127.0.0.1:${relay.port}/mqtt`
  const child = spawn(runtime, [joiner], { env: { ...process.env, LEAK_RELAYS: url + ',' + url.replace('/mqtt', '/mqtt2') }, stdio: ['pipe', 'pipe', 'inherit'] })
  let last = null, buf = ''
  child.stdout.on('data', (d) => { buf += d; const ls = buf.split('\n'); buf = ls.pop(); for (const l of ls) if (l) last = JSON.parse(l) })
  const snap = (tag) => ({ tag, lsof: lsofCount(child.pid), tcp: lsofTcp(child.pid), ...last })
  const lines = []
  try {
    await sleep(holdMs)
    const first = snap('hold#0')
    lines.push(JSON.stringify(first))
    let peak = first
    for (let i = 1; i <= cycles; i++) {
      await relay.set('drop'); await sleep(dropMs)
      await relay.set('refuse'); await sleep(refuseMs)
      await relay.set('hold'); await sleep(holdMs)
      const s = snap('hold#' + i)
      lines.push(JSON.stringify(s))
      if (s.lsof > peak.lsof) peak = s
    }
    return { first, last: snap('final'), peak, lines }
  } finally {
    child.stdin.end()
    await new Promise((r) => { const t = setTimeout(() => { try { child.kill('SIGKILL') } catch { /* */ } r() }, 3000); child.once('exit', () => { clearTimeout(t); r() }) })
    await relay.stop()
  }
}

const RUNTIMES = [['node', process.execPath], ['bun', which('bun')]].filter(([, p]) => p)

for (const [name, runtime] of RUNTIMES) {
  test(`socket leak: ${name} joiner holds a FLAT socket count across hold/drop/refuse cycles`, { timeout: 90000, skip: !LSOF && 'needs lsof' }, async () => {
    const r = await leakRun(runtime)
    for (const l of r.lines) console.log(`# ${name} ${l}`)
    console.log(`# ${name} first lsof=${r.first.lsof} tcp=${r.first.tcp} open=${r.first.open} | final lsof=${r.last.lsof} tcp=${r.last.tcp} open=${r.last.open} made=${r.last.made}`)
    // Two relay URLs ⇒ two live relay sockets in steady state, however many cycles ran.
    assert.ok(r.last.open <= 2, `relay WebSockets still open after ${r.lines.length - 1} cycles: ${r.last.open} (want ≤ 2)`)
    assert.ok(r.last.tcp <= r.first.tcp + 1, `TCP sockets grew: ${r.first.tcp} → ${r.last.tcp}`)
    assert.ok(r.last.lsof <= r.first.lsof + 4, `open fds grew: ${r.first.lsof} → ${r.last.lsof}`)
    // Backoff with a ceiling: ~6 cycles × ~5s with a 1s cap is a few dozen redials, never hundreds.
    assert.ok(r.last.made < 120, `redial storm: ${r.last.made} sockets constructed`)
  })
}

test('socket guard: trips once past a cap, with one clear line, and stops sampling', () => {
  let n = 2, trips = []
  const g = createSocketGuard({ sample: () => ({ relayOpen: n, relayMade: n, fds: 30 }), caps: { relayOpen: 64, fds: 1024, dialsPerMin: 120 },
    intervalMs: 1e9, onTrip: (m) => trips.push(m) })
  assert.equal(g.check(), null)
  n = 65
  const msg = g.check()
  assert.match(msg, /^socket guard tripped: relayOpen=65 > cap 64 \(.*\) — transport torn down, daemon exiting$/)
  assert.equal(g.check(), null, 'trips exactly once')
  assert.deepEqual(trips, [msg])
  g.stop()
})

test('socket guard: a redial storm (sockets constructed per minute) trips even when each closes', () => {
  let made = 0, t = 0
  const trips = []
  const g = createSocketGuard({ sample: () => ({ relayOpen: 1, relayMade: made }), caps: { relayOpen: 64, dialsPerMin: 120 },
    intervalMs: 1e9, now: () => t, onTrip: (m) => trips.push(m) })
  for (let i = 0; i < 12; i++) { made += 10; t += 5000; assert.equal(g.check(), null, 'a steady 2/s stays under the cap') }
  made += 200; t += 5000
  assert.match(g.check(), /dialsPerMin=\d+ > cap 120/)
  g.stop()
})

test('socket counts: this runtime reports what it can measure', () => {
  const c = socketCounts(() => ({ made: 3, open: 1 }))
  assert.equal(c.relayOpen, 1); assert.equal(c.relayMade, 3)
  if (process.platform !== 'win32') assert.ok(c.fds > 0, 'posix: /dev/fd is countable')
})

test('socket guard: a tunnel daemon past its cap exits with ONE clear error line the launcher prints', { timeout: 30000 }, async () => {
  const home = mkdtempSync(join(tmpdir(), 'p2p-guard-'))
  try {
    // P2P_FD_CAP=1 makes the very first check (before any network is touched) trip.
    const r = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [bin, 'tunnel', 'listen', '--ephemeral'], { env: { ...process.env, P2P_HOME: home, P2P_RENDEZVOUS_DIR: '', P2P_FD_CAP: '1' }, stdio: ['ignore', 'pipe', 'pipe'] })
      let out = '', err = ''
      child.stdout.on('data', (d) => { out += d }); child.stderr.on('data', (d) => { err += d })
      const t = setTimeout(() => { child.kill(); reject(new Error('timeout ' + out + err)) }, 25000)
      child.on('exit', (code) => { clearTimeout(t); resolve({ code, out, err }) })
    })
    console.log('# launcher stderr: ' + r.err.trim())
    assert.equal(r.code, 3, r.out + r.err)
    assert.match(r.err, /^p2p tunnel: socket guard tripped: fds=\d+ > cap 1 \(.*\) — transport torn down, daemon exiting$/m)
    const root = join(home, 'tunnel', 'default'), { id } = JSON.parse(readFileSync(join(root, 'current.json')))
    const st = JSON.parse(readFileSync(join(root, id, 'state.json')))
    assert.match(st.error, /^socket guard tripped/); assert.ok(st.stopped, 'daemon shut itself down')
    const pid = st.pid
    await sleep(300)
    assert.throws(() => process.kill(pid, 0), 'daemon process is gone')
    assert.ok(!readdirSync(join(root, id)).includes('resident.lock'), 'resident lock released')
  } finally { rmSync(home, { recursive: true, force: true }) }
})
