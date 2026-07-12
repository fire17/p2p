#!/usr/bin/env node
// p2p-chat — demo terminal chat + human-verification surface for the p2p framework.
//
// This is the dogfood CLI the owner/verification task actually RUNS to feel-test the
// whole thing. Two jobs it must nail (DESIGN D4): (1) show the 26-char contact key big
// and copyable; (2) make the FIRST-ACK — the MITM-proof key-confirmation moment — loud
// and unmistakable.
//
// Backend: it drives the public API of ../src/node.js (INTERFACES.md §node.js). While
// that module is still being built (owner: lane-wire), this CLI runs on an embedded
// IN-PROCESS backend that reuses the REAL src/key.js commitment gate — so the UX and the
// gate are genuine, only the network + Noise transport are shortcut. The moment
// src/node.js exists and exports { identity, listen }, this CLI switches to it with no
// code change here.
//
// ponytail: single file, node:readline, zero deps. Owner: lane-noise. Scope: bin/ only.

import readline from 'node:readline'
import process from 'node:process'
import { generateIdentity, decodeKey, verifyCommitment, TypoError } from '../src/key.js'
import { loadOrCreateIdentity } from './lib.js'

// ── tiny ANSI (skipped when not a TTY) ───────────────────────────────────────
const TTY = process.stdout.isTTY
const c = (code, s) => (TTY ? `\x1b[${code}m${s}\x1b[0m` : String(s))
const bold = (s) => c('1', s)
const green = (s) => c('32', s)
const cyan = (s) => c('36', s)
const dim = (s) => c('2', s)
const red = (s) => c('31', s)
const yellow = (s) => c('33', s)

const shortId = (S) => String(S).slice(0, 6)
// Real node.js peers are keyed by remote identity: the DIALER's peer has .S (the key it
// dialed); the LISTENER's accepted peer has .S = null but .remoteStatic (32B X25519). Label
// from whichever is present.
const peerLabel = (peer) =>
  peer && peer.S
    ? shortId(peer.S)
    : peer && peer.remoteStatic
      ? Buffer.from(peer.remoteStatic).toString('hex').slice(0, 6).toUpperCase()
      : '??????'
const asBuf = (d) => (Buffer.isBuffer(d) ? d : Buffer.from(String(d)))

// ── the backend contract this CLI depends on ─────────────────────────────────
// identity()            -> { S, edPub, xPub, ... }
// listen(identity,opts) -> node
// node.on(event, fn)    events: 'peer' (peer connected), 'message' ({from,data}),
//                                'disconnect' (peer)
// node.connect(KEY)     -> Promise<peer>  RESOLVES ONLY AFTER the first-ack (the proof)
// node.close()
// peer.send(data)       -> Promise<ack>   ; peer.S / peer.shortId
async function loadBackend({ ephemeral = false, profile = 'default' } = {}) {
  try {
    const mod = await import(new URL('../src/node.js', import.meta.url))
    if (typeof mod.listen === 'function' && typeof mod.identity === 'function') {
      // ponytail: real node.js may name its message/peer event payloads differently —
      // if wiring breaks when it lands, reconcile the event shapes in THIS function
      // (single reconcile point) against INTERFACES.md §node.js.
      // STABLE identity (~/.p2p/<profile>.json) so a killed+restarted listener keeps the
      // same key — item #5 (buffered resend across restart) needs this. --ephemeral opts out.
      return { real: true, identity: () => loadOrCreateIdentity({ ephemeral, profile }), listen: mod.listen }
    }
  } catch {
    /* not built yet — fall through to embedded demo backend */
  }
  return { real: false, ...embeddedBackend() }
}

// ── embedded in-process demo backend (reuses the REAL key.js gate) ───────────
// Mirrors src/node.js shapes EXACTLY so the CLI has one code path: async identity/listen,
// positional events ('message' -> (peer, buf), 'peer' -> (peer)), node.peers() method, and
// peers with {S, remoteStatic}. In-process only (REGISTRY) — the real core does the network.
const REGISTRY = new Map() // S -> LoopNode

function embeddedBackend() {
  return { identity: async () => generateIdentity(), listen: async (id, opts = {}) => new LoopNode(id, opts) }
}

class LoopNode {
  constructor(id) {
    this.id = id
    this.S = id.S
    this.handlers = {}
    this._peers = new Set()
    REGISTRY.set(this.S, this)
  }
  on(ev, fn) {
    ;(this.handlers[ev] ||= []).push(fn)
    return this
  }
  emit(ev, ...args) {
    for (const fn of this.handlers[ev] || []) fn(...args)
  }
  peers() {
    return [...this._peers]
  }
  async connect(KEY) {
    const key = String(KEY).trim().toUpperCase()
    const { commitment } = decodeKey(key) // throws TypoError on typo/bad checksum
    const target = REGISTRY.get(key)
    if (!target) {
      throw new Error(
        'peer not reachable — not found in this process. The demo backend is in-process ' +
          'only; two separate terminals need the real network core (src/node.js).'
      )
    }
    // REAL MITM gate (DESIGN D4): the string is a commitment to the peer's keys; a
    // substituted identity fails this second-preimage check (~2^-110).
    if (!verifyCommitment(commitment, target.id.edPub, target.id.xPub)) {
      throw new Error('commitment gate FAILED — key does not match peer identity (possible MITM). Aborted.')
    }
    // dialerPeer = my handle on target (S known). listenerPeer = target's handle on me
    // (S=null + remoteStatic, exactly like a real accepted peer). Each is also the
    // sender-view stamped on messages the OTHER side receives.
    const dialerPeer = { S: target.S, remoteStatic: target.id.xPub, connected: true, close() {} }
    const listenerPeer = { S: null, remoteStatic: this.id.xPub, connected: true, close() {} }
    dialerPeer.send = async (d) => (target.emit('message', listenerPeer, asBuf(d)), 0)
    listenerPeer.send = async (d) => (this.emit('message', dialerPeer, asBuf(d)), 0)
    this._peers.add(dialerPeer)
    target._peers.add(listenerPeer)
    target.emit('peer', listenerPeer) // inbound side sees a new peer
    this.emit('peer', dialerPeer)
    return dialerPeer // resolves AFTER gate + ack == the first-ack proof surface
  }
  close() {
    REGISTRY.delete(this.S)
    this._peers.clear()
  }
}

// ── display ──────────────────────────────────────────────────────────────────
function printKey(S) {
  const title = 'YOUR p2p KEY — share with a friend'
  const W = Math.max(title.length, S.length) + 4 // inner width, incl. 2-space pad each side
  const bar = '─'.repeat(W)
  const pad = (s) => '  ' + s + ' '.repeat(W - 2 - s.length)
  process.stdout.write('\n')
  console.log(cyan('  ┌' + bar + '┐'))
  console.log(cyan('  │') + bold(pad(title)) + cyan('│'))
  console.log(cyan('  ├' + bar + '┤'))
  console.log(cyan('  │') + bold(green(pad(S))) + cyan('│'))
  console.log(cyan('  └' + bar + '┘'))
  console.log(dim('  copy the 26 chars above · they run:  ') + bold('p2p-chat ' + S))
  process.stdout.write('\n')
}

function printAck(peer) {
  console.log(
    '\n' +
      green(bold('  ✅ secure channel established — verified, no MITM')) +
      dim('  (peer ' + peerLabel(peer) + ')')
  )
  console.log(dim('  the first ack decrypted: proof the peer holds the key that matches the string.'))
  console.log(dim('  type a message and press enter · Ctrl-C to quit') + '\n')
}

// ── REPL wiring shared by both modes ─────────────────────────────────────────
function startRepl(node, getPeers, { isDialer = false } = {}) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: cyan('you › ') })
  node.on('message', (peer, data) => {
    // redraw cleanly under the prompt
    readline.cursorTo(process.stdout, 0)
    readline.clearLine(process.stdout, 0)
    console.log(bold(cyan(peerLabel(peer) + ' › ')) + data.toString())
    rl.prompt(true)
  })
  node.on('peer', (peer) => {
    readline.cursorTo(process.stdout, 0)
    readline.clearLine(process.stdout, 0)
    console.log(dim('  · peer ' + peerLabel(peer) + ' connected'))
    rl.prompt(true)
  })
  rl.prompt()
  // track in-flight sends so a stdin-EOF close drains them (real peer.send resolves on ACK)
  let inflight = Promise.resolve()
  rl.on('line', (line) => {
    const text = line.trim()
    if (text) {
      const peers = getPeers()
      if (peers.length === 0) console.log(dim('  (no peer connected yet — waiting…)'))
      else inflight = inflight.then(() => Promise.all(peers.map((p) => p.send(text).catch(() => {}))))
    }
    rl.prompt()
  })
  let closing = false
  const shutdown = async () => {
    if (closing) return
    closing = true
    await inflight.catch(() => {}) // confirm delivery (ACK) before tearing down
    console.log('\n' + dim('  closing…'))
    try {
      node.close()
    } catch {}
    try {
      rl.close()
    } catch {}
    process.exit(0)
  }
  rl.on('SIGINT', shutdown)
  // stdin EOF: a DIALER (piped send) or an interactive TTY user (Ctrl-D) exits. But a
  // non-TTY LISTENER (backgrounded, e.g. `node p2p-chat > log &`) must NOT self-close —
  // that would tear down its endpoint and stop mDNS announce, making it undiscoverable.
  rl.on('close', () => {
    if (isDialer || process.stdin.isTTY) shutdown()
  })
  process.on('SIGINT', shutdown)
  return rl
}

// ── modes ──────────────────────────────────────────────────────────────────
async function runListen(be) {
  const id = await be.identity()
  const node = await be.listen(id, {})
  if (!be.real) {
    console.log(
      yellow('  ⚠ demo backend') +
        dim(' — src/node.js not linked; in-process only. --selftest and single-process demo work now.')
    )
  }
  printKey(id.S)
  console.log(dim('  listening · waiting for a friend to connect…'))
  startRepl(node, () => node.peers(), { isDialer: false })
}

async function runConnect(be, KEY) {
  // validate locally BEFORE any network work (DESIGN: checksum gate on typos)
  try {
    decodeKey(String(KEY).trim().toUpperCase())
  } catch (e) {
    if (e instanceof TypoError) {
      console.error(red('  ✗ bad key: ') + e.message + dim('  (check you copied all 26 characters)'))
      process.exit(2)
    }
    throw e
  }
  const id = await be.identity()
  const node = await be.listen(id, {}) // we also listen, so the peer can reach us back
  if (!be.real) {
    console.log(
      yellow('  ⚠ demo backend') +
        dim(' — src/node.js not linked; in-process only, so a live remote peer will not be found.')
    )
  }
  console.log(dim('  your key: ') + cyan(id.S))
  console.log(dim('  connecting to ') + cyan(shortId(KEY)) + dim(' · resolving rendezvous, punching NAT, running Noise IK…'))
  let peer
  try {
    peer = await node.connect(KEY)
  } catch (e) {
    console.error(red('  ✗ connect failed: ') + e.message)
    process.exit(3)
  }
  printAck(peer)
  startRepl(node, () => node.peers(), { isDialer: true })
}

// ── --selftest: two in-process nodes, full round-trip (CLI plumbing proof) ────
async function selftest() {
  const be = { real: false, ...embeddedBackend() }
  const a = await be.listen(await be.identity())
  const b = await be.listen(await be.identity())
  let aPeer = false
  let aMsg = null
  let bMsg = null
  a.on('peer', () => (aPeer = true))
  a.on('message', (_peer, data) => (aMsg = data.toString()))
  b.on('message', (_peer, data) => (bMsg = data.toString()))

  const bToA = await b.connect(a.S) // first-ack
  await bToA.send('hello from B')
  await new Promise((r) => setTimeout(r, 10))
  const aToB = a.peers()[0]
  await aToB.send('ack from A')
  await new Promise((r) => setTimeout(r, 10))

  let badKeyRejected = false
  try {
    await b.connect('NOTAVALIDKEY0000000000000A') // wrong checksum
  } catch (e) {
    badKeyRejected = e instanceof TypoError
  }

  const checks = [
    ['connect() resolved (first-ack fired)', !!bToA],
    ['listener saw peer event', aPeer],
    ['B→A message delivered', aMsg === 'hello from B'],
    ['A→B message delivered', bMsg === 'ack from A'],
    ['malformed key rejected (checksum)', badKeyRejected],
  ]
  let ok = true
  for (const [name, pass] of checks) {
    console.log((pass ? green('  ✔ ') : red('  ✗ ')) + name)
    if (!pass) ok = false
  }
  console.log(ok ? green(bold('\n  SELFTEST PASS\n')) : red(bold('\n  SELFTEST FAIL\n')))
  process.exit(ok ? 0 : 1)
}

// ── entry ─────────────────────────────────────────────────────────────────────
async function main() {
  const args = process.argv.slice(2)
  if (args.includes('--help') || args.includes('-h')) {
    console.log(
      [
        bold('p2p-chat') + ' — MITM-proof P2P demo chat',
        '',
        '  p2p-chat                 load/create stable key, listen, wait for incoming',
        '  p2p-chat <KEY>           connect to a 26-char key, then chat',
        '  p2p-chat --ephemeral     use a throwaway key (not saved to ~/.p2p)',
        '  p2p-chat --profile <n>   use a separate stored identity',
        '  p2p-chat --selftest      run two in-process nodes end-to-end',
        '  p2p-chat --help          this text',
      ].join('\n')
    )
    return
  }
  if (args.includes('--selftest')) return selftest()

  const ephemeral = args.includes('--ephemeral')
  const pIdx = args.indexOf('--profile')
  const profile = pIdx >= 0 && args[pIdx + 1] ? args[pIdx + 1] : 'default'
  const be = await loadBackend({ ephemeral, profile })
  const key = args.find((a) => !a.startsWith('-') && a !== profile)
  if (key) await runConnect(be, key)
  else await runListen(be)
}

main().catch((e) => {
  console.error(red('  ✗ ' + (e && e.message ? e.message : e)))
  process.exit(1)
})
