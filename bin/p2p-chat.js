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

// ── the backend contract this CLI depends on ─────────────────────────────────
// identity()            -> { S, edPub, xPub, ... }
// listen(identity,opts) -> node
// node.on(event, fn)    events: 'peer' (peer connected), 'message' ({from,data}),
//                                'disconnect' (peer)
// node.connect(KEY)     -> Promise<peer>  RESOLVES ONLY AFTER the first-ack (the proof)
// node.close()
// peer.send(data)       -> Promise<ack>   ; peer.S / peer.shortId
async function loadBackend() {
  try {
    const mod = await import(new URL('../src/node.js', import.meta.url))
    if (typeof mod.listen === 'function' && typeof mod.identity === 'function') {
      // ponytail: real node.js may name its message/peer event payloads differently —
      // if wiring breaks when it lands, reconcile the event shapes in THIS function
      // (single reconcile point) against INTERFACES.md §node.js.
      return { real: true, identity: mod.identity, listen: mod.listen }
    }
  } catch {
    /* not built yet — fall through to embedded demo backend */
  }
  return { real: false, ...embeddedBackend() }
}

// ── embedded in-process demo backend (reuses the REAL key.js gate) ───────────
const REGISTRY = new Map() // S -> LoopNode  (in-process only, by design)

function embeddedBackend() {
  return { identity: () => generateIdentity(), listen: (id, opts = {}) => new LoopNode(id, opts) }
}

class LoopNode {
  constructor(id) {
    this.id = id
    this.S = id.S
    this.handlers = {}
    this.peers = new Set()
    REGISTRY.set(this.S, this)
  }
  on(ev, fn) {
    ;(this.handlers[ev] ||= []).push(fn)
    return this
  }
  emit(ev, arg) {
    for (const fn of this.handlers[ev] || []) fn(arg)
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
    const mine = makePeer(this, target)
    const theirs = makePeer(target, this)
    this.peers.add(mine)
    target.peers.add(theirs)
    target.emit('peer', theirs) // inbound side sees a new peer
    this.emit('peer', mine)
    return mine // connect resolves AFTER gate + ack == the first-ack proof surface
  }
  close() {
    REGISTRY.delete(this.S)
    this.peers.clear()
  }
}

function makePeer(fromNode, toNode) {
  return {
    S: toNode.S,
    shortId: shortId(toNode.S),
    async send(data) {
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data))
      queueMicrotask(() => toNode.emit('message', { from: makePeer(toNode, fromNode), data: buf }))
      return { ok: true } // ack
    },
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
      dim('  (peer ' + peer.shortId + ')')
  )
  console.log(dim('  the first ack decrypted: proof the peer holds the key that matches the string.'))
  console.log(dim('  type a message and press enter · Ctrl-C to quit') + '\n')
}

// ── REPL wiring shared by both modes ─────────────────────────────────────────
function startRepl(node, getPeers) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: cyan('you › ') })
  node.on('message', ({ from, data }) => {
    // redraw cleanly under the prompt
    readline.cursorTo(process.stdout, 0)
    readline.clearLine(process.stdout, 0)
    console.log(bold(cyan(shortId(from.S) + ' › ')) + data.toString())
    rl.prompt(true)
  })
  node.on('peer', (peer) => {
    readline.cursorTo(process.stdout, 0)
    readline.clearLine(process.stdout, 0)
    console.log(dim('  · peer ' + peer.shortId + ' connected'))
    rl.prompt(true)
  })
  rl.prompt()
  rl.on('line', async (line) => {
    const text = line.trim()
    if (text) {
      const peers = getPeers()
      if (peers.length === 0) console.log(dim('  (no peer connected yet — waiting…)'))
      else for (const p of peers) await p.send(text)
    }
    rl.prompt()
  })
  const shutdown = () => {
    console.log('\n' + dim('  closing…'))
    try {
      node.close()
    } catch {}
    rl.close()
    process.exit(0)
  }
  rl.on('SIGINT', shutdown)
  process.on('SIGINT', shutdown)
  return rl
}

// ── modes ──────────────────────────────────────────────────────────────────
async function runListen(be) {
  const id = be.identity()
  const node = be.listen(id, {})
  if (!be.real) {
    console.log(
      yellow('  ⚠ demo backend') +
        dim(' — src/node.js not linked yet; in-process only. --selftest and single-process demo work now.')
    )
  }
  printKey(id.S)
  console.log(dim('  listening · waiting for a friend to connect…'))
  startRepl(node, () => [...node.peers])
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
  const id = be.identity()
  const node = be.listen(id, {}) // we also listen, so the peer can reach us back
  if (!be.real) {
    console.log(
      yellow('  ⚠ demo backend') +
        dim(' — src/node.js not linked yet; in-process only, so a live remote peer will not be found.')
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
  startRepl(node, () => [...node.peers])
}

// ── --selftest: two in-process nodes, full round-trip (CLI plumbing proof) ────
async function selftest() {
  const be = { real: false, ...embeddedBackend() }
  const a = be.listen(be.identity())
  const b = be.listen(be.identity())
  let aPeer = false
  let aMsg = null
  let bMsg = null
  a.on('peer', () => (aPeer = true))
  a.on('message', ({ data }) => (aMsg = data.toString()))
  b.on('message', ({ data }) => (bMsg = data.toString()))

  const bToA = await b.connect(a.S) // first-ack
  await bToA.send('hello from B')
  await new Promise((r) => setTimeout(r, 10))
  const aToB = [...a.peers][0]
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
        '  p2p-chat                 generate a key, listen, wait for incoming',
        '  p2p-chat <KEY>           connect to a 26-char key, then chat',
        '  p2p-chat --selftest      run two in-process nodes end-to-end',
        '  p2p-chat --help          this text',
      ].join('\n')
    )
    return
  }
  if (args.includes('--selftest')) return selftest()

  const be = await loadBackend()
  const key = args.find((a) => !a.startsWith('-'))
  if (key) await runConnect(be, key)
  else await runListen(be)
}

main().catch((e) => {
  console.error(red('  ✗ ' + (e && e.message ? e.message : e)))
  process.exit(1)
})
