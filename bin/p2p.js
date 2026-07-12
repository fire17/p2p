#!/usr/bin/env node
// p2p — the framework's command-line entry. Subcommands + a full-screen TUI.
// Zero deps. Stable identity by default (~/.p2p/<profile>.json), so your key survives
// restarts and a friend can reach you again with the same string.
//
//   p2p                     launch the TUI (listen + chat)          [default]
//   p2p tui [KEY]           TUI; optionally dial KEY on start
//   p2p chat [KEY]          line-mode chat (scriptable / no full-screen)
//   p2p listen              line-mode: go online, print key, wait
//   p2p connect <KEY>       line-mode: dial a key and chat
//   p2p key [--new]         print your stable key (create if needed; --new rotates it)
//   p2p doctor              check rendezvous reachability (STUN / DHT / trackers)
//   p2p --selftest          two in-process nodes end-to-end (plumbing proof)
//
// flags:  --ephemeral (throwaway identity)  ·  --profile <name> (separate identity/key)

import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import readline from 'node:readline'
import {
  loadNode, loadOrCreateIdentity, saveIdentity, generateIdentity, decodeKey, TypoError, doctor,
  bold, dim, red, green, cyan, yellow, magenta, peerLabel, shortId, idFilePath,
  loadFriends, addFriend, resolveFriend, peerKey,
} from './lib.js'

const HERE = dirname(fileURLToPath(import.meta.url))

function flagVal(args, name) { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined }
function opts(args) {
  return { ephemeral: args.includes('--ephemeral'), profile: flagVal(args, '--profile') || 'default' }
}

// ── key display ────────────────────────────────────────────────────────────────
function printKeyBox(S) {
  const title = 'YOUR p2p KEY — share with a friend'
  const W = Math.max(title.length, S.length) + 4
  const bar = '─'.repeat(W)
  const pad = (s) => '  ' + s + ' '.repeat(W - 2 - s.length)
  console.log('\n' + cyan('  ┌' + bar + '┐'))
  console.log(cyan('  │') + bold(pad(title)) + cyan('│'))
  console.log(cyan('  ├' + bar + '┤'))
  console.log(cyan('  │') + bold(green(pad(S))) + cyan('│'))
  console.log(cyan('  └' + bar + '┘'))
  console.log(dim('  they run:  ') + bold('p2p ' + S) + dim('   (or: p2p connect ' + S + ')') + '\n')
}

// ── line-mode chat (stable identity, real network) ──────────────────────────────
async function lineMode({ dialKey, ephemeral, profile }) {
  const id = loadOrCreateIdentity({ ephemeral, profile })
  const mod = await loadNode()
  const node = await mod.listen(id, {})
  const getPeers = () => (node.peers ? node.peers() : [])
  let rl = null
  const printLine = (line) => {
    if (rl) { readline.cursorTo(process.stdout, 0); readline.clearLine(process.stdout, 0) }
    console.log(line)
    if (rl) rl.prompt(true)
  }
  // attach network handlers up front so no incoming peer/message is missed
  node.on('message', (peer, data) => printLine(bold(magenta(peerLabel(peer) + ' › ')) + data.toString()))
  node.on('peer', (peer) => {
    const { isNew } = addFriend(peerKey(peer), { selfKey: id.S, profile })
    printLine(dim('  · peer ' + peerLabel(peer) + ' connected') + (isNew ? green('  ✚ added to friends') : ''))
  })
  node.on('disconnect', (peer) => printLine(dim('  · peer ' + peerLabel(peer) + ' disconnected')))

  if (dialKey) {
    try { decodeKey(String(dialKey).trim().toUpperCase()) } catch (e) {
      if (e instanceof TypoError) { console.error(red('  ✗ bad key: ') + e.message); process.exit(2) }
      throw e
    }
    console.log(dim('  your key: ') + cyan(id.S))
    console.log(dim('  connecting to ') + cyan(shortId(dialKey)) + dim(' · rendezvous + NAT punch + Noise IK…'))
    try {
      const peer = await node.connect(dialKey)
      console.log('\n' + green(bold('  ✅ secure channel established — verified, no MITM')) + dim('  (peer ' + peerLabel(peer) + ')'))
    } catch (e) { console.error(red('  ✗ connect failed: ') + e.message); process.exit(3) }
  } else {
    printKeyBox(id.S)
    console.log(dim('  listening · waiting for a friend to connect…'))
  }

  // create the input reader ONLY now — before this, a piped line would fire 'line' with no
  // handler and be lost (breaks scripting; interactive typing was unaffected).
  rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: cyan('you › ') })
  let inflight = Promise.resolve()
  rl.prompt()
  rl.on('line', (line) => {
    const text = line.trim()
    if (text) {
      const ps = getPeers()
      if (!ps.length) console.log(dim('  (no peer connected yet — waiting…)'))
      else inflight = inflight.then(() => Promise.all(ps.map((p) => p.send(text).catch(() => {}))))
    }
    rl.prompt()
  })
  let closing = false
  const shutdown = async () => {
    if (closing) return; closing = true
    try { await inflight } catch { /* */ }
    console.log('\n' + dim('  closing…'))
    try { node.close() } catch { /* */ }
    try { rl.close() } catch { /* */ }
    process.exit(0)
  }
  const isDialer = !!dialKey
  rl.on('SIGINT', shutdown)
  rl.on('close', () => { if (isDialer || process.stdin.isTTY) shutdown() })
  process.on('SIGINT', shutdown)
}

// ── doctor ──────────────────────────────────────────────────────────────────────
async function runDoctor() {
  console.log(bold('\n  p2p doctor — rendezvous reachability (free public infra)\n'))
  const rows = await doctor()
  for (const [name, ok, detail] of rows) {
    console.log('  ' + (ok ? green('✔') : red('✗')) + '  ' + name.padEnd(34) + dim(detail))
  }
  const anyUp = rows.some((r) => r[1])
  console.log('\n  ' + (anyUp ? green('rendezvous reachable — you can be found.') : red('no rendezvous reachable — check your network.')) + '\n')
  process.exit(anyUp ? 0 : 1)
}

// ── selftest (delegate to the proven in-process plumbing check) ──────────────────
function selftest() {
  const p = spawn(process.execPath, [join(HERE, 'p2p-chat.js'), '--selftest'], { stdio: 'inherit' })
  p.on('exit', (code) => process.exit(code ?? 0))
}

function launchTui(args) {
  const p = spawn(process.execPath, [join(HERE, 'p2p-tui.js'), ...args], { stdio: 'inherit' })
  p.on('exit', (code) => process.exit(code ?? 0))
}

const HELP = `${bold('p2p')} — MITM-proof, zero-dependency P2P chat

  ${bold('p2p')}                     launch the TUI (listen + chat)   ${dim('[default]')}
  ${bold('p2p tui')} [KEY]           full-screen TUI; optionally dial KEY on start
  ${bold('p2p chat')} [KEY]          line-mode chat (scriptable)
  ${bold('p2p listen')}              line-mode: go online, print your key, wait
  ${bold('p2p connect')} <KEY|name>  line-mode: dial a 26-char key or a saved friend
  ${bold('p2p friends')}             list everyone you've connected with (reconnect by name)
  ${bold('p2p key')} [--new]         print your stable key (--new rotates it)
  ${bold('p2p doctor')}              check rendezvous reachability
  ${bold('p2p --selftest')}          two in-process nodes end-to-end

  flags:  ${dim('--ephemeral')} throwaway identity   ${dim('--profile <name>')} separate key
  your key lives at ${dim(idFilePath('<profile>'))} (0600)`

async function main() {
  const argv = process.argv.slice(2)
  if (argv.includes('--help') || argv.includes('-h')) { console.log(HELP); return }
  if (argv.includes('--selftest')) return selftest()

  const o = opts(argv)
  const positional = argv.filter((a, i) => !a.startsWith('-') && argv[i - 1] !== '--profile')
  const cmd = positional[0]

  // a bare 26-char key as the first arg == connect via TUI (the friendly default)
  const looksLikeKey = (s) => typeof s === 'string' && /^[0-9A-HJ-NP-Za-hj-np-z]{26}$/.test(s)

  switch (cmd) {
    case undefined:
      return launchTui(argv) // no command -> TUI listen
    case 'tui':
      return launchTui(argv.filter((a) => a !== 'tui'))
    case 'chat':
      return lineMode({ dialKey: positional[1], ...o })
    case 'listen':
      return lineMode({ dialKey: null, ...o })
    case 'connect': case 'dial': {
      const arg = positional[1]
      if (!arg) { console.error(red('  usage: p2p connect <26-char-key | friend-name>')); process.exit(2) }
      const key = resolveFriend(arg, o.profile) || arg // a saved friend's name/short-id, or a raw key
      return lineMode({ dialKey: key, ...o })
    }
    case 'friends': case 'f': {
      const list = loadFriends(o.profile)
      if (!list.length) { console.log(dim('\n  no friends yet — connect with someone and they\'re saved here.\n')); return }
      console.log(bold('\n  your p2p friends') + dim(` (${list.length})`) + '\n')
      for (const f of list.sort((a, b) => b.lastSeen - a.lastSeen)) {
        const last = new Date(f.lastSeen).toISOString().slice(0, 16).replace('T', ' ')
        console.log('  ' + bold(cyan((f.nick || shortId(f.key)).padEnd(14))) + dim(f.key) + dim('  last ' + last))
      }
      console.log(dim('\n  reconnect:  ') + bold('p2p connect <name>') + '\n')
      return
    }
    case 'key': {
      const rotate = argv.includes('--new')
      let id
      if (rotate && !o.ephemeral) { id = generateIdentity(); saveIdentity(id, o.profile) }
      else id = loadOrCreateIdentity(o)
      printKeyBox(id.S)
      return
    }
    case 'doctor':
      return runDoctor()
    default:
      if (looksLikeKey(cmd)) return launchTui(argv) // `p2p <KEY>` -> TUI + dial
      console.error(red('  unknown command: ') + cmd + dim('   (try p2p --help)'))
      process.exit(2)
  }
}

main().catch((e) => { console.error(red('  ✗ ' + (e && e.message ? e.message : e))); process.exit(1) })
