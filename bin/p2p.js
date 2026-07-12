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
  mintInvite, parseShare, looksLikeShare, isOwnKey, OWN_KEY_MSG,
} from './lib.js'

const HERE = dirname(fileURLToPath(import.meta.url))

function flagVal(args, name) { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined }
function opts(args) {
  return { ephemeral: args.includes('--ephemeral'), profile: flagVal(args, '--profile') || 'default' }
}

// ── key display ────────────────────────────────────────────────────────────────
function printBox(title, value, color = green) {
  const W = Math.max(title.length, value.length) + 4
  const bar = '─'.repeat(W)
  const pad = (s) => '  ' + s + ' '.repeat(W - 2 - s.length)
  console.log('\n' + cyan('  ┌' + bar + '┐'))
  console.log(cyan('  │') + bold(pad(title)) + cyan('│'))
  console.log(cyan('  ├' + bar + '┤'))
  console.log(cyan('  │') + bold(color(pad(value))) + cyan('│'))
  console.log(cyan('  └' + bar + '┘'))
  console.log(dim('  they run:  ') + bold('p2p ' + value) + dim('   (or: p2p connect ' + value + ')') + '\n')
}

function printKeyBox(S) {
  printBox('YOUR p2p KEY — share with a friend', S)
}

/** One-time invite share string: the key + its per-invite secret tail (metadata privacy). */
function printInviteBox(share) {
  printBox('ONE-TIME INVITE — send to ONE person', share, yellow)
  console.log(dim('  single-use: only the holder of this string can find, decrypt or reach this node.'))
  console.log(dim('  it lives while this process runs — quit and the invite is gone (mint a new one).') + '\n')
}

// ── line-mode chat (stable identity, real network) ──────────────────────────────
// `mintInviteMode: true` => publish under a fresh one-time K_inv instead of the reusable S.
// The invite MUST be minted from the identity this node actually listens as — minting it earlier,
// from a separate loadOrCreateIdentity() call, silently breaks under --ephemeral (that call returns a
// NEW random identity every time), and the invitee then fails the commitment gate against a key
// nobody is listening on. Caught by the two-process gate; keep the mint and the listen on one id.
async function lineMode({ dialKey, ephemeral, profile, mintInviteMode = false }) {
  const id = loadOrCreateIdentity({ ephemeral, profile })
  // own-key guard: refuse dialing yourself BEFORE any network work (never go online to self-dial).
  if (dialKey && isOwnKey(dialKey, id.S)) { console.error(red('  ✗ ') + OWN_KEY_MSG); process.exit(2) }
  const invite = mintInviteMode ? mintInvite(id) : null
  const mod = await loadNode()
  const node = await mod.listen(id, invite ? { invite: invite.secret } : {})
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
    let share
    try { share = parseShare(String(dialKey).trim()); decodeKey(share.S) } catch (e) {   // bare S or an S-<tail> invite
      if (e instanceof TypoError) { console.error(red('  ✗ bad key: ') + e.message); process.exit(2) }
      throw e
    }
    console.log(dim('  your key: ') + cyan(id.S))
    console.log(dim('  connecting to ') + cyan(shortId(share.S)) +
      dim(' · rendezvous + NAT punch + Noise ' + (share.secret ? 'IKpsk2 (private invite)…' : 'IK…')))
    try {
      const peer = await node.connect(dialKey)
      console.log('\n' + green(bold('  ✅ secure channel established — verified, no MITM')) + dim('  (peer ' + peerLabel(peer) + ')'))
    } catch (e) { console.error(red('  ✗ connect failed: ') + e.message); process.exit(3) }
  } else if (invite) {
    printInviteBox(invite.share)
    console.log(dim('  listening (private invite mode) · rendezvous record is sealed — only your invitee can read it…'))
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
  ${bold('p2p connect')} <KEY|SHARE|name>  line-mode: dial a key, an invite share string, or a friend
  ${bold('p2p invite')}              mint a ONE-TIME private invite (S-…) and listen for it
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
      if (!arg) { console.error(red('  usage: p2p connect <26-char-key | S-invite-share | friend-name>')); process.exit(2) }
      // an invite share string is never a friend name — try it verbatim first
      const key = looksLikeShare(arg) ? arg : (resolveFriend(arg, o.profile) || arg)
      return lineMode({ dialKey: key, ...o })
    }
    case 'invite':
      // Mint a fresh one-time K_inv for THIS identity, print the share string, and go online in
      // invite mode: presence is published only under rid_inv, sealed under k_ip (metadata privacy).
      return lineMode({ dialKey: null, mintInviteMode: true, ...o })
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
      if (looksLikeShare(cmd)) return launchTui(argv) // `p2p <KEY>` / `p2p <S-INVITE>` -> TUI + dial
      console.error(red('  unknown command: ') + cmd + dim('   (try p2p --help)'))
      process.exit(2)
  }
}

main().catch((e) => { console.error(red('  ✗ ' + (e && e.message ? e.message : e))); process.exit(1) })
