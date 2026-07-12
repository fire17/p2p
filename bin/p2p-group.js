#!/usr/bin/env node
// p2p group — terminal GROUP chat: sender keys + a signed membership hash-chain, riding the SAME
// pairwise Noise links the 1:1 chat already uses (src/group.js, DESIGN BC-7). No new transport.
//
//   p2p group new [KEY ...]    create a group whose members are the 26-char keys you list → prints
//                              the GROUP CODE (share it with them, like a key)
//   p2p group join <CODE>      join a group you were given the code for
//
//   in-chat:  /members   /add <KEY> (admin only)   /code   /quit
//
// The browser client runs this same src/group.js over the same wire, so a TUI member and a browser
// member are in one group by construction (witnessed by test/browser-group-tui.mjs).
//
// ponytail: one file, node:readline, zero deps. The exported helpers below are what the CLI itself
// calls — test/tui-group.test.js drives THOSE, so the test proves the shipped path, not a copy.

import readline from 'node:readline'
import { randomBytes } from 'node:crypto'
import { createSecureGroup } from '../src/group.js'
import {
  loadNode, loadOrCreateIdentity, decodeKey, TypoError,
  bold, dim, red, green, cyan, yellow, magenta, peerLabel, shortId,
} from './lib.js'

// ── group code: base64 of the 32-byte group secret G (exactly what the browser shows/accepts) ──

/** A fresh group code — 32 random bytes, base64. Treat it like a key: whoever holds it is in. */
export const newGroupCode = () => randomBytes(32).toString('base64')

/**
 * Validate a pasted group code and return the raw 32-byte secret G.
 * Strict: a truncated/typo'd code must fail LOUDLY here, not silently produce a different groupId
 * (which would look like "joined" while nobody can ever hear you).
 * @param {string} code
 * @returns {Buffer} G (32 bytes)
 */
export function parseGroupCode(code) {
  const s = String(code || '').trim()
  if (!s) throw new TypoError('no group code given')
  const G = Buffer.from(s, 'base64')
  if (G.length !== 32) throw new TypoError(`bad group code (decodes to ${G.length} bytes, expected 32) — copy the whole code`)
  if (G.toString('base64') !== s) throw new TypoError('bad group code (not valid base64) — copy it exactly, no spaces')
  return G
}

/**
 * Build the secure group for a listening node. Not joined yet — the caller attaches its handlers
 * first, then awaits group.join() (the browser client does exactly this order).
 * @param {object} node      from node.listen()
 * @param {object} identity  from loadOrCreateIdentity()
 * @param {{code:string, members?:string[], create?:boolean}} o
 */
export function makeGroup(node, identity, { code, members = [], create = false }) {
  return createSecureGroup(node, identity, { secret: parseGroupCode(code), members, create })
}

// ── display ────────────────────────────────────────────────────────────────────
function printCodeBox(code) {
  const W = code.length + 4
  const bar = '─'.repeat(W)
  const pad = (s) => '  ' + s + ' '.repeat(W - 2 - s.length)
  console.log('\n' + cyan('  ┌' + bar + '┐'))
  console.log(cyan('  │') + bold(pad('GROUP CODE — share with the members')) + cyan('│'))
  console.log(cyan('  ├' + bar + '┤'))
  console.log(cyan('  │') + bold(yellow(pad(code))) + cyan('│'))
  console.log(cyan('  └' + bar + '┘'))
  console.log(dim('  they run:  ') + bold('p2p group join ' + code) + '\n')
}

const HELP = `${bold('p2p group')} — end-to-end encrypted group chat in the terminal

  ${bold('p2p group new')} [KEY ...]   create a group with those 26-char member keys → prints the CODE
  ${bold('p2p group join')} <CODE>     join a group you were given the code for

  in-chat:  ${dim('/members')}   ${dim('/add <KEY>')} (admin only)   ${dim('/code')}   ${dim('/quit')}

  flags:  ${dim('--ephemeral')} throwaway identity   ${dim('--profile <name>')} separate key

  Members must be ONLINE (running p2p group join) for the creator to hand them a sender key.
  The same group works with the browser client — same code, same protocol.`

// ── the CLI ────────────────────────────────────────────────────────────────────
/**
 * @param {string[]} positional  sub-command + args, e.g. ['new','KEY1'] / ['join','<CODE>']
 * @param {{ephemeral?:boolean, profile?:string}} o
 */
export async function groupMain(positional = [], o = {}) {
  const sub = positional[0]
  if (!sub || sub === 'help' || sub === '--help') { console.log(HELP); return }
  if (sub !== 'new' && sub !== 'join') {
    console.error(red('  unknown: p2p group ') + sub + dim('   (try p2p group --help)'))
    process.exit(2)
  }

  const id = loadOrCreateIdentity(o)
  const create = sub === 'new'

  // members / code, validated BEFORE any network work (never go online just to fail on a typo)
  let code, members = []
  if (create) {
    for (const raw of positional.slice(1)) {
      const k = String(raw).trim().toUpperCase()
      try { decodeKey(k) } catch (e) {
        if (e instanceof TypoError) { console.error(red('  ✗ bad member key: ') + e.message); process.exit(2) }
        throw e
      }
      if (k === id.S.toUpperCase()) continue        // your own key is implicit — never list yourself
      if (!members.includes(k)) members.push(k)
    }
    code = newGroupCode()
  } else {
    try { parseGroupCode(positional[1]) } catch (e) {
      console.error(red('  ✗ ') + e.message); process.exit(2)
    }
    code = String(positional[1]).trim()
  }

  const mod = await loadNode()
  const node = await mod.listen(id)

  let rl = null
  const printLine = (line) => {
    if (rl) { readline.cursorTo(process.stdout, 0); readline.clearLine(process.stdout, 0) }
    console.log(line)
    if (rl) rl.prompt(true)
  }

  node.on('peer', (peer) => printLine(dim('  · peer ' + peerLabel(peer) + ' connected')))
  node.on('disconnect', (peer) => printLine(dim('  · peer ' + peerLabel(peer) + ' disconnected')))

  const group = makeGroup(node, id, { code, members, create })
  group.on('message', (from, data) =>
    printLine(bold(magenta(shortId(from) + ' › ')) + Buffer.from(data).toString('utf8')))
  group.on('membership', (list) => printLine(dim(`  · membership: ${list.length} member${list.length === 1 ? '' : 's'}`)))
  // Divergence is never silent: a forged author, a rival create, a sender key we don't hold yet.
  group.on('divergence', (d) => printLine(yellow('  ⚠ ' + d.reason) + dim(d.by ? '  by ' + shortId(d.by) : '')))

  console.log(dim('  your key: ') + cyan(id.S))
  if (create) {
    printCodeBox(code)
    if (!members.length) {
      console.log(yellow('  empty group') + dim(' — nobody was listed. Add members with /add <KEY> once they are online.\n'))
    } else {
      console.log(dim('  members: ') + members.map(shortId).join(dim(', ')) + dim('  — handing them sender keys…\n'))
    }
  } else {
    console.log(dim('  joining group ') + cyan(group.groupId.slice(0, 12) + '…') +
      dim(' — the creator must have listed YOUR key above (or /add you).\n'))
  }

  await group.join()   // hand my sender key to every member I know; pull the ones I'm missing

  rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: cyan('you › ') })
  let inflight = Promise.resolve()

  const send = async (text) => {
    try {
      const r = await group.send(text)
      if (r.relayed.length) {
        printLine(dim(`  · ${r.delivered.length} direct, ${r.relayed.length} via relay (${r.relayed.map(shortId).join(', ')} not reachable)`))
      } else if (!r.delivered.length) {
        printLine(dim('  (no other member online yet — nobody received that)'))
      }
    } catch (e) { printLine(red('  ✗ send failed: ') + e.message) }
  }

  const command = async (text) => {
    const [cmd, arg] = text.split(/\s+/)
    if (cmd === '/quit' || cmd === '/exit') return shutdown()
    if (cmd === '/code') return printLine(dim('  group code: ') + yellow(group.secret))
    if (cmd === '/members') {
      const m = group.members()
      return printLine(dim('  members (') + m.length + dim('): ') + m.map((k) => (k === id.S.toUpperCase() ? bold(cyan(shortId(k) + ' (you)')) : shortId(k))).join(dim(', ')) +
        dim('  · admin ' + (group.admin() ? shortId(group.admin()) : 'none')))
    }
    if (cmd === '/add') {
      const k = String(arg || '').trim().toUpperCase()
      try { decodeKey(k) } catch { return printLine(red('  ✗ usage: /add <26-char-key>')) }
      if (group.admin() !== id.S.toUpperCase()) return printLine(red('  ✗ only the group admin can add members'))
      printLine(dim(`  adding ${shortId(k)}… — they must run: `) + bold('p2p group join ' + group.secret))
      try { await group.add(k); printLine(green('  ✔ added ') + shortId(k)) }
      catch (e) { printLine(red('  ✗ add failed: ') + e.message) }
      return
    }
    printLine(dim('  commands: /members  /add <KEY>  /code  /quit'))
  }

  rl.prompt()
  rl.on('line', (line) => {
    const text = line.trim()
    if (text.startsWith('/')) inflight = inflight.then(() => command(text))
    else if (text) inflight = inflight.then(() => send(text))
    rl.prompt()
  })

  let closing = false
  async function shutdown() {
    if (closing) return
    closing = true
    try { await inflight } catch { /* */ }
    console.log('\n' + dim('  closing…'))
    try { node.close() } catch { /* */ }
    try { rl.close() } catch { /* */ }
    process.exit(0)
  }
  rl.on('SIGINT', shutdown)
  rl.on('close', () => { if (process.stdin.isTTY) shutdown() })
  process.on('SIGINT', shutdown)
}

// Runnable on its own (`node bin/p2p-group.js new KEY…`) as well as via `p2p group`.
if (process.argv[1] && process.argv[1].endsWith('p2p-group.js')) {
  const argv = process.argv.slice(2)
  const i = argv.indexOf('--profile')
  const o = { ephemeral: argv.includes('--ephemeral'), profile: (i >= 0 ? argv[i + 1] : undefined) || 'default' }
  const positional = argv.filter((a, n) => !a.startsWith('-') && argv[n - 1] !== '--profile')
  groupMain(positional, o).catch((e) => { console.error(red('  ✗ ' + (e && e.message ? e.message : e))); process.exit(1) })
}
