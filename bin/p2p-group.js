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
import { randomBytes, createHash } from 'node:crypto'
import { createSecureGroup } from '../src/group.js'
import {
  loadNode, loadOrCreateIdentity, decodeKey, TypoError, drainBounded,
  bold, dim, red, green, cyan, yellow, magenta, peerLabel, shortId,
} from './lib.js'

// ── the group CODE ────────────────────────────────────────────────────────────
//
//   CODE = base64( G(32B) ‖ SHA256(G)[0..3) )        — 35 bytes, 48 chars
//
// The 3-byte checksum exists to kill the GHOST GROUP: raw base64(G) has no redundancy, so a single
// mistyped body character that happens to stay valid base64 decodes to a DIFFERENT G — hence a
// different groupId — and the victim sees a cheerful "joined" while sitting alone in a group nobody
// else is in, with no error, ever. A typo must fail LOUDLY at parse, not silently succeed into
// nowhere. 3 bytes ⇒ a mistyped code slips through ~1 in 16.7M, and the code stays one short line.
//
// G itself is UNCHANGED (still the 32-byte group secret the protocol hashes into groupId), so this
// is purely a transport encoding for humans — src/group.js is untouched.
//
// The browser mints and parses the SAME format with the SAME bytes (src/browser/app.js — its
// node:crypto shim gives it the identical sync SHA-256), so a code minted in either client parses in
// the other. That interop is the whole point; test/tui-group.test.js pins the checksum bytes.

const codeSum = (G) => createHash('sha256').update(G).digest().subarray(0, 3)

/** Encode a 32-byte group secret G as the shareable CODE (G ‖ 3-byte checksum, base64). */
export const encodeGroupCode = (G) => Buffer.concat([Buffer.from(G), codeSum(G)]).toString('base64')

/** A fresh group code. Treat it like a key: whoever holds it is in. */
export const newGroupCode = () => encodeGroupCode(randomBytes(32))

/**
 * Validate a pasted group code and return the raw 32-byte secret G.
 * Every failure mode below is LOUD on purpose — a group code that "works" but points at a group
 * nobody else is in is the worst outcome this CLI can produce.
 * @param {string} code
 * @returns {Buffer} G (32 bytes)
 */
export function parseGroupCode(code) {
  const s = String(code || '').trim()
  if (!s) throw new TypoError('no group code given')
  const raw = Buffer.from(s, 'base64')
  if (raw.length !== 35) throw new TypoError(`bad group code (decodes to ${raw.length} bytes, expected 35) — copy the whole code`)
  if (raw.toString('base64') !== s) throw new TypoError('bad group code (not valid base64) — copy it exactly, no spaces')
  const G = raw.subarray(0, 32)
  if (!codeSum(G).equals(raw.subarray(32))) {
    throw new TypoError('bad group code (checksum failed) — you likely mistyped or truncated it. Ask for the code again and paste it whole.')
  }
  return Buffer.from(G)
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
    // `code`, never group.secret: group.js hands back the RAW base64 G (no checksum), which is not a
    // shareable code any more — printing it would emit a string the other side now refuses at parse.
    if (cmd === '/code') return printLine(dim('  group code: ') + yellow(code))
    if (cmd === '/members') {
      const m = group.members()
      return printLine(dim('  members (') + m.length + dim('): ') + m.map((k) => (k === id.S.toUpperCase() ? bold(cyan(shortId(k) + ' (you)')) : shortId(k))).join(dim(', ')) +
        dim('  · admin ' + (group.admin() ? shortId(group.admin()) : 'none')))
    }
    if (cmd === '/add') {
      const k = String(arg || '').trim().toUpperCase()
      try { decodeKey(k) } catch { return printLine(red('  ✗ usage: /add <26-char-key>')) }
      if (group.admin() !== id.S.toUpperCase()) return printLine(red('  ✗ only the group admin can add members'))
      printLine(dim(`  adding ${shortId(k)}… — they must run: `) + bold('p2p group join ' + code))
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

  // ── teardown: Ctrl-C must ALWAYS exit ────────────────────────────────────────
  // peer.send() resolves ONLY on its ACK (src/node.js) — a send to a dead/hung peer NEVER settles.
  // The old shutdown did an unbounded `await inflight` behind `if (closing) return`, so the first
  // Ctrl-C hung in that await and the guard then swallowed every retry: an unkillable process. A
  // GROUP makes it likelier still — group.send() fans out to every member, so ONE dead member is
  // enough to trap the exit. Now the drain is BOUNDED, and a second Ctrl-C exits immediately.
  let closing = false   // a graceful shutdown has begun
  let exiting = false   // teardown is running — the first exit wins (rl.close() re-enters via 'close')
  const finish = (code) => {
    if (exiting) return // re-entered from the 'close' event below; let the in-flight exit stand
    exiting = true
    try { node.close() } catch { /* */ }
    try { rl.close() } catch { /* */ }
    try { process.stdin.setRawMode?.(false) } catch { /* */ } // readline raw-mode: hand back a sane shell
    process.exit(code)
  }
  const shutdown = async () => {
    if (closing) return finish(130) // a SECOND Ctrl-C: stop waiting for anything, get out now
    closing = true
    await drainBounded(inflight, 300) // let a landing ack finish — but NEVER hang on it
    console.log('\n' + dim('  closing…'))
    finish(0)
  }
  rl.on('SIGINT', shutdown)
  rl.on('close', () => { if (process.stdin.isTTY) shutdown() })
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', () => finish(143))
  process.on('SIGHUP', () => finish(129))
}

// Runnable on its own (`node bin/p2p-group.js new KEY…`) as well as via `p2p group`.
if (process.argv[1] && process.argv[1].endsWith('p2p-group.js')) {
  const argv = process.argv.slice(2)
  const i = argv.indexOf('--profile')
  const o = { ephemeral: argv.includes('--ephemeral'), profile: (i >= 0 ? argv[i + 1] : undefined) || 'default' }
  const positional = argv.filter((a, n) => !a.startsWith('-') && argv[n - 1] !== '--profile')
  groupMain(positional, o).catch((e) => { console.error(red('  ✗ ' + (e && e.message ? e.message : e))); process.exit(1) })
}
