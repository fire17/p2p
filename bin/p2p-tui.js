#!/usr/bin/env node
// p2p-tui — a full-screen terminal chat UI over the p2p framework. Zero deps: raw ANSI +
// node:tty raw mode, no blessed/ink. Header (my id + key + status + peers), scrollable
// message log, bottom input line. Commands start with '/'. Everything else is sent to all
// connected peers. The first-ack (MITM proof) surfaces as a system line + a green status.
//
// Usage:  p2p-tui [KEY] [--ephemeral] [--profile <name>]
//   no KEY  -> go online + listen; share your key with a friend
//   KEY     -> also dial that 26-char key on start
//
// ponytail: one file, Node built-ins only. Reuses ../src/node.js (network) via bin/lib.js.

import process from 'node:process'
import {
  loadNode, loadOrCreateIdentity, decodeKey, TypoError,
  peerLabel, shortId, loadFriends, addFriend, resolveFriend, peerKey, parseShare, looksLikeShare,
  isOwnKey, OWN_KEY_MSG,
  drainBounded, keyAction, createHistory, clampScroll,
} from './lib.js'

const ESC = '\x1b['
const alt = (on) => process.stdout.write(on ? ESC + '?1049h' : ESC + '?1049l')
const cursor = (on) => process.stdout.write(on ? ESC + '?25h' : ESC + '?25l')
const moveTo = (row, col) => ESC + row + ';' + col + 'H'
const CLR_EOL = ESC + 'K'

// palette (kept inline so the TUI owns its own look)
const P = {
  head: (s) => `${ESC}30;46m${s}${ESC}0m`, // black on cyan bar
  ok: (s) => `${ESC}1;32m${s}${ESC}0m`,
  warn: (s) => `${ESC}33m${s}${ESC}0m`,
  err: (s) => `${ESC}31m${s}${ESC}0m`,
  dim: (s) => `${ESC}2m${s}${ESC}0m`,
  me: (s) => `${ESC}36m${s}${ESC}0m`,
  them: (s) => `${ESC}35m${s}${ESC}0m`,
  sys: (s) => `${ESC}2;33m${s}${ESC}0m`,
  bold: (s) => `${ESC}1m${s}${ESC}0m`,
}
const stripLen = (s) => s.replace(/\x1b\[[0-9;]*m/g, '').length // visible width

// ── state ─────────────────────────────────────────────────────────────────────
const state = {
  id: null,
  node: null,
  msgs: [], // {who, text, kind: 'me'|'them'|'sys', label}
  input: '',
  status: 'starting…',
  statusKind: 'warn', // ok|warn|err
  peers: () => [],
  scroll: 0, // lines scrolled up from bottom (0 = live)
  unread: 0, // messages that landed while scrolled back
  hist: createHistory(), // ↑/↓ recall of what YOU sent
}

function add(kind, text, label = '') {
  // If the user is READING SCROLLBACK, a new message must not yank them to the bottom (that made
  // the log unreadable the moment anyone typed). Grow the offset by the lines we just appended so
  // the same content stays under their eyes, and count it as unread instead.
  const before = state.scroll > 0 ? renderMsgLines(cols()).length : 0
  state.msgs.push({ kind, text, label })
  if (state.msgs.length > 5000) state.msgs.splice(0, 1000) // bound memory
  if (state.scroll > 0) {
    const grew = renderMsgLines(cols()).length - before
    if (grew > 0) state.scroll += grew
    state.unread++
  }
  render()
}

// ── layout / render ─────────────────────────────────────────────────────────
function cols() { return process.stdout.columns || 80 }
function rows() { return process.stdout.rows || 24 }

// wrap one logical message into visible lines that fit `width`
function wrap(prefix, text, width) {
  const words = String(text).split(/(\s+)/)
  const lines = []
  let line = prefix
  const budget = () => width - stripLen(line)
  for (const w of words) {
    if (stripLen(w) <= budget()) { line += w; continue }
    // word longer than remaining space
    if (stripLen(line) > stripLen(prefix)) { lines.push(line); line = ' '.repeat(stripLen(prefix)) }
    // hard-break very long tokens
    let rest = w
    while (stripLen(rest) > width - stripLen(prefix)) {
      const take = width - stripLen(prefix)
      lines.push(line + rest.slice(0, take)); line = ' '.repeat(stripLen(prefix)); rest = rest.slice(take)
    }
    line += rest
  }
  lines.push(line)
  return lines
}

function renderMsgLines(width) {
  const out = []
  for (const m of state.msgs) {
    let prefix, body
    if (m.kind === 'me') { prefix = P.me('you › '); body = m.text }
    else if (m.kind === 'them') { prefix = P.them(m.label + ' › '); body = m.text }
    else { prefix = P.sys('  · '); body = P.sys(m.text) }
    for (const l of wrap(prefix, body, width)) out.push(l)
  }
  return out
}

let rendering = false
function render() {
  if (rendering) return
  rendering = true
  queueMicrotask(() => { rendering = false; draw() })
}

function draw() {
  const W = cols(), H = rows()
  const buf = []
  cursor(false)
  buf.push(moveTo(1, 1))

  // header
  const me = shortId(state.id.S)
  const st = state.statusKind === 'ok' ? P.ok(state.status)
    : state.statusKind === 'err' ? P.err(state.status) : P.warn(state.status)
  const n = state.peers().length
  const left = ` p2p · me:${me} · ${state.status} · peers:${n} `
  const right = ` /help · /key · /quit `
  const padN = Math.max(1, W - stripLen(P.head(left)) - stripLen(P.head(right)))
  buf.push(P.head(left + ' '.repeat(padN) + right) + CLR_EOL)

  // message viewport (rows 2 .. H-2)
  const viewH = Math.max(1, H - 3)
  const all = renderMsgLines(W)
  state.scroll = clampScroll(state.scroll, all.length, viewH)
  if (state.scroll === 0) state.unread = 0
  const end = all.length - state.scroll
  const start = Math.max(0, end - viewH)
  const window = all.slice(start, end)
  for (let i = 0; i < viewH; i++) {
    buf.push(moveTo(2 + i, 1) + (window[i] || '') + CLR_EOL)
  }

  // status/separator line (H-1) — also where scrolling advertises itself
  const hint = state.scroll > 0
    ? P.warn(`  ⟂ scrollback ${state.scroll} line${state.scroll === 1 ? '' : 's'} up`
      + (state.unread ? ` · ${state.unread} new below` : '') + ' — PgDn/End for live')
    : P.dim('  ↑/↓ history · PgUp/PgDn scroll · Ctrl-C quit')
  buf.push(moveTo(H - 1, 1) + hint + CLR_EOL)

  // input line (H)
  const promptStr = P.bold('› ')
  const avail = W - stripLen(promptStr) - 1
  const shown = state.input.length > avail ? state.input.slice(state.input.length - avail) : state.input
  buf.push(moveTo(H, 1) + promptStr + shown + CLR_EOL)
  process.stdout.write(buf.join(''))
  // place cursor after input
  process.stdout.write(moveTo(H, stripLen(promptStr) + shown.length + 1))
  cursor(true)
}

// ── scrolling ─────────────────────────────────────────────────────────────────
const viewH = () => Math.max(1, rows() - 3)          // same viewport draw() uses
const page = () => Math.max(1, rows() - 5)
const totalLines = () => renderMsgLines(cols()).length
function scrollBy(n) { scrollTo(state.scroll + n) }
function scrollTo(n) {
  state.scroll = clampScroll(n, totalLines(), viewH())
  if (state.scroll === 0) state.unread = 0
  render()
}

// ── input handling (raw mode) ─────────────────────────────────────────────────
// RAW MODE means the terminal's line discipline is OFF: Ctrl-C is delivered as the byte 0x03,
// NOT as SIGINT. So the ONLY thing that can honour Ctrl-C here is this handler — and it must do
// so unconditionally, before anything that could throw or block. Hence the check sits first.
function onKey(str) {
  const act = keyAction(str)
  if (act === 'quit-force') return forceExit(130) // Ctrl-C / Ctrl-D — always, even mid-connect
  if (act) return doAction(act)
  for (const ch of str) {
    const code = ch.codePointAt(0)
    if (ch === '\x03' || ch === '\x04') return forceExit(130) // belt-and-braces (e.g. inside a paste)
    if (ch === '\r' || ch === '\n') { submit(); continue }
    if (ch === '\x7f' || ch === '\b') { state.input = state.input.slice(0, -1); render(); continue }
    if (ch === '\x15') { state.input = ''; render(); continue } // Ctrl-U clear line
    if (ch === '\x1b') return // a lone/unrecognised escape sequence: swallow, never print it
    if (code >= 0x20) { state.input += ch; render() }
  }
}

function doAction(act) {
  switch (act) {
    case 'hist-prev': state.input = state.hist.prev(state.input); render(); break
    case 'hist-next': state.input = state.hist.next(state.input); render(); break
    case 'page-up': scrollBy(page()); break
    case 'page-down': scrollBy(-page()); break
    case 'line-up': scrollBy(1); break
    case 'line-down': scrollBy(-1); break
    case 'scroll-top': scrollTo(totalLines()); break // clamped to the oldest line
    case 'scroll-live': scrollTo(0); break
  }
}

let inflight = Promise.resolve()
function submit() {
  const text = state.input
  state.input = ''
  if (!text.trim()) { render(); return }
  state.hist.remember(text) // ↑/↓ recall — commands too (re-dialling a 26-char key by hand is the pain)
  if (text.startsWith('/')) return command(text.trim())
  const peers = state.peers()
  if (peers.length === 0) { add('sys', 'no peer connected yet — share your key or /connect <key>'); return }
  add('me', text)
  inflight = inflight.then(() => Promise.all(peers.map((p) => p.send(text).catch((e) => add('sys', 'send failed: ' + e.message)))))
}

function command(line) {
  const [cmd, ...rest] = line.slice(1).split(/\s+/)
  const arg = rest.join(' ')
  switch (cmd) {
    case 'help': case '?':
      add('sys', 'commands: /connect <key|S-invite|friend> · /friends · /key · /peers · /clear · /quit')
      add('sys', 'keys: ↑/↓ recall what you sent · PgUp/PgDn scroll · Home/End oldest/live · Shift+↑/↓ one line · Ctrl-C quit (always)')
      break
    case 'key':
      add('sys', 'your key (share it): ' + state.id.S); break
    case 'peers': {
      const ps = state.peers()
      add('sys', ps.length ? 'connected: ' + ps.map(peerLabel).join(', ') : 'no peers connected'); break
    }
    case 'friends': case 'f': {
      const list = loadFriends(state.profile).sort((a, b) => b.lastSeen - a.lastSeen)
      if (!list.length) { add('sys', 'no friends yet — connect with someone and they\'re saved'); break }
      add('sys', `friends (${list.length}): ` + list.map((f) => (f.nick || shortId(f.key))).join(', '))
      add('sys', 'reconnect: /connect <name>')
      break
    }
    case 'connect': case 'c':
      // an invite share string is never a friend name — dial it verbatim
      dial(looksLikeShare(arg) ? arg : (resolveFriend(arg, state.profile) || arg)); break
    case 'clear':
      state.msgs = []; render(); break
    case 'quit': case 'q': case 'exit':
      quit(); break
    default:
      add('sys', 'unknown command /' + cmd + ' — try /help')
  }
  render()
}

async function dial(key) {
  key = String(key).trim().toUpperCase()
  if (!key) { add('sys', 'usage: /connect <26-char-key | S-invite-share>'); return }
  let share
  try { share = parseShare(key); decodeKey(share.S) } catch (e) {    // bare S, or a one-time invite share
    add('sys', e instanceof TypoError ? 'bad key: ' + e.message : 'bad key'); return
  }
  // own-key guard: dialing your own key never connects (you'd be talking to yourself).
  if (isOwnKey(share.S, state.id.S)) { add('sys', '✗ ' + OWN_KEY_MSG); setStatus('online (idle)', 'ok'); return }
  add('sys', `connecting to ${shortId(share.S)} · resolving rendezvous, punching NAT, Noise ${share.secret ? 'IKpsk2 (private invite)' : 'IK'}…`)
  setStatus('connecting…', 'warn')
  try {
    const peer = await state.node.connect(key)
    add('sys', `✅ secure channel established — verified, no MITM (peer ${peerLabel(peer)})`)
    setStatus('online', 'ok')
  } catch (e) {
    add('sys', '✗ connect failed: ' + e.message)
    setStatus('online (idle)', 'ok')
  }
}

function setStatus(s, kind = 'warn') { state.status = s; state.statusKind = kind; render() }

// ── lifecycle: EXIT MUST ALWAYS WIN ───────────────────────────────────────────
// The old quit() did `await inflight` behind a `quitting` re-entrancy guard. peer.send() resolves
// only on its ACK (src/node.js), so a dead/hung peer NEVER settles it: the first Ctrl-C hung in
// that await, and `if (quitting) return` then swallowed every retry — an unkillable process with a
// wrecked terminal. Rules now: (1) nothing on the exit path awaits a network promise; (2) the
// terminal is restored FIRST, so even a later throw leaves a usable shell; (3) exit is synchronous.

/** Put the terminal back the way we found it. Safe to call twice, safe to call mid-crash. */
function restoreTerminal() {
  try { process.stdin.setRawMode?.(false) } catch { /* */ }
  try { process.stdin.pause() } catch { /* */ }
  try { cursor(true) } catch { /* */ }
  try { alt(false) } catch { /* */ }
  try { process.stdout.write('\n') } catch { /* */ }
}

/** The last word, always. Synchronous, unconditional, never awaits anything. */
let closed = false
function forceExit(code = 130) {
  restoreTerminal()
  if (!closed) { closed = true; try { state.node?.close?.() } catch { /* */ } } // sync/best-effort in node.js
  process.exit(code)
}

/** /quit — same teardown, but give in-flight sends a BOUNDED moment to land first. */
async function quit() {
  add('sys', 'closing…')
  await drainBounded(inflight, 300) // never unbounded: a dead peer's send never settles
  forceExit(0)
}

async function main() {
  // Wire the escape hatches BEFORE anything that can hang (listen/dial can block on the network),
  // and before raw mode swallows Ctrl-C. A signal must never be gated on app state.
  process.on('SIGINT', () => forceExit(130))
  process.on('SIGTERM', () => forceExit(143))
  process.on('SIGHUP', () => forceExit(129))
  // A crash in raw + alt-screen mode would otherwise hand the user a dead terminal.
  process.on('uncaughtException', (e) => {
    restoreTerminal()
    console.error('p2p-tui crashed: ' + (e && e.message ? e.message : e))
    process.exit(1)
  })
  process.on('unhandledRejection', (e) => {
    restoreTerminal()
    console.error('p2p-tui crashed: ' + (e && e.message ? e.message : e))
    process.exit(1)
  })

  const args = process.argv.slice(2)
  const ephemeral = args.includes('--ephemeral')
  const pi = args.indexOf('--profile')
  const profile = pi >= 0 ? args[pi + 1] : 'default'
  const dialKey = args.find((a) => !a.startsWith('-') && a !== profile)

  if (!process.stdout.isTTY) {
    console.error('p2p-tui needs an interactive terminal (TTY). For pipes/scripts use: p2p-chat')
    process.exit(1)
  }

  state.profile = profile
  state.id = loadOrCreateIdentity({ ephemeral, profile })
  const mod = await loadNode()
  state.node = await mod.listen(state.id, {})
  state.peers = () => (state.node.peers ? state.node.peers() : [])

  state.node.on('message', (peer, data) => add('them', data.toString(), peerLabel(peer)))
  state.node.on('peer', (peer) => {
    const { isNew } = addFriend(peerKey(peer), { selfKey: state.id.S, profile })
    add('sys', `peer ${peerLabel(peer)} connected` + (isNew ? ' ✚ added to friends' : ''))
    setStatus('online', 'ok')
  })
  state.node.on('disconnect', (peer) => add('sys', `peer ${peerLabel(peer)} disconnected`))

  // screen setup
  alt(true)
  process.stdout.write(ESC + '2J')
  process.stdin.setRawMode?.(true)
  process.stdin.resume()
  process.stdin.setEncoding('utf8')
  process.stdin.on('data', (str) => {
    // Ctrl-C is checked HERE, ahead of every other code path: even if onKey/render is broken or
    // the app is mid-hang, this byte still gets the user their shell back.
    if (str.includes('\x03')) return forceExit(130)
    try { onKey(str) } catch { /* an input/render bug must never wedge the key loop */ }
  })
  process.stdout.on('resize', render)

  add('sys', 'welcome to p2p — share YOUR key so a friend can reach you:')
  add('sys', state.id.S)
  add('sys', ephemeral ? '(ephemeral identity — not saved)' : `(stable identity · profile "${profile}")`)
  add('sys', 'type a message to chat · /help for commands' + (dialKey ? '' : ' · /connect <key> to reach someone'))
  add('sys', '↑/↓ recall what you sent · PgUp/PgDn scroll back · Ctrl-C always quits')
  setStatus('online (idle)', 'ok')
  if (dialKey) dial(dialKey)
  render()
}

main().catch((e) => {
  try { cursor(true); alt(false) } catch { /* */ }
  console.error('p2p-tui error: ' + (e && e.message ? e.message : e))
  process.exit(1)
})
