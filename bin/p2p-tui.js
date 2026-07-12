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
}

function add(kind, text, label = '') {
  state.msgs.push({ kind, text, label })
  if (state.msgs.length > 5000) state.msgs.splice(0, 1000) // bound memory
  state.scroll = 0
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
  const maxScroll = Math.max(0, all.length - viewH)
  if (state.scroll > maxScroll) state.scroll = maxScroll
  const end = all.length - state.scroll
  const start = Math.max(0, end - viewH)
  const window = all.slice(start, end)
  for (let i = 0; i < viewH; i++) {
    buf.push(moveTo(2 + i, 1) + (window[i] || '') + CLR_EOL)
  }

  // status/separator line (H-1)
  const hint = state.scroll > 0 ? P.dim(`  ⟂ scrolled ${state.scroll} lines — PgDn/End for live`) : P.dim('  ')
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

// ── input handling (raw mode) ─────────────────────────────────────────────────
function onKey(str) {
  for (const ch of str) {
    const code = ch.codePointAt(0)
    if (ch === '\x03') return quit() // Ctrl-C
    if (ch === '\r' || ch === '\n') { submit(); continue }
    if (ch === '\x7f' || ch === '\b') { state.input = state.input.slice(0, -1); render(); continue }
    if (ch === '\x15') { state.input = ''; render(); continue } // Ctrl-U clear line
    if (str.startsWith('\x1b[')) { handleEscape(str); return } // arrow/pgup as a unit
    if (code >= 0x20 && ch !== '\x1b') { state.input += ch; render() }
  }
}
function handleEscape(seq) {
  if (seq === '\x1b[5~') { state.scroll += Math.max(1, rows() - 5); render() } // PgUp
  else if (seq === '\x1b[6~') { state.scroll = Math.max(0, state.scroll - (rows() - 5)); render() } // PgDn
  else if (seq === '\x1b[F' || seq === '\x1bOF') { state.scroll = 0; render() } // End -> live
}

let inflight = Promise.resolve()
function submit() {
  const text = state.input
  state.input = ''
  if (!text.trim()) { render(); return }
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
      add('sys', 'commands: /connect <key|S-invite|friend> · /friends · /key · /peers · /clear · /quit'); break
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

// ── lifecycle ─────────────────────────────────────────────────────────────────
let quitting = false
async function quit() {
  if (quitting) return
  quitting = true
  try { await inflight } catch { /* drain sends */ }
  try { state.node?.close?.() } catch { /* */ }
  try { process.stdin.setRawMode?.(false) } catch { /* */ }
  cursor(true); alt(false)
  process.stdout.write('\n')
  process.exit(0)
}

async function main() {
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
  process.stdin.on('data', onKey)
  process.stdout.on('resize', render)
  process.on('SIGINT', quit)
  process.on('SIGTERM', quit)

  add('sys', 'welcome to p2p — share YOUR key so a friend can reach you:')
  add('sys', state.id.S)
  add('sys', ephemeral ? '(ephemeral identity — not saved)' : `(stable identity · profile "${profile}")`)
  add('sys', 'type a message to chat · /help for commands' + (dialKey ? '' : ' · /connect <key> to reach someone'))
  setStatus('online (idle)', 'ok')
  if (dialKey) dial(dialKey)
  render()
}

main().catch((e) => {
  try { cursor(true); alt(false) } catch { /* */ }
  console.error('p2p-tui error: ' + (e && e.message ? e.message : e))
  process.exit(1)
})
