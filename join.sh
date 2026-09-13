#!/bin/sh
# p2p.akeyo.io/join.sh — ONE static script for every machine. The listener key is a PARAMETER, never a file on this site:
#   curl -fsSL https://p2p.akeyo.io/join.sh | sh -s -- <LISTENER_KEY>
# The key is the only argument (share it as https://p2p.akeyo.io/#/join/<LISTENER_KEY> — the page renders this line client-side).
# On a Linux server (systemd present, run as root or with passwordless sudo) it also installs the keeper service (rejoin after
# reboot) and enables the owner terminal grant for the listener — the owner running it IS the consent. Add --chat-only to skip that.
# Derived from tools/render-join.mjs (same SHA-pinned installer, same join helper). Inspect before running.
p2p_join_main() {
  set -eu
  umask 077
  JOIN_KEY="${P2P_JOIN_KEY:-}"
  case "$JOIN_KEY" in *[!0123456789ABCDEFGHJKMNPQRSTVWXYZ]*|'') echo 'Invalid listener key' >&2; return 2;; esac
  [ "${#JOIN_KEY}" -eq 26 ] || { echo 'Invalid listener key length' >&2; return 2; }
  echo "Agent Tunnel: install verified Bun + p2p v0.3.8; connect chat to $JOIN_KEY."
  echo 'Your machine name, username, OS and architecture will be sent to this peer.'
  if [ "${JOIN_MODE:-}" = --server ]; then echo 'SERVER MODE (owner command): the chat daemon is kept alive across reboots and the listener owner gets terminal access on this machine.'; else echo 'The chat daemon continues after this command exits. This join line does not enable remote terminal access.'; fi
  JOIN_TMP="$(mktemp -d "${TMPDIR:-/tmp}/p2p-join.XXXXXX")"
  trap 'rm -rf "$JOIN_TMP"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 15 --max-time 120 --retry 2 'https://raw.githubusercontent.com/fire17/p2p/c26fde63ea01164bcbdb470e3c6a6f69682f748b/init' -o "$JOIN_TMP/init"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=120 -O "$JOIN_TMP/init" 'https://raw.githubusercontent.com/fire17/p2p/c26fde63ea01164bcbdb470e3c6a6f69682f748b/init'
  else echo 'curl or wget is required' >&2; return 1; fi
  if command -v sha256sum >/dev/null 2>&1; then JOIN_HASH="$(sha256sum "$JOIN_TMP/init" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then JOIN_HASH="$(shasum -a 256 "$JOIN_TMP/init" | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then JOIN_HASH="$(openssl dgst -sha256 "$JOIN_TMP/init" | awk '{print $NF}')"
  else echo 'A SHA256 tool is required; refusing to execute the installer' >&2; return 1; fi
  [ "$JOIN_HASH" = '71833d1f4b1d305f8fc551151182c113ea93ca5c02b3f5dc4a0c89ad0a0826cd' ] || { echo 'Installer SHA256 mismatch; nothing was executed' >&2; return 1; }
  P2P_HOME="${P2P_HOME:-$HOME/.p2p}"
  export P2P_HOME
  P2P_RUNTIME=bun P2P_REF=v0.3.8 \
    P2P_SRC=https://github.com/fire17/p2p/releases/download/v0.3.8/p2p-v0.3.8.tar.gz \
    P2P_SRC_SUMS=https://github.com/fire17/p2p/releases/download/v0.3.8/SHASUMS256.txt \
    sh "$JOIN_TMP/init" </dev/null
  [ "$(cat "$P2P_HOME/runtime.kind")" = bun ] || { echo 'Installer did not select Bun' >&2; return 1; }
  JOIN_RUNTIME="$(cat "$P2P_HOME/runtime.path")"
  [ -x "$JOIN_RUNTIME" ] || { echo 'The installed Bun runtime is missing' >&2; return 1; }
  cat >"$JOIN_TMP/join.mjs" <<'P2P_JOIN_HELPER'
// Embedded by render-join.mjs after the SHA-pinned installer succeeds.
// Only chat operations: local terminal permission is never requested or enabled here.
import { spawnSync, spawn } from 'node:child_process'
import { readdirSync, writeFileSync, unlinkSync, realpathSync, existsSync } from 'node:fs'
import { readFileSync } from 'node:fs'
import { hostname, userInfo, platform, arch } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

async function main() {
const [key, home] = process.argv.slice(2)
const fail = (message, code = 2) => { throw Object.assign(new Error(message), { exitCode: code }) }
if (!/^0[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{25}$/.test(key || '')) fail('invalid listener key')
if (!home) fail('installation home is missing')
if (!process.versions.bun) fail('the selected runtime is not Bun')
// Windows temp/home paths can contain 8.3 aliases. Resolve the actual installed
// location before module loading and CLI launch, while preserving Unicode names.
let app
try { app = realpathSync(join(resolve(home), 'app')) }
catch (error) { fail('cannot locate the installed application: ' + error.message) }
let keyModule
const keyFile = join(app, 'src', 'key.js')
try { keyModule = await import(pathToFileURL(realpathSync(keyFile)).href) }
catch (error) { fail('cannot load the installed key validator (file exists: ' + existsSync(keyFile) + '): ' + error.message) }
try { keyModule.decodeKey(key) }
catch (error) { fail('listener key checksum is invalid: ' + error.message) }
const name = 'join-' + key
const bin = join(app, 'bin', 'p2p.js')
const env = { ...process.env, P2P_HOME: resolve(home) }
function cli(args, timeout = 45000) {
  const result = spawnSync(process.execPath, [bin, 'tunnel', ...args], {
    env, encoding: 'utf8', timeout, maxBuffer: 1024 * 1024,
    windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  })
  if (result.error) fail('CLI failed: ' + result.error.message, 3)
  return { code: result.status ?? 3, out: result.stdout || '', err: result.stderr || '' }
}
// Async variant for the connect step so a spinner can run while it dials (his ask: "connecting to <key> with a spinner").
function cliSpin(args, label, timeout = 45000) {
  return new Promise(resolvePromise => {
    const child = spawn(process.execPath, [bin, 'tunnel', ...args], { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = '', err = '', i = 0
    const frames = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
    const tick = setInterval(() => { process.stdout.write('\r  ' + frames[i++ % frames.length] + ' ' + label + ' '); }, 90)
    const killer = setTimeout(() => { try { child.kill() } catch {} }, timeout)
    child.stdout.on('data', d => { out += d })
    child.stderr.on('data', d => { err += d })
    child.on('close', code => { clearInterval(tick); clearTimeout(killer); process.stdout.write('\r' + ' '.repeat(label.length + 6) + '\r'); resolvePromise({ code: code ?? 3, out, err }) })
    child.on('error', e => { clearInterval(tick); clearTimeout(killer); resolvePromise({ code: 3, out, err: err + e.message }) })
  })
}
function status(sessionName) {
  const result = cli(['status', '--name', sessionName], 15000)
  if (result.code === 5 && !result.out.trim()) return null
  if (![0, 5].includes(result.code)) fail('cannot inspect session ' + sessionName + ': ' + result.err, result.code)
  try { return JSON.parse(result.out) } catch { fail('invalid daemon status for ' + sessionName, 3) }
}
function sessionMetadata(state) {
  let metadata
  try { metadata = JSON.parse(readFileSync(join(state.dir, 'session.json'), 'utf8')) }
  catch { fail('cannot inspect the previous session metadata; its identity will not be replaced') }
  if (metadata.id !== state.id || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(metadata.profile || '')) {
    fail('previous session identity metadata is invalid; its identity will not be replaced')
  }
  return metadata
}
function persistedProfile(previous) {
  const metadata = sessionMetadata(previous.state)
  let matchesShare = false
  try { matchesShare = keyModule.decodeKey(String(metadata.share || '').split('-')[0]).commitment.equals(keyModule.decodeKey(key).commitment) } catch {}
  if (metadata.role !== 'join' || !matchesShare) fail('previous session does not record a join to this listener; inspect it before restarting')
  if (metadata.ephemeral !== false) {
    fail('the previous session used an ephemeral identity that ended when its daemon stopped. Its identity cannot be recovered; ask the listener owner for a fresh listener. No replacement identity was created.')
  }
  const path = join(resolve(home), metadata.profile + '.json')
  if (!existsSync(path)) fail('the saved identity for profile ' + metadata.profile + ' is missing; restore that identity or ask the listener owner for a fresh listener. No replacement identity was created.')
  let saved
  try { saved = JSON.parse(readFileSync(path, 'utf8')) }
  catch { fail('the saved identity for profile ' + metadata.profile + ' is unreadable; it will not be replaced') }
  // Validate only the stored public identity and its commitment. Never export,
  // reconstruct, or log private key material from a previous daemon.
  let matchesIdentity = false
  try {
    matchesIdentity = saved.S === previous.state.self && /^[a-f0-9]{64}$/i.test(saved.edPub) && /^[a-f0-9]{64}$/i.test(saved.xPub) &&
      keyModule.verifyCommitment(keyModule.decodeKey(saved.S).commitment, Buffer.from(saved.edPub, 'hex'), Buffer.from(saved.xPub, 'hex'))
  } catch {}
  if (!matchesIdentity) fail('the saved identity does not match the previous session; it will not be replaced')
  return metadata.profile
}

// Reuse an existing authenticated connection, including one made by the older
// two-command prompt. A rerun must not replace its identity or start a second peer.
let names = []
try { names = readdirSync(join(home, 'tunnel'), { withFileTypes: true })
  .filter(entry => entry.isDirectory() && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(entry.name)).map(entry => entry.name) }
catch (error) { if (error.code !== 'ENOENT') fail('cannot inspect existing tunnel sessions: ' + error.message, 3) }
if (names.length > 256) fail('too many local tunnel sessions; inspect them before joining', 2)
let selected = null, conflict = false
const previous = []
for (const candidate of [...new Set([name, 'default', ...names])]) {
  const state = status(candidate)
  if (state?.peerKey === key && state.self) previous.push({ name: candidate, state })
  if (!state?.alive) continue
  if (state.connected && state.peerKey === key) { selected = { name: candidate, state }; break }
  if (candidate === name) conflict = true
}
if (!selected && conflict) fail('this listener session already has a running daemon that is not connected to the requested peer; inspect it with p2p tunnel status --name ' + name, 2)
let restartProfile = name
if (!selected && previous.length) {
  // Prefer history with acknowledged traffic over a later failed connection,
  // then the most recent pairing. Never silently invent its replacement key.
  previous.sort((a, b) => Number(b.state.sent > 0) - Number(a.state.sent > 0) || (b.state.connectedAt || 0) - (a.state.connectedAt || 0))
  restartProfile = persistedProfile(previous[0])
}
if (selected && sessionMetadata(selected.state).ephemeral !== false) {
  console.log('Reusing a legacy ephemeral identity while its daemon is alive. Stopping it or rebooting loses that identity; a fresh listener from the listener owner will then be required.')
}

const clean = value => String(value).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 200)
let username = 'unknown'
try { username = userInfo().username } catch {}
const identity = 'connected: ' + clean(hostname()) + ' ' + clean(username) + '\n' +
  JSON.stringify({ MACHINE: clean(hostname()), USER: clean(username), OS: platform(), ARCH: arch(), AGENT: 'bootstrap', RUNTIME: 'bun ' + process.versions.bun })
if (!selected) {
  // --profile is essential: the CLI otherwise creates an ephemeral identity on
  // each fresh session, which an already-bound host would correctly reject.
  console.log('')
  const result = await cliSpin(['join', key, '--name', name, '--profile', restartProfile,
    '--say', 'Agent Tunnel connected; machine identification follows.', '--connect-timeout', '30'], 'connecting to ' + key)
  if (result.code !== 0) fail(result.err.trim() || result.out.trim() || 'connection failed; the listener may be offline or already paired with another machine', result.code)
  const state = status(name)
  if (!state?.alive || !state.connected || state.peerKey !== key) fail('the requested peer did not become connected', 3)
  selected = { name, state }
  console.log('  ✓ connected to ' + key)
}
// --file avoids PowerShell native argv quoting and never treats machine metadata
// or remote messages as shell syntax. Wait for a delivery acknowledgment.
const messageFile = join(resolve(home), '.join-' + process.pid + '-' + Date.now() + '.txt')
try {
  writeFileSync(messageFile, identity, { mode: 0o600, flag: 'wx' })
  // Three tries, 20 s each: over the public relay the delivery ack can lag well past 10 s while the message
  // itself has already landed (seen live 2026-09-13 on a Debian VPS: listener recv=2, joiner "not acknowledged").
  let acked = false, lastErr = ''
  for (let attempt = 1; attempt <= 3 && !acked; attempt++) {
    const result = await cliSpin(['send', '--file', messageFile, '--name', selected.name, '--wait', '20'], 'sending machine identification (try ' + attempt + '/3)', 30000)
    if (result.code === 0) acked = true
    else { lastErr = result.err.trim(); const st = status(selected.name); if (!st?.alive || !st.connected) fail('the connection dropped while sending machine identification: ' + lastErr, 3) }
  }
  if (!acked) console.log('  ! machine identification sent, delivery not acknowledged in 60 s (' + lastErr + ') — the link is up; continuing.')
  else console.log('  ✓ machine identification acknowledged')
} finally { try { unlinkSync(messageFile) } catch {} }
console.log('Agent Tunnel connected to ' + key + ' as ' + selected.state.self + '.')
console.log('Chat daemon is running in the background (PID ' + selected.state.pid + '). It does not start automatically after a reboot.')
console.log('Status: p2p tunnel status --name ' + selected.name)
console.log('Messages: p2p tunnel recv --name ' + selected.name + ' --wait 60')
console.log('Stop: p2p tunnel stop --name ' + selected.name)
console.log('Terminal activation is separate. This join line does not grant remote command execution.')
}
try { await main() } catch (error) { console.error('Agent Tunnel: ' + error.message); process.exitCode = error.exitCode || 3 }
P2P_JOIN_HELPER
  "$JOIN_RUNTIME" "$JOIN_TMP/join.mjs" "$JOIN_KEY" "$P2P_HOME" </dev/null
}
livemind_server_prereqs() {
  # A minimal Debian ships without unzip (the Bun installer needs it), sometimes without curl/ca-certificates.
  SUDO=''; [ "$(id -u)" -eq 0 ] || SUDO='sudo -n'
  NEED=''
  for t in unzip curl tmux; do command -v "$t" >/dev/null 2>&1 || NEED="$NEED $t"; done
  [ -d /etc/ssl/certs ] || NEED="$NEED ca-certificates"
  if [ -n "$NEED" ]; then
    echo "LiveMind server prerequisites: installing$NEED"
    export DEBIAN_FRONTEND=noninteractive
    $SUDO apt-get update -qq >/dev/null 2>&1 || true
    $SUDO apt-get install -y -qq $NEED >/dev/null || { echo "apt-get install failed for:$NEED" >&2; return 1; }
  fi
  command -v unzip >/dev/null 2>&1 || { echo 'unzip is still missing; cannot continue' >&2; return 1; }
}
livemind_server_setup() {
  set -eu
  KEY="$JOIN_KEY"; NAME="join-$KEY"; P2P="$HOME/.local/bin/p2p"; HOMEDIR="$HOME"; ME="$(id -un)"
  echo "LiveMind server setup: keeper service (rejoin after reboot) + owner terminal grant for the MIND (tmux session livemind-terminal)."
  SUDO=''; [ "$(id -u)" -eq 0 ] || SUDO='sudo -n'
  if ! command -v tmux >/dev/null 2>&1; then $SUDO apt-get update -qq >/dev/null 2>&1 || true; $SUDO apt-get install -y -qq tmux >/dev/null; fi
  $SUDO mkdir -p /usr/local/lib/livemind
  $SUDO tee /usr/local/lib/livemind/tunnel-keeper.sh >/dev/null <<KEEPER
#!/bin/sh
# LiveMind tunnel keeper (installed by the join line, 2026-09-13): rejoin the MIND listener whenever
# the chat daemon is gone; keep the owner terminal grant alive in a tmux session.
export HOME='$HOMEDIR' P2P_HOME='$HOMEDIR/.p2p' PATH="$HOMEDIR/.local/bin:\$PATH"
KEY='$KEY'; NAME='$NAME'; P2P='$P2P'
while :; do
  ST="\$("\$P2P" tunnel status --name "\$NAME" 2>/dev/null || true)"
  case "\$ST" in
    *'"alive":true'*'"connected":true'*|*'"connected":true'*'"alive":true'*) : ;;   # up
    *'"alive":true'*) "\$P2P" tunnel stop --name "\$NAME" >/dev/null 2>&1 || true; sleep 2
                       "\$P2P" tunnel join "\$KEY" --name "\$NAME" --profile "\$NAME" --say "livemind-server rejoined \$(hostname)" --connect-timeout 30 || true ;;   # alive but the peer dropped: a join daemon dials once, never re-dials
    *) "\$P2P" tunnel join "\$KEY" --name "\$NAME" --profile "\$NAME" --say "livemind-server rejoined \$(hostname)" --connect-timeout 30 || true ;;
  esac
  if ! tmux has-session -t livemind-terminal 2>/dev/null; then
    tmux new-session -d -s livemind-terminal "'\$P2P' tunnel terminal --allow '\$KEY' --name '\$NAME' --shell bash; sleep 10"
  fi
  sleep 30
done
KEEPER
  $SUDO chmod 755 /usr/local/lib/livemind/tunnel-keeper.sh
  $SUDO tee /etc/systemd/system/livemind-tunnel.service >/dev/null <<UNIT
[Unit]
Description=LiveMind Agent Tunnel keeper (chat daemon + owner terminal grant for the MIND)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$ME
ExecStart=/usr/local/lib/livemind/tunnel-keeper.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now livemind-tunnel.service
  sleep 12
  TERM_STATE=down; tmux has-session -t livemind-terminal 2>/dev/null && TERM_STATE=up
  OSNAME="$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
  echo "MIND-READY $ME@$(hostname) $(uname -m) $OSNAME terminal=$TERM_STATE"
  "$P2P" tunnel send --name "$NAME" "MIND-READY $ME@$(hostname) $(uname -m) $OSNAME terminal=$TERM_STATE keeper=$($SUDO systemctl is-active livemind-tunnel.service 2>/dev/null || echo unknown)" --wait 10 >/dev/null 2>&1 || true
}
JOIN_MODE=''
for a in "$@"; do case "$a" in --chat-only) JOIN_MODE=--chat-only;; --server) JOIN_MODE=--server;; -*) echo "unknown option: $a" >&2; exit 2;; *) [ -n "${P2P_JOIN_KEY:-}" ] || P2P_JOIN_KEY="$a";; esac; done
if [ -z "${P2P_JOIN_KEY:-}" ]; then
  echo 'usage: curl -fsSL https://p2p.akeyo.io/join.sh | sh -s -- <LISTENER_KEY> [--chat-only]' >&2; exit 2
fi
if [ -z "$JOIN_MODE" ]; then
  # default: full server setup wherever it can be done (Linux + systemd + root or passwordless sudo); chat-only elsewhere
  if [ "$(uname -s 2>/dev/null)" = Linux ] && command -v systemctl >/dev/null 2>&1 && { [ "$(id -u)" -eq 0 ] || sudo -n true 2>/dev/null; }; then JOIN_MODE=--server; else JOIN_MODE=--chat-only; fi
fi
export P2P_JOIN_KEY JOIN_MODE
if [ "$JOIN_MODE" = --server ]; then
  livemind_server_prereqs || exit 1
  p2p_join_main; JOIN_RC=$?
  if [ "$JOIN_RC" -ne 0 ] && "$HOME/.local/bin/p2p" tunnel status --name "join-$P2P_JOIN_KEY" 2>/dev/null | grep -q '"connected":true'; then
    echo 'join reported an error but the chat daemon is connected — installing the keeper anyway (it re-dials on every drop).'; JOIN_RC=0
  fi
  [ "$JOIN_RC" -eq 0 ] || exit "$JOIN_RC"
  livemind_server_setup
  echo 'Undo everything this line did:  curl -fsSL https://p2p.akeyo.io/uninstall.sh | sh'
else p2p_join_main; fi
