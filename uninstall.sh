#!/bin/sh
# p2p.akeyo.io/uninstall.sh — undo EVERYTHING the join line did on this machine, so it can be tested again fresh
# (with a new listener key). Owner's ask, 2026-09-13.  Usage:
#   curl -fsSL https://p2p.akeyo.io/uninstall.sh | sh            # remove the keeper service, the terminal grant,
#                                                                 # every tunnel daemon, the p2p install and its identity
#   curl -fsSL https://p2p.akeyo.io/uninstall.sh | sh -s -- --purge-apt   # also apt-remove unzip + tmux (Linux)
# Inspect before running. Nothing here touches anything outside ~/.p2p, ~/.local/bin/p2p, the shell-rc PATH block,
# /usr/local/lib/livemind, /etc/systemd/system/livemind-tunnel.service and the tmux session livemind-terminal.
set -u
PURGE_APT=0
for a in "$@"; do case "$a" in --purge-apt) PURGE_APT=1;; *) echo "unknown option: $a" >&2; exit 2;; esac; done
SUDO=''; [ "$(id -u)" -eq 0 ] || { command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null && SUDO='sudo -n'; }
P2P_HOME="${P2P_HOME:-$HOME/.p2p}"
P2P="$HOME/.local/bin/p2p"
say() { printf '  %s\n' "$*"; }

echo 'p2p uninstall'
# 1. keeper service (Linux, systemd)
if command -v systemctl >/dev/null 2>&1 && [ -n "$SUDO$([ "$(id -u)" -eq 0 ] && echo root)" ]; then
  if [ -f /etc/systemd/system/livemind-tunnel.service ]; then
    $SUDO systemctl disable --now livemind-tunnel.service >/dev/null 2>&1 || true
    $SUDO rm -f /etc/systemd/system/livemind-tunnel.service
    $SUDO systemctl daemon-reload >/dev/null 2>&1 || true
    say '✓ keeper service removed (livemind-tunnel.service)'
  else say '- keeper service: not installed'; fi
  [ -d /usr/local/lib/livemind ] && { $SUDO rm -rf /usr/local/lib/livemind; say '✓ /usr/local/lib/livemind removed'; }
fi
# 2. owner terminal grant
if command -v tmux >/dev/null 2>&1 && tmux has-session -t livemind-terminal 2>/dev/null; then
  tmux kill-session -t livemind-terminal 2>/dev/null || true; say '✓ terminal grant stopped (tmux livemind-terminal)'
else say '- terminal grant: not running'; fi
# 3. every tunnel daemon of this install (graceful stop, then whatever is left)
if [ -x "$P2P" ] && [ -d "$P2P_HOME/tunnel" ]; then
  for d in "$P2P_HOME"/tunnel/*/; do
    [ -d "$d" ] || continue; n="$(basename "$d")"
    P2P_HOME="$P2P_HOME" "$P2P" tunnel stop --name "$n" >/dev/null 2>&1 && say "✓ tunnel daemon stopped: $n" || say "- tunnel $n: no live daemon"
  done
fi
if command -v pkill >/dev/null 2>&1; then pkill -u "$(id -u)" -f "$P2P_HOME/app/bin/p2p.js tunnel serve" 2>/dev/null && say '✓ leftover daemon processes killed' || true; fi
# 4. the install + identity (keys live under P2P_HOME — a fresh join gets a NEW peer identity; the listener owner must mint a new key)
if [ -d "$P2P_HOME" ]; then rm -rf "$P2P_HOME"; say "✓ $P2P_HOME removed (runtime, app, sessions, identities)"; else say "- $P2P_HOME: absent"; fi
[ -e "$P2P" ] && { rm -f "$P2P"; say "✓ $P2P removed"; }
[ -e "$HOME/.local/bin/p2p.cmd" ] && rm -f "$HOME/.local/bin/p2p.cmd"
# 5. the PATH block the installer appended (marked block, removed verbatim)
for rc in "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zshrc" "${ZDOTDIR:-$HOME}/.zshrc" "$HOME/.profile" "$HOME/.config/fish/config.fish"; do
  [ -f "$rc" ] && grep -qF '# >>> p2p >>>' "$rc" 2>/dev/null || continue
  tmp="$rc.p2p-uninstall.$$"
  awk '/^# >>> p2p >>>$/{skip=1} !skip{print} /^# <<< p2p <<<$/{skip=0}' "$rc" >"$tmp" && cat "$tmp" >"$rc" && rm -f "$tmp" && say "✓ PATH block removed from $rc"
done
# 6. apt packages the join line installed (only on request — they are harmless and may predate us)
if [ "$PURGE_APT" -eq 1 ] && command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get remove -y -qq unzip tmux >/dev/null 2>&1 && say '✓ apt: unzip tmux removed' || say '! apt remove failed (run it by hand)'
else say '- apt packages (unzip, tmux) left in place; add --purge-apt to remove them'; fi
echo 'done — this machine is fresh. Rejoin with a NEW key from the listener owner:'
echo '  curl -fsSL https://p2p.akeyo.io/join.sh | sh -s -- <NEW_KEY>'
