#!usr/bin/env bash
# peerbridge uninstaller: reverses install.sh. Removes only what peerbridge added
# (its hooks.json entry, its skill dir, its launchd plist / systemd unit, the pb symlink, the prefix).
# Backups: hooks.json -> hooks.json.bak.peerbridge-uninstall.<ts>; prefix -> ${TMPDIR:-/tmp}/peerbridge-backup-<ts>.tgz
#
#   ./uninstall.sh [--keep-prefix]
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"   # dash/sh -> bash
set -euo pipefail

PREFIX="${PEERBRIDGE_PREFIX:-$HOME/.peerbridge}"
CODEX_HOME_IN="${CODEX_HOME:-}"
LABEL="${PEERBRIDGE_LAUNCHD_LABEL:-com.peerbridge.hub}"
UNIT="${PEERBRIDGE_SYSTEMD_UNIT:-peerbridge-hub}"
BINLINK="$HOME/.local/bin/pb"
AUTOSTART=""
KEEP_PREFIX=0
[ "${1:-}" = "--keep-prefix" ] && KEEP_PREFIX=1
TS="$(date +%Y%m%d-%H%M%S)"
say() { printf 'peerbridge: %s\n' "$*"; }
warn() { printf 'peerbridge: WARNING: %s\n' "$*" >&2; }

MAN="$PREFIX/install-manifest"
if [ -f "$MAN" ]; then
  # values written by install.sh; parsed, never sourced
  get() { sed -n "s/^$1=//p" "$MAN" | head -n1; }
  CODEX_HOME_M="$(get CODEX_HOME)"; LABEL="$(get LABEL)"; UNIT="$(get UNIT)"
  BINLINK="$(get BINLINK)"; AUTOSTART="$(get AUTOSTART)"
fi
CODEX_HOME="${CODEX_HOME_IN:-${CODEX_HOME_M:-$HOME/.codex}}"

# 1. autostart off first (so launchd/systemd does not respawn the hub we stop next)
if [ "$(uname -s)" = Darwin ]; then
  PLIST="${AUTOSTART:-$HOME/Library/LaunchAgents/$LABEL.plist}"
  case "$PLIST" in *.plist) ;; *) PLIST="$HOME/Library/LaunchAgents/$LABEL.plist" ;; esac
  if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
    launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 && say "launchd agent unloaded: gui/$(id -u)/$LABEL" || warn "launchctl bootout $LABEL failed"
  fi
  if [ -f "$PLIST" ]; then rm -f "$PLIST"; say "removed $PLIST"; fi
elif command -v systemctl >/dev/null 2>&1; then
  UNITF="${AUTOSTART:-${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$UNIT.service}"
  case "$UNITF" in *.service) ;; *) UNITF="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$UNIT.service" ;; esac
  if [ -f "$UNITF" ]; then
    systemctl --user disable --now "$UNIT.service" >/dev/null 2>&1 || true
    rm -f "$UNITF"; systemctl --user daemon-reload >/dev/null 2>&1 || true
    say "removed systemd unit $UNITF"
  fi
fi

# 2. stop the hub (only if this prefix's pb exists)
if [ -x "$PREFIX/bin/pb" ]; then
  "$PREFIX/bin/pb" stop 2>/dev/null && say "hub stopped" || say "no running hub to stop"
fi

# 3. remove only our Codex SessionStart hook entry
HOOKS="$CODEX_HOME/hooks.json"
if [ -f "$HOOKS" ]; then
  python3 - "$HOOKS" "$TS" <<'PY'
import json, os, re, shutil, sys
path, ts = sys.argv[1:3]
ours = re.compile(r"bin/pb'? ensure --quiet-hook")
raw = open(path, encoding="utf-8").read()
try:
    data = json.loads(raw)
except json.JSONDecodeError as e:
    print(f"peerbridge: WARNING: {path} is not valid JSON ({e}); left untouched", file=sys.stderr); sys.exit(0)
ss = (data.get("hooks") or {}).get("SessionStart") if isinstance(data, dict) else None
if not isinstance(ss, list):
    print(f"peerbridge: no peerbridge hook in {path}"); sys.exit(0)
removed = 0
keep = []
for g in ss:
    if isinstance(g, dict) and isinstance(g.get("hooks"), list):
        before = len(g["hooks"])
        g["hooks"] = [h for h in g["hooks"] if not (isinstance(h, dict) and ours.search(str(h.get("command", ""))))]
        removed += before - len(g["hooks"])
        if before and not g["hooks"]:
            continue                      # group held only our hook
    keep.append(g)
if not removed:
    print(f"peerbridge: no peerbridge hook in {path}"); sys.exit(0)
data["hooks"]["SessionStart"] = keep
if not keep:
    del data["hooks"]["SessionStart"]
bak = f"{path}.bak.peerbridge-uninstall.{ts}"
shutil.copy2(path, bak)
out = json.dumps(data, indent=2) + ("\n" if raw.endswith("\n") else "")
tmp = path + ".tmp.peerbridge"
open(tmp, "w", encoding="utf-8").write(out)
os.replace(tmp, path)
print(f"peerbridge: removed {removed} hook entr{'y' if removed == 1 else 'ies'} from {path} (backup {bak})")
PY
fi

# 4. our Codex skill dir
SK="$CODEX_HOME/skills/peerbridge"
if [ -d "$SK" ]; then rm -rf "$SK"; say "removed Codex skill $SK"; fi

# 5. pb symlink (only if it points into our prefix)
if [ -L "$BINLINK" ] && [ "$(readlink "$BINLINK")" = "$PREFIX/bin/pb" ]; then
  rm -f "$BINLINK"; say "removed symlink $BINLINK"
elif [ -e "$BINLINK" ]; then
  warn "$BINLINK is not our symlink; left alone"
fi

# 6. prefix (backed up first; includes hub state: names.json, logs, receipts)
if [ "$KEEP_PREFIX" = 1 ]; then
  say "prefix kept (--keep-prefix): $PREFIX"
elif [ -d "$PREFIX" ]; then
  case "$PREFIX" in ""|"/"|"$HOME"|"$HOME/") warn "refusing to remove unsafe PREFIX='$PREFIX'"; exit 1 ;; esac
  if [ ! -f "$PREFIX/install-manifest" ] && [ ! -d "$PREFIX/lib/peerbridge" ]; then
    warn "$PREFIX does not look like a peerbridge install; left alone"
  else
    BK="${TMPDIR:-/tmp}"; BK="${BK%/}/peerbridge-backup-$TS.tgz"
    tar -czf "$BK" -C "$(dirname "$PREFIX")" --exclude='*.sock' "$(basename "$PREFIX")" 2>/dev/null \
      && say "backed up $PREFIX -> $BK" || warn "backup of $PREFIX failed (continuing)"
    rm -rf "$PREFIX"; say "removed $PREFIX"
  fi
fi
say "uninstalled."
[ -L "$HOME/.local/bin/cxsend" ] && rm -f "$HOME/.local/bin/cxsend" && echo "peerbridge: removed ~/.local/bin/cxsend"
