#!/usr/bin/env bash
# peerbridge installer: idempotent, one command, prints every action.
#
#   ./install.sh [--selftest]
#
# Env knobs:
#   PEERBRIDGE_PREFIX       install root (default ~/.peerbridge; never under ~/Documents, ~/Desktop, ~/Downloads)
#   CODEX_HOME              Codex config dir (default ~/.codex)
#   PEERBRIDGE_NO_LAUNCHD=1 skip launchd / systemd autostart (fake-HOME tests)
#   PEERBRIDGE_NO_START=1   do not start the hub at the end
#   PEERBRIDGE_LAUNCHD_LABEL  launchd label / systemd unit stem (default com.peerbridge.hub / peerbridge-hub)
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"   # dash/sh -> bash
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd -P)"
PREFIX="${PEERBRIDGE_PREFIX:-$HOME/.peerbridge}"
CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
LABEL="${PEERBRIDGE_LAUNCHD_LABEL:-com.peerbridge.hub}"
UNIT="${PEERBRIDGE_SYSTEMD_UNIT:-peerbridge-hub}"
BINLINK="$HOME/.local/bin/pb"
TS="$(date +%Y%m%d-%H%M%S)"
SELFTEST=0
for a in "$@"; do
  case "$a" in
    --selftest) SELFTEST=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "install.sh: unknown arg $a" >&2; exit 2 ;;
  esac
done

say() { printf 'peerbridge: %s\n' "$*"; }
warn() { printf 'peerbridge: WARNING: %s\n' "$*" >&2; }

PY="$(command -v python3 || true)"
[ -n "$PY" ] || { echo "peerbridge: python3 not found on PATH" >&2; exit 1; }

# macOS TCC: launchd-spawned processes cannot read ~/Documents, ~/Desktop, ~/Downloads.
case "$PREFIX" in
  "$HOME/Documents"*|"$HOME/Desktop"*|"$HOME/Downloads"*)
    echo "peerbridge: refusing PREFIX=$PREFIX (macOS TCC-protected folder; launchd cannot read it)" >&2; exit 1 ;;
  ""|"/"|"$HOME"|"$HOME/")
    echo "peerbridge: refusing unsafe PREFIX='$PREFIX'" >&2; exit 1 ;;
esac
[ -f "$SRC/peerbridge/ccpeer.py" ] && [ -f "$SRC/bin/pb" ] || { echo "peerbridge: run from the peerbridge source tree" >&2; exit 1; }

# 1. code -> $PREFIX/lib/peerbridge + $PREFIX/bin/pb (pb resolves ../lib/peerbridge via realpath)
mkdir -p "$PREFIX/lib" "$PREFIX/bin"
LIB="$PREFIX/lib/peerbridge"
changed=0
for f in "$SRC"/peerbridge/*.py; do
  cmp -s "$f" "$LIB/$(basename "$f")" 2>/dev/null || changed=1
done
for f in "$LIB"/*.py; do
  [ -e "$f" ] || continue
  [ -f "$SRC/peerbridge/$(basename "$f")" ] || changed=1   # stale file in old install
done
if [ "$changed" = 1 ]; then
  rm -rf "$LIB.new"; mkdir -p "$LIB.new"
  cp "$SRC"/peerbridge/*.py "$LIB.new/"
  rm -rf "$LIB"; mv "$LIB.new" "$LIB"
  say "installed package -> $LIB ($(ls "$LIB" | tr '\n' ' '))"
else
  say "package up to date: $LIB"
fi
if cmp -s "$SRC/bin/pb" "$PREFIX/bin/pb" 2>/dev/null; then
  say "pb up to date: $PREFIX/bin/pb"
else
  cp "$SRC/bin/pb" "$PREFIX/bin/pb.new" && chmod 755 "$PREFIX/bin/pb.new" && mv "$PREFIX/bin/pb.new" "$PREFIX/bin/pb"
  say "installed CLI -> $PREFIX/bin/pb"
fi
cp "$SRC/uninstall.sh" "$PREFIX/uninstall.sh" 2>/dev/null && chmod 755 "$PREFIX/uninstall.sh" || true

# 1b. cxsend (raw inject CLI, v0.1) next to pb + ~/.local/bin/cxsend
if [ -f "$SRC/bin/cxsend" ]; then
  cp "$SRC/bin/cxsend" "$PREFIX/bin/cxsend.new" && chmod 755 "$PREFIX/bin/cxsend.new" && mv "$PREFIX/bin/cxsend.new" "$PREFIX/bin/cxsend"
  mkdir -p "$HOME/.local/bin"
  if [ ! -e "$HOME/.local/bin/cxsend" ] || [ -L "$HOME/.local/bin/cxsend" ]; then ln -sfn "$PREFIX/bin/cxsend" "$HOME/.local/bin/cxsend"; fi
  say "installed cxsend -> $PREFIX/bin/cxsend"
fi

# 1c. codex-unsandboxed: opt-in launcher for peerbridge mode (b); installed, never made the default
if [ -f "$SRC/bin/codex-unsandboxed" ]; then
  cp "$SRC/bin/codex-unsandboxed" "$PREFIX/bin/codex-unsandboxed" && chmod 755 "$PREFIX/bin/codex-unsandboxed"
  if [ ! -e "$HOME/.local/bin/codex-unsandboxed" ] || [ -L "$HOME/.local/bin/codex-unsandboxed" ]; then
    ln -sfn "$PREFIX/bin/codex-unsandboxed" "$HOME/.local/bin/codex-unsandboxed"; fi
  say "installed opt-in launcher -> codex-unsandboxed (mode b: no sandbox, no approvals; plain codex stays sandboxed)"
fi

# 2. ~/.local/bin/pb symlink
mkdir -p "$(dirname "$BINLINK")"
if [ -L "$BINLINK" ] && [ "$(readlink "$BINLINK")" = "$PREFIX/bin/pb" ]; then
  say "symlink ok: $BINLINK -> $PREFIX/bin/pb"
elif [ -e "$BINLINK" ] && [ ! -L "$BINLINK" ]; then
  mv "$BINLINK" "$BINLINK.bak.$TS"; ln -s "$PREFIX/bin/pb" "$BINLINK"
  say "existing $BINLINK moved to $BINLINK.bak.$TS; symlinked -> $PREFIX/bin/pb"
else
  ln -sfn "$PREFIX/bin/pb" "$BINLINK"
  say "symlinked $BINLINK -> $PREFIX/bin/pb"
fi
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) warn "$HOME/.local/bin is not on PATH; add it so Codex shells find 'pb'" ;; esac

# 3. Codex SessionStart hook: OPT-IN (PEERBRIDGE_CODEX_HOOK=1). Hooks run inside the Codex daemon and a new hook
#    needs a one-time trust approval in every Codex UI; launchd/systemd already keeps the hub up, so default off.
if [ "${PEERBRIDGE_CODEX_HOOK:-0}" = 1 ]; then
#    hook (json merge, appended LAST so existing hooks keep their index-keyed trust)
mkdir -p "$CODEX_HOME"
HOOKS="$CODEX_HOME/hooks.json"
"$PY" - "$HOOKS" "$PREFIX/bin/pb" "$TS" <<'PY'
import json, os, re, shutil, sys
path, pb, ts = sys.argv[1:4]
cmd = f"'{pb}' ensure --quiet >/dev/null 2>&1 || true"
ours = re.compile(r"bin/pb'? ensure --quiet")
raw = None
if os.path.exists(path):
    raw = open(path, encoding="utf-8").read()
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as e:
        print(f"peerbridge: WARNING: {path} is not valid JSON ({e}); hook NOT installed", file=sys.stderr)
        sys.exit(0)
else:
    data = {}
if not isinstance(data, dict):
    print(f"peerbridge: WARNING: {path} top level is not an object; hook NOT installed", file=sys.stderr); sys.exit(0)
groups = data.setdefault("hooks", {}).setdefault("SessionStart", [])
found = False
for g in groups:
    for h in g.get("hooks", []) if isinstance(g, dict) else []:
        if isinstance(h, dict) and ours.search(str(h.get("command", ""))):
            if found:
                h["__drop__"] = True          # duplicate of ours
            else:
                found = True
                if h.get("command") != cmd:
                    h["command"] = cmd
for g in groups:
    if isinstance(g, dict) and "hooks" in g:
        g["hooks"] = [h for h in g["hooks"] if not (isinstance(h, dict) and h.get("__drop__"))]
groups[:] = [g for g in groups if not (isinstance(g, dict) and g.get("hooks") == [] )]
if not found:
    groups.append({"hooks": [{"command": cmd, "timeout": 10, "type": "command"}]})
out = json.dumps(data, indent=2) + ("\n" if raw is None or raw.endswith("\n") else "")
if out == raw:
    print(f"peerbridge: Codex hook already present in {path}")
else:
    if raw is not None:
        bak = f"{path}.bak.peerbridge.{ts}"
        shutil.copy2(path, bak)
        print(f"peerbridge: backed up {path} -> {bak}")
    tmp = path + ".tmp.peerbridge"
    open(tmp, "w", encoding="utf-8").write(out)
    os.replace(tmp, path)
    print(f"peerbridge: Codex SessionStart hook merged into {path}: {cmd}")
PY
CFG="$CODEX_HOME/config.toml"
if [ -f "$CFG" ] && ! grep -Eq '^[[:space:]]*hooks[[:space:]]*=[[:space:]]*true' "$CFG"; then
  warn "Codex hooks look disabled; set [features] hooks = true in $CFG (not edited by this installer)"
fi
say "note: Codex asks you to trust a new hook once (review it in Codex); until then the launchd/systemd agent keeps the hub up"

else
  say "Codex hook skipped (set PEERBRIDGE_CODEX_HOOK=1 to add a SessionStart 'pb ensure' kick; autostart covers it)"
fi

# 4. Codex skill
SKILL_SRC="$SRC/codex-skill/SKILL.md"
SKILL_DST="$CODEX_HOME/skills/peerbridge/SKILL.md"
if [ -f "$SKILL_SRC" ]; then
  mkdir -p "$(dirname "$SKILL_DST")"
  if cmp -s "$SKILL_SRC" "$SKILL_DST"; then
    say "Codex skill up to date: $SKILL_DST"
  else
    [ -f "$SKILL_DST" ] && cp "$SKILL_DST" "$SKILL_DST.bak.$TS"
    cp "$SKILL_SRC" "$SKILL_DST"
    say "installed Codex skill -> $SKILL_DST"
  fi
else
  warn "$SKILL_SRC missing; Codex skill NOT installed (re-run install.sh once it exists)"
fi

# 5. autostart
autostart_path=""
if [ "${PEERBRIDGE_NO_LAUNCHD:-0}" = 1 ]; then
  say "autostart skipped (PEERBRIDGE_NO_LAUNCHD=1)"
elif [ "$(uname -s)" = Darwin ]; then
  PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
  mkdir -p "$(dirname "$PLIST")"
  CODEX_DIR="$(dirname "$(command -v codex 2>/dev/null || echo /usr/local/bin/codex)")"
  NEW="$("$PY" - "$LABEL" "$PY" "$LIB/hub.py" "$PREFIX/hub.out" "$CODEX_DIR:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" <<'PY'
import plistlib, sys
label, py, hub, out, path = sys.argv[1:6]
sys.stdout.write(plistlib.dumps({
    "Label": label,
    "ProgramArguments": [py, hub],
    "RunAtLoad": True,
    # hub exits 0 when another hub already holds the flock: do not respawn-loop on that; restart on crashes
    "KeepAlive": {"SuccessfulExit": False},
    "ThrottleInterval": 10,
    "StandardOutPath": out,
    "StandardErrorPath": out,
    "EnvironmentVariables": {"PATH": path},
    "ProcessType": "Background",
}).decode())
PY
)"
  if [ -f "$PLIST" ] && [ "$(cat "$PLIST")" = "$NEW" ] && launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
    say "launchd agent up to date and loaded: $PLIST"
  else
    [ -f "$PLIST" ] && cp "$PLIST" "$PREFIX/$(basename "$PLIST").bak.$TS"
    printf '%s' "$NEW" > "$PLIST"
    launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
    if launchctl bootstrap "gui/$(id -u)" "$PLIST"; then
      say "launchd agent loaded: $PLIST (gui/$(id -u)/$LABEL)"
    else
      warn "launchctl bootstrap failed for $PLIST; the Codex hook will still start the hub"
    fi
  fi
  autostart_path="$PLIST"
elif command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  UNITF="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$UNIT.service"
  mkdir -p "$(dirname "$UNITF")"
  NEW="[Unit]
Description=peerbridge hub (Codex threads as Claude Code peers)

[Service]
ExecStart=$PY $LIB/hub.py
Restart=on-failure
RestartSec=5
StandardOutput=append:$PREFIX/hub.out
StandardError=append:$PREFIX/hub.out

[Install]
WantedBy=default.target"
  if [ -f "$UNITF" ] && [ "$(cat "$UNITF")" = "$NEW" ]; then
    say "systemd user unit up to date: $UNITF"
  else
    printf '%s\n' "$NEW" > "$UNITF"
    say "wrote systemd user unit: $UNITF"
  fi
  systemctl --user daemon-reload && systemctl --user enable --now "$UNIT.service" >/dev/null 2>&1 \
    && say "systemd: $UNIT.service enabled + started" || warn "systemctl --user enable failed; the Codex hook will start the hub"
  autostart_path="$UNITF"
else
  say "no launchd / systemd --user available: the Codex SessionStart hook starts the hub"
fi

# 6. manifest (read by uninstall.sh)
cat > "$PREFIX/install-manifest" <<EOF
PREFIX=$PREFIX
CODEX_HOME=$CODEX_HOME
LABEL=$LABEL
UNIT=$UNIT
BINLINK=$BINLINK
AUTOSTART=$autostart_path
INSTALLED=$TS
EOF

# 7. start + selftest
if [ "${PEERBRIDGE_NO_START:-0}" = 1 ]; then
  say "hub start skipped (PEERBRIDGE_NO_START=1)"
else
  if "$PREFIX/bin/pb" ensure >/dev/null; then
    say "hub running: $("$PREFIX/bin/pb" status 2>/dev/null | tr -d '\n ' | cut -c1-160)"
  else
    warn "pb ensure failed; see $PREFIX/hub.out"
  fi
fi
if [ "$SELFTEST" = 1 ]; then
  if [ -x "$SRC/selftest.sh" ] || [ -f "$SRC/selftest.sh" ]; then
    say "running selftest"; bash "$SRC/selftest.sh"
  else
    warn "--selftest given but $SRC/selftest.sh missing"
  fi
fi
say "done. Try: pb list"
