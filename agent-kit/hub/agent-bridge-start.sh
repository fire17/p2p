#!/usr/bin/env bash
# agent-bridge-start.sh - discover this PC's herdr agents and (re)start hub/agent-bridge.py for them, detached.
#
#   agent-bridge-start.sh --prefix lap [--session main] [--dry-run] [--wait 120]
#
# Routes (hub name -> peer), discovered at start, never fixed ids:
#   <prefix>-claude = peer:claude+bypass   the Claude Code session named "claude" (herdr pane label claude, `claude -n claude`)
#   <prefix>-rc     = peer:rc              the Claude Code session named "rc"
#   <prefix>-codex  = peer:<thread id>     the herdr "codex" pane's CURRENT thread, then `pb expose --thread <id>`
# A Claude peer must resolve to exactly one live session (ccpeer.resolve). The codex thread is a rollout the managed
# Codex daemon holds open (any originator), cwd = the pane's cwd, created no earlier than 120 s before the pane's
# codex process started. Several candidates: the one pb already exposes wins; still ambiguous = no codex route (logged),
# never a guess. Missing peers are retried for --wait seconds, then the bridge starts with what exists (logged).
# Idempotent: a live bridge with the same routes is left alone. --dry-run prints the map and command, changes nothing.
# Files: pid and log next to the caller's choice of $BRIDGE_DIR (default ~/.agent-bridge): agent-bridge.pid/.log.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="${AGENT_KIT:-${SHAI_KIT:-$(dirname "$HERE")}}"
DIR="${BRIDGE_DIR:-$HOME/.agent-bridge}"
PREFIX=""; S="main"; DRY=0; WAIT=120
while [ $# -gt 0 ]; do case "$1" in
  --prefix) PREFIX="${2:?}"; shift 2 ;; --session) S="${2:?}"; shift 2 ;;
  --dry-run) DRY=1; shift ;; --wait) WAIT="${2:?}"; shift 2 ;;
  *) echo "usage: $0 --prefix NAME [--session S] [--dry-run] [--wait SEC]" >&2; exit 2 ;; esac; done
[ -n "$PREFIX" ] || { echo "agent-bridge-start: --prefix is required (e.g. lap, desk)" >&2; exit 2; }
export PATH="$HOME/.local/bin:$PATH"
for c in herdr jq pb python3; do command -v $c >/dev/null || { echo "agent-bridge-start: missing $c" >&2; exit 1; }; done
mkdir -p "$DIR"; LOG="$DIR/agent-bridge.log"; PIDF="$DIR/agent-bridge.pid"
say() { echo "$(date +%FT%T) START $*" | tee -a "$LOG"; }

# exactly one live Claude Code / Codex peer with this name or id? (same resolver the bridge uses)
peer_ok() { python3 - "$KIT/codex-bridge/peerbridge" "$1" <<'PY'
import sys; sys.path.insert(0, sys.argv[1]); import ccpeer
sys.exit(0 if len(ccpeer.resolve(sys.argv[2])) == 1 else 1)
PY
}

codex_thread() {   # prints the codex pane's current thread id, or nothing (reason on stderr)
  local pane info pid cwd start daemons
  pane="$(herdr --session "$S" pane list 2>/dev/null | jq -r '[.result.panes[]|select(.label=="codex")][0].pane_id // empty')"
  [ -n "$pane" ] || { echo "no herdr pane labelled codex in session $S" >&2; return; }
  info="$(herdr --session "$S" pane process-info --pane "$pane" 2>/dev/null)"
  pid="$(jq -r '[.result.process_info.foreground_processes[]|select(.name=="codex")][0].pid // empty' <<<"$info")"
  cwd="$(jq -r '[.result.process_info.foreground_processes[]|select(.name=="codex")][0].cwd // empty' <<<"$info")"
  [ -n "$pid" ] || { echo "codex pane $pane runs no codex process" >&2; return; }
  start=$(( $(date +%s) - $(ps -o etimes= -p "$pid" | tr -d ' ') ))
  daemons="$(pgrep -f 'app-server.*--managed-daemon' | tr '\n' ' ')"
  [ -n "$daemons" ] || { echo "no managed Codex daemon running" >&2; return; }
  python3 - "$start" "$cwd" $daemons <<'PY'
import glob, json, os, subprocess, sys
from datetime import datetime
start, cwd, daemons = int(sys.argv[1]), sys.argv[2], sys.argv[3:]
open_files = set()
for d in daemons:
    for fd in glob.glob(f"/proc/{d}/fd/*"):
        try: t = os.readlink(fd)
        except OSError: continue
        if "/sessions/" in t and os.path.basename(t).startswith("rollout-") and t.endswith(".jsonl"): open_files.add(t)
cands = []
for f in open_files:
    try: meta = json.loads(open(f, encoding="utf-8").readline()).get("payload", {})
    except (OSError, ValueError): continue
    # any originator (codex-tui, a peerbridge hub, an IDE): the cwd + created-after-start + held-open-by-the-daemon tests decide
    if meta.get("cwd") != cwd: continue
    try: created = datetime.fromisoformat(meta["timestamp"].replace("Z", "+00:00")).timestamp()
    except (KeyError, ValueError): continue
    if created >= start - 120: cands.append((created, meta["id"]))
if len(cands) > 1:
    try: exposed = set(json.load(open(os.path.expanduser("~/.peerbridge/policy.json"))).get("threads", []))
    except (OSError, ValueError): exposed = set()
    pick = [c for c in cands if c[1] in exposed]
    if len(pick) == 1: cands = pick
if len(cands) == 1: print(cands[0][1])
else: print(f"codex thread: {len(cands)} candidates {[c[1] for c in cands]} (want exactly 1)", file=sys.stderr)
PY
}

# ---- discover, retrying missing peers for up to $WAIT s
deadline=$(( $(date +%s) + WAIT ))
while :; do
  maps=(); missing=()
  for p in claude rc; do
    if peer_ok "$p"; then [ $p = claude ] && maps+=(--map "$PREFIX-claude=peer:claude+bypass") || maps+=(--map "$PREFIX-rc=peer:rc")
    else missing+=("$p"); fi
  done
  tid="$(codex_thread 2>>"$LOG")"
  if [ -n "$tid" ]; then maps+=(--map "$PREFIX-codex=peer:$tid"); else missing+=(codex); fi
  [ ${#missing[@]} -eq 0 ] || [ "$(date +%s)" -ge "$deadline" ] && break
  sleep 5
done
[ ${#missing[@]} -eq 0 ] || say "WARNING no route for: ${missing[*]} (gave up after ${WAIT}s; see log)"
[ ${#maps[@]} -gt 0 ] || { say "ERROR nothing to bridge"; exit 1; }
cmd=(python3 -u "$KIT/hub/agent-bridge.py" --gate trusted "${maps[@]}")
say "routes: ${maps[*]}"

if [ "$DRY" = 1 ]; then
  [ -n "$tid" ] && echo "would run: pb expose --thread $tid"
  echo "would run: ${cmd[*]}"
  [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null && echo "live bridge: $(tr '\0' ' ' < /proc/$(cat "$PIDF")/cmdline)"
  exit 0
fi
[ -n "$tid" ] && { pb expose --thread "$tid" >/dev/null || say "ERROR pb expose --thread $tid failed"; }
if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then
  live="$(tr '\0' ' ' < "/proc/$(cat "$PIDF")/cmdline")"
  [ "$live" = "${cmd[*]} " ] && { say "bridge pid $(cat "$PIDF") already runs these routes"; exit 0; }
  kill "$(cat "$PIDF")"; sleep 1
fi
setsid nohup "${cmd[@]}" >> "$LOG" 2>&1 < /dev/null &
echo $! > "$PIDF"; say "bridge pid $(cat "$PIDF") started"
