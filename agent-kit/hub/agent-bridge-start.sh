#!/usr/bin/env bash
# agent-bridge-start.sh - discover this PC's herdr agents and (re)start hub/agent-bridge.py for them, detached.
#
#   agent-bridge-start.sh --prefix lap [--session main] [--claude claude] [--dry-run] [--wait 120]   one shot
#   agent-bridge-start.sh --prefix lap [--session main] [--claude claude] --watch 60                 keep it matching
#   --workspace W (either mode): look for the labelled panes only in herdr workspace W (default: the whole session)
#
# Routes (hub name -> route), discovered every time, never fixed ids. For the herdr pane labelled codex and each pane
# named in --claude (comma list, default "claude"; e.g. --claude claude,review for a second Claude pane), each label
# on exactly ONE pane (codex: several = no new route, logged, never a guess, a live bridge keeps its route; claude:
# only logged, since its route reaches the ccpeer session, not the pane):
#   <prefix>-<label>  peer:<label>, the Claude Code session named like the pane (`claude -n <label>`); it
#        must resolve to exactly one live session (ccpeer.resolve). +bypass only when that claude process really runs
#        bypassPermissions (its /proc/<pid>/cmdline has --dangerously-skip-permissions or --permission-mode
#        bypassPermissions); herdr reports no argv for claude, so /proc is read directly, for the pid of the session
#        ccpeer resolved (the one the route reaches), not for whatever runs in the pane.
#   <prefix>-codex  peer:<thread id>, the codex pane's CURRENT thread: a rollout the managed Codex daemon holds open
#        (any originator), cwd = the pane's cwd, created no earlier than 120 s before the pane's codex process
#        started (the thread can be created 30 s before it, or hours after it at the first prompt). No such thread,
#        but the one chosen before (agent-bridge.codex-thread) is still open with that cwd: keep it (start = now -
#        etimes moves when WSL steps its clock). A new thread always wins. Several: the one pb
#        already exposes wins; still ambiguous: no codex route (logged, never a guess). The thread is `pb expose`d
#        (re-tried on the next pass if that failed; never again once it worked, so the owner's `pb hide` sticks);
#        once that worked, the thread this script exposed before is `pb hide`n.
#        No thread yet (Codex makes one only at the pane's first prompt): herdr:<session>:<pane>, i.e. the bridge
#        types into the pane, guarded by its idle + dialog check. That first message creates the thread; --watch then
#        switches to the native peer.
#        Both codex routes carry +trusted: only senders in trusted.json reach Codex (it runs its turns unattended).
# One shot: missing peers are retried for --wait s, then the bridge starts with what exists (WARNING in the log).
# --watch SEC: rediscover every SEC s and restart the bridge only when the map differs from the live one on two
#   checks in a row (one failed lookup never drops a route). Covers reboot, pane restarts and the lazy codex thread.
#   One watcher per --dir (flock); a second one exits.
# Idempotent: a live bridge with the same routes is left alone. --dry-run prints the map and command, changes nothing.
# Files in $BRIDGE_DIR (default ~/.agent-bridge): agent-bridge.pid, agent-bridge.log, agent-bridge.codex-thread,
# agent-bridge.watch.lock, agent-bridge.watch.pid.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="${AGENT_KIT:-${SHAI_KIT:-$(dirname "$HERE")}}"
DIR="${BRIDGE_DIR:-$HOME/.agent-bridge}"
PREFIX=""; S="main"; DRY=0; WAIT=120; WATCH=0; CLAUDES="claude"; WS=""
while [ $# -gt 0 ]; do case "$1" in
  --prefix) PREFIX="${2:?}"; shift 2 ;; --session) S="${2:?}"; shift 2 ;; --claude) CLAUDES="${2:?}"; shift 2 ;;
  --dry-run) DRY=1; shift ;; --wait) WAIT="${2:?}"; shift 2 ;; --watch) WATCH="${2:?}"; shift 2 ;;
  --workspace) WS="${2:?}"; shift 2 ;;
  *) echo "usage: $0 --prefix NAME [--session S] [--workspace W] [--claude LABEL[,LABEL]] [--dry-run] [--wait SEC | --watch SEC]" >&2; exit 2 ;; esac; done
case ",$CLAUDES," in *,codex,*|*[!A-Za-z0-9_,-]*|,,) echo "agent-bridge-start: --claude takes pane labels, e.g. claude or claude,review" >&2; exit 2 ;; esac
[ -n "$PREFIX" ] || { echo "agent-bridge-start: --prefix is required (e.g. lap, desk)" >&2; exit 2; }
[ "$WATCH" = 0 ] || [ "$DRY" = 0 ] || { echo "agent-bridge-start: --watch and --dry-run exclude each other" >&2; exit 2; }
export PATH="$HOME/.local/bin:$PATH"
for c in herdr jq pb python3 flock; do command -v $c >/dev/null || { echo "agent-bridge-start: missing $c" >&2; exit 1; }; done
mkdir -p "$DIR"; LOG="$DIR/agent-bridge.log"; PIDF="$DIR/agent-bridge.pid"; TIDF="$DIR/agent-bridge.codex-thread"
say() { echo "$(date +%FT%T) START $*" | tee -a "$LOG"; }

h() { herdr --session "$S" "$@"; }
pane_of() {  # the ONE pane labelled $1 ("" = none); several: nothing on stdout, ids on stderr, exit 2 (never a guess)
  local ids n
  ids="$(h pane list ${WS:+--workspace "$WS"} 2>/dev/null | jq -r --arg l "$1" '.result.panes[]?|select(.label==$l)|.pane_id // empty')"
  n=$(grep -c . <<<"$ids")
  [ "$n" -le 1 ] && { echo "$ids"; return 0; }
  echo "$(date +%FT%T) START pane label $1: $n panes" $ids "(want exactly 1)" >&2; return 2
}
keep() {  # several panes carry the label: keep the live bridge's route for hub name $1, if it has one
  local w; for w in $(live_cmd); do case "$w" in "$1="*) MAPS+=(--map "$w"); return ;; esac; done
}
proc_of() {  # pid and cwd ("pid<TAB>cwd") of the process named $2 in the foreground of pane $1
  h pane process-info --pane "$1" 2>/dev/null \
    | jq -r --arg n "$2" '[.result.process_info.foreground_processes[]|select(.name==$n)][0] | "\(.pid // "")\t\(.cwd // "")"'; }

peer_ok() {  # exactly one live Claude session named $1? its pid on stdout (the process the route reaches)
python3 - "$KIT/codex-bridge/peerbridge" "$1" <<'PY'
import sys; sys.path.insert(0, sys.argv[1]); import ccpeer
r = ccpeer.resolve(sys.argv[2])
if len(r) != 1: sys.exit(1)
print(r[0].get("pid") or "")
PY
}

is_bypass() {  # the claude process really runs bypassPermissions?
  local a; a="$(tr '\0' '\n' 2>/dev/null < "/proc/$1/cmdline")" || return 1
  grep -qx -- '--dangerously-skip-permissions' <<<"$a" && return 0
  grep -A1 -x -- '--permission-mode' <<<"$a" | grep -qx bypassPermissions
}

codex_thread() {  # thread id on stdout; "" = the pane has no thread yet; exit 1 = cannot tell (reason on stderr)
  local pid="$1" cwd="$2" start daemons
  start=$(( $(date +%s) - $(ps -o etimes= -p "$pid" | tr -d ' ') ))
  daemons="$(pgrep -f 'app-server.*--managed-daemon' | tr '\n' ' ')"
  [ -n "$daemons" ] || { echo "no managed Codex daemon running" >&2; return 1; }
  python3 - "$start" "$cwd" "$TIDF" $daemons <<'PY'
import glob, json, os, sys
from datetime import datetime
start, cwd, tidf, daemons = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4:]
try: prev = open(tidf).read().strip()
except OSError: prev = ""
open_files = set()
for d in daemons:
    for fd in glob.glob(f"/proc/{d}/fd/*"):
        try: t = os.readlink(fd)
        except OSError: continue
        if "/sessions/" in t and os.path.basename(t).startswith("rollout-") and t.endswith(".jsonl"): open_files.add(t)
cands, prev_open = [], False
for f in open_files:
    try: meta = json.loads(open(f, encoding="utf-8").readline()).get("payload", {})
    except (OSError, ValueError): continue
    if meta.get("cwd") != cwd: continue
    if prev and meta.get("id") == prev: prev_open = True
    try: created = datetime.fromisoformat(meta["timestamp"].replace("Z", "+00:00")).timestamp()
    except (KeyError, ValueError): continue
    if created >= start - 120: cands.append((created, meta["id"]))
if not cands and prev_open:
    # No thread created since the pane started, but the one chosen before is still open with this cwd: keep it.
    # (start = now - etimes moves when WSL steps its wall clock, which can push that thread out of the window.)
    cands = [(0, prev)]
if len(cands) > 1:
    try: exposed = set(json.load(open(os.path.expanduser("~/.peerbridge/policy.json"))).get("threads", []))
    except (OSError, ValueError): exposed = set()
    pick = [c for c in cands if c[1] in exposed]
    if len(pick) == 1: cands = pick
if len(cands) > 1:
    print(f"codex thread: {len(cands)} candidates {[c[1] for c in cands]} (want exactly 1)", file=sys.stderr); sys.exit(1)
print(cands[0][1] if cands else "")
PY
}

discover() {  # sets MAPS (array), TID (codex thread or ""), MISSING (array)
  MAPS=(); MISSING=(); TID=""
  local label pane pc pid cwd t
  for label in ${CLAUDES//,/ }; do
    # the claude route reaches the ccpeer session, not a pane: several panes with the label are only logged
    pane="$(pane_of "$label" 2>>"$LOG")" || pane="several"
    [ -n "$pane" ] || { MISSING+=("$label(no pane)"); continue; }
    pid="$(peer_ok "$label")" || { MISSING+=("$label(no unique live session)"); continue; }
    if [ -n "$pid" ] && is_bypass "$pid"; then MAPS+=(--map "$PREFIX-$label=peer:$label+bypass")
    else MAPS+=(--map "$PREFIX-$label=peer:$label"); fi
  done
  pane="$(pane_of codex 2>>"$LOG")" || { MISSING+=("codex(several panes, see log)"); keep "$PREFIX-codex"; return; }
  [ -n "$pane" ] || { MISSING+=("codex(no pane)"); return; }
  pc="$(proc_of "$pane" codex)"; pid="${pc%%$'\t'*}"; cwd="${pc#*$'\t'}"
  [ -n "$pid" ] || { MISSING+=("codex(no codex process)"); return; }
  if t="$(codex_thread "$pid" "$cwd" 2>>"$LOG")"; then
    if [ -n "$t" ]; then TID="$t"; MAPS+=(--map "$PREFIX-codex=peer:$t+trusted")
    else MAPS+=(--map "$PREFIX-codex=herdr:$S:$pane+trusted"); fi   # no thread yet: typed until the first prompt makes one
  else MISSING+=("codex(thread unclear, see log)"); fi
}

live_cmd() {  # cmdline of the live bridge; fails when the pid file is stale (dead, or the pid reused by another process)
  local p a; p="$(cat "$PIDF" 2>/dev/null)" || return 1
  case "$p" in ""|*[!0-9]*) return 1 ;; esac
  kill -0 "$p" 2>/dev/null && a="$(tr '\0' ' ' 2>/dev/null < "/proc/$p/cmdline")" || return 1
  case "$a" in *"/hub/agent-bridge.py --gate trusted "*) printf '%s' "$a" ;; *) return 1 ;; esac
}

tid_ok() {  # TID was exposed once already (TIDF is written only after a pb expose worked). Never re-exposed after
  [ "$(cat "$TIDF" 2>/dev/null)" = "$TID" ]   # that: a `pb hide` by the owner sticks.
}

expose_tid() {  # pb expose TID; only once that worked: hide the thread exposed before and remember TID
  local old; old="$(cat "$TIDF" 2>/dev/null || true)"
  pb expose --thread "$TID" >/dev/null || { say "ERROR pb expose --thread $TID failed (retried next pass)"; return 1; }
  [ -n "$old" ] && [ "$old" != "$TID" ] && { pb hide --thread "$old" >/dev/null || say "ERROR pb hide --thread $old failed"; }
  echo "$TID" > "$TIDF"
}

apply() {  # make the running bridge match MAPS/TID
  local cmd=(python3 -u "$KIT/hub/agent-bridge.py" --gate trusted "${MAPS[@]}") p
  [ -n "$TID" ] && ! tid_ok && expose_tid
  [ "$(live_cmd)" = "${cmd[*]} " ] && { say "bridge pid $(cat "$PIDF") already runs these routes"; return; }
  p="$(cat "$PIDF" 2>/dev/null)"
  if live_cmd >/dev/null; then   # only ever signal the bridge itself, and let it finish (no -9: it may hold a claim)
    kill "$p" 2>/dev/null
    for _ in $(seq 40); do live_cmd >/dev/null || break; sleep 0.25; done
    live_cmd >/dev/null && say "WARNING old bridge pid $p still running after 10s"
  fi
  rm -f "$PIDF"
  setsid nohup "${cmd[@]}" >> "$LOG" 2>&1 < /dev/null &
  echo $! > "$PIDF"; say "bridge pid $(cat "$PIDF") started: ${MAPS[*]}"
}

if [ "$WATCH" != 0 ]; then
  exec 9>"$DIR/agent-bridge.watch.lock"
  flock -n 9 || { echo "agent-bridge-start: a watcher already runs for $DIR" >&2; exit 0; }
  echo $$ > "$DIR/agent-bridge.watch.pid"
  say "watch every ${WATCH}s (prefix $PREFIX, session $S)"
  pending=""
  while :; do                  # 9>&- below: children (above all the bridge) must not inherit the watcher lock
    discover 9>&-
    want="python3 -u $KIT/hub/agent-bridge.py --gate trusted ${MAPS[*]} "
    if [ ${#MAPS[@]} -gt 0 ] && [ "$(live_cmd)" != "$want" ]; then
      if [ "$pending" = "$want" ] || ! live_cmd >/dev/null; then   # seen twice in a row, or nothing running at all
        [ ${#MISSING[@]} -eq 0 ] || say "WARNING no route for: ${MISSING[*]}"
        apply 9>&-; pending=""
      else pending="$want"; fi
    else pending=""; [ -n "$TID" ] && ! tid_ok 9>&- && expose_tid 9>&-; fi   # routes match: retry a failed/lost expose
    sleep "$WATCH" 9>&-
  done
fi

deadline=$(( $(date +%s) + WAIT ))
while :; do
  discover
  [ ${#MISSING[@]} -eq 0 ] || [ "$(date +%s)" -ge "$deadline" ] && break
  sleep 5
done
[ ${#MISSING[@]} -eq 0 ] || say "WARNING no route for: ${MISSING[*]} (after ${WAIT}s)"
[ ${#MAPS[@]} -gt 0 ] || { say "ERROR nothing to bridge"; exit 1; }
if [ "$DRY" = 1 ]; then
  echo "routes: ${MAPS[*]}"
  [ -n "$TID" ] && echo "would run: pb expose --thread $TID"
  echo "would run: python3 -u $KIT/hub/agent-bridge.py --gate trusted ${MAPS[*]}"
  echo "live bridge: $(live_cmd || echo none)"
  exit 0
fi
apply
