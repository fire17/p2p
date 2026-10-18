#!/usr/bin/env bash
# agent-bridge-start.sh - discover this PC's herdr agents and (re)start hub/agent-bridge.py for them, detached.
#
#   agent-bridge-start.sh --prefix lap [--session main] [--claude claude] [--dry-run] [--wait 120]   one shot
#   agent-bridge-start.sh --prefix lap [--session main] [--claude claude] --watch 60                 keep it matching
#   --workspace W (either mode): look for the labelled panes only in herdr workspace W (default: the whole session)
#
# Routes (hub name -> route), discovered every time, never fixed ids. For the herdr pane labelled codex and each pane
# named in --claude (comma list, default "claude"; e.g. --claude claude,review for a second Claude pane), each label
# on exactly ONE pane (several = no new route, logged, never a guess, a live bridge keeps its route):
#   <prefix>-<label>  peer:<session id>, the session the pane's own claude process runs as: its registry record
#        (by pid, never by display name: two PCs or two panes may both run `claude -n X`). That record must be on
#        this machine (its pidDomain = ccpeer.pid_domain(); the bridge checks it again at every delivery) and its
#        session id must resolve to exactly that one process. A restarted or /clear-ed session gets a new id:
#        --watch follows it. +bypass only when that claude process really runs bypassPermissions (its
#        /proc/<pid>/cmdline has --dangerously-skip-permissions or --permission-mode bypassPermissions); herdr
#        reports no argv for claude, so /proc is read directly.
#   <prefix>-codex  peer:<thread id>, the codex pane's CURRENT thread: a rollout the managed Codex daemon holds open
#        (any originator) with cwd = the pane's cwd. Exactly ONE such rollout and no other codex process in that cwd:
#        that one, whatever its time. Otherwise the ones created no earlier than 120 s + 10% of the process age
#        before the pane's codex process started (the thread can be created 30 s before it, or hours after it at the
#        first prompt; the 10% absorbs a WSL monotonic clock that runs fast or slow against the wall clock the
#        rollout time is written in; /proc starttime + btime is the same clock as now - etimes, so it cannot). No such
#        thread, but the one chosen before (agent-bridge.codex-thread) is still open with that cwd: keep it. A new
#        thread always wins. Several: the one pb already exposes wins; still ambiguous: no codex route (logged, never
#        a guess). The daemon keeps a thread open after its TUI exits, so right after a pane restart in the same cwd
#        the old thread can stay the route until the new process's first prompt makes a new one. The thread is `pb expose`d
#        (re-tried on the next pass if that failed; never again once it worked, so the owner's `pb hide` sticks);
#        once that worked, the thread this script exposed before is `pb hide`n.
#        No thread yet (Codex makes one only at the pane's first prompt): herdr:<session>:<pane>, i.e. the bridge
#        types into the pane, guarded by its idle + dialog check. That first message creates the thread; --watch then
#        switches to the native peer.
#        Both codex routes carry +trusted: only senders in trusted.json reach Codex (it runs its turns unattended).
# --names FILE (either mode): more routes, one per `[<pane label>]=<name>` pair in FILE (e.g. a names map like
#   `[web-claude]=web-claude`) whose label ends in -claude or -codex; other pairs, and anything after a #, are skipped.
#   <prefix>-<name>  for a -claude label: exactly as <prefix>-<label> above (whatever `-n` the session got).
#                    for a -codex label: exactly as <prefix>-codex above, with its own previous-thread file
#        (agent-bridge.codex-thread.<prefix>-<name>), so one route's new thread never hides another's.
#   Several panes with the label: no new route, a live bridge keeps its route. Codex panes that share a cwd
#   (the plain codex pane included): none of them gets a new route (a thread is told apart only by cwd).
#   One bridge carries all routes.
# One shot: missing peers are retried for --wait s, then the bridge starts with what exists (WARNING in the log).
# --watch SEC: rediscover every SEC s and restart the bridge only when the map differs from the live one on two
#   checks in a row (one failed lookup never drops a route). Covers reboot, pane restarts and the lazy codex thread.
#   One watcher per --dir (flock); a second one exits.
# Idempotent: a live bridge with the same routes is left alone. --dry-run prints the map and command, changes nothing.
# Files in $BRIDGE_DIR (default ~/.agent-bridge): agent-bridge.pid, agent-bridge.log, agent-bridge.codex-thread[.<route>],
# agent-bridge.watch.lock, agent-bridge.watch.pid.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="${AGENT_KIT:-${SHAI_KIT:-$(dirname "$HERE")}}"
DIR="${BRIDGE_DIR:-$HOME/.agent-bridge}"
PREFIX=""; S="main"; DRY=0; WAIT=120; WATCH=0; CLAUDES="claude"; WS=""; NAMES=""
while [ $# -gt 0 ]; do case "$1" in
  --prefix) PREFIX="${2:?}"; shift 2 ;; --session) S="${2:?}"; shift 2 ;; --claude) CLAUDES="${2:?}"; shift 2 ;;
  --dry-run) DRY=1; shift ;; --wait) WAIT="${2:?}"; shift 2 ;; --watch) WATCH="${2:?}"; shift 2 ;;
  --workspace) WS="${2:?}"; shift 2 ;; --names) NAMES="${2:?}"; shift 2 ;;
  *) echo "usage: $0 --prefix NAME [--session S] [--workspace W] [--claude LABEL[,LABEL]] [--names FILE] [--dry-run] [--wait SEC | --watch SEC]" >&2; exit 2 ;; esac; done
case ",$CLAUDES," in *,codex,*|*[!A-Za-z0-9_,-]*|,,) echo "agent-bridge-start: --claude takes pane labels, e.g. claude or claude,review" >&2; exit 2 ;; esac
[ -n "$PREFIX" ] || { echo "agent-bridge-start: --prefix is required (e.g. lap, desk)" >&2; exit 2; }
[ -z "$NAMES" ] || [ -r "$NAMES" ] || { echo "agent-bridge-start: --names $NAMES is not readable" >&2; exit 2; }
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

session_of() {  # session id of the live Claude session that IS process $1, on this machine, resolving to it alone
python3 - "$KIT/codex-bridge/peerbridge" "$1" <<'PY'
import re, sys; sys.path.insert(0, sys.argv[1]); import ccpeer
mine = [r for r in ccpeer.records() if str(r.get("pid")) == sys.argv[2]]
if len(mine) != 1: sys.exit(1)
sid = str(mine[0].get("sessionId") or "")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", sid): sys.exit(1)  # a route peer holds no space, '+' or ':'
here, theirs = getattr(ccpeer, "pid_domain", lambda: "")(), mine[0].get("pidDomain")
tail = lambda d: d.split(":", 1)[1] if d.split(":", 1)[0] in ("linux", "wsl") and ":" in d else d
if here and isinstance(theirs, str) and tail(theirs) != tail(here): sys.exit(1)  # a record from another machine
r = ccpeer.resolve(sid)
if len(r) != 1 or str(r[0].get("pid")) != sys.argv[2]: sys.exit(1)
print(sid)
PY
}

is_bypass() {  # the claude process really runs bypassPermissions?
  local a; a="$(tr '\0' '\n' 2>/dev/null < "/proc/$1/cmdline")" || return 1
  grep -qx -- '--dangerously-skip-permissions' <<<"$a" && return 0
  grep -A1 -x -- '--permission-mode' <<<"$a" | grep -qx bypassPermissions
}

codex_thread() {  # thread id on stdout; "" = the pane has no thread yet; exit 1 = cannot tell (reason on stderr)
  local pid="$1" cwd="$2" tidf="$3" age daemons   # tidf: this route's previous-thread file
  age="$(ps -o etimes= -p "$pid" | tr -d ' ')"
  daemons="$(pgrep -f 'app-server.*--managed-daemon' | tr '\n' ' ')"
  [ -n "$daemons" ] || { echo "no managed Codex daemon running" >&2; return 1; }
  python3 - "$age" "$cwd" "$tidf" "$pid" $daemons <<'PY'
import glob, json, os, sys, time
from datetime import datetime
age, cwd, tidf, pid, daemons = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
start, slack = time.time() - age, 120 + age // 10
def other_codex():  # another codex process (not a daemon) runs in this cwd
    for d in glob.glob("/proc/[0-9]*"):
        try:
            if os.path.basename(d) in (pid, *daemons) or open(d + "/comm").read().strip() != "codex": continue
            if os.readlink(d + "/cwd") == cwd and b"app-server" not in open(d + "/cmdline", "rb").read(): return True
        except OSError: continue
    return False
try: prev = open(tidf).read().strip()
except OSError: prev = ""
open_files = set()
for d in daemons:
    for fd in glob.glob(f"/proc/{d}/fd/*"):
        try: t = os.readlink(fd)
        except OSError: continue
        if "/sessions/" in t and os.path.basename(t).startswith("rollout-") and t.endswith(".jsonl"): open_files.add(t)
cands, matches, prev_open = [], [], False
for f in open_files:
    try: meta = json.loads(open(f, encoding="utf-8").readline()).get("payload", {})
    except (OSError, ValueError): continue
    if meta.get("cwd") != cwd or not meta.get("id"): continue
    matches.append((0, meta["id"]))
    if prev and meta.get("id") == prev: prev_open = True
    try: created = datetime.fromisoformat(meta["timestamp"].replace("Z", "+00:00")).timestamp()
    except (KeyError, ValueError): continue
    if created >= start - slack: cands.append((created, meta["id"]))
if len(matches) == 1 and not other_codex():
    cands = matches   # the only thread with this cwd, and no other codex there: no clock needed
elif not cands and prev_open:
    # No thread created since the pane started, but the one chosen before is still open with this cwd: keep it.
    # (start = now - etimes moves when WSL steps its wall clock, which can push that thread out of the window.)
    cands = [(0, prev)]
if len(cands) > 1:
    try: exposed = set(json.load(open(os.path.expanduser("~/.peerbridge/policy.json"))).get("threads", []))
    except (OSError, ValueError): exposed = set()
    pick = [c for c in cands if c[1] in exposed]
    if len(pick) == 1: cands = pick
if len(cands) > 1:
    print(f"codex thread in {cwd}: {len(cands)} candidates {[c[1] for c in cands]} (want exactly 1)", file=sys.stderr); sys.exit(1)
print(cands[0][1] if cands else "")
PY
}

named() {  # "label=name" lines from --names: [<label>]=<name> pairs whose label ends in -claude / -codex
  [ -n "$NAMES" ] || return 0
  sed 's/#.*//' "$NAMES" | grep -oE '\[[A-Za-z0-9_.-]+-(claude|codex)\]=[A-Za-z0-9][A-Za-z0-9_.-]*' | sed 's/^\[//; s/\]=/=/'
}

tidf() {  # route $1's previous-thread file (the plain codex route keeps the old file name)
  if [ "$1" = "$PREFIX-codex" ]; then echo "$TIDF"; else echo "$TIDF.$1"; fi; }

named_claude() {  # route $2 for the claude in the pane labelled $1: peer = the session id that pane's process runs as
  local pane pid sn
  pane="$(pane_of "$1" 2>>"$LOG")" || { MISSING+=("$1(several panes, see log)"); keep "$2"; return; }
  [ -n "$pane" ] || { MISSING+=("$1(no pane)"); return; }
  pid="$(proc_of "$pane" claude)"; pid="${pid%%$'\t'*}"
  [ -n "$pid" ] || { MISSING+=("$1(no claude process)"); return; }
  sn="$(session_of "$pid")" || { MISSING+=("$1(no unique live session for pid $pid)"); return; }
  if is_bypass "$pid"; then MAPS+=(--map "$2=peer:$sn+bypass"); else MAPS+=(--map "$2=peer:$sn"); fi
}

codex_routes() {  # "label=route" args: the codex pane per label -> its thread (or herdr until it has one)
  local kv label hub pane pc pid cwd t cwds="" i=0; local -a L=() H=() P=() C=() D=()
  for kv in "$@"; do   # pass 1: pane, codex pid and cwd per label
    label="${kv%%=*}"; hub="${kv#*=}"
    pane="$(pane_of "$label" 2>>"$LOG")" || { MISSING+=("$label(several panes, see log)"); keep "$hub"; continue; }
    [ -n "$pane" ] || { MISSING+=("$label(no pane)"); continue; }
    pc="$(proc_of "$pane" codex)"; pid="${pc%%$'\t'*}"; cwd="${pc#*$'\t'}"
    [ -n "$pid" ] || { MISSING+=("$label(no codex process)"); continue; }
    L+=("$label"); H+=("$hub"); P+=("$pane"); C+=("$pid"); D+=("$cwd"); cwds+="$cwd"$'\n'
  done
  while [ $i -lt ${#L[@]} ]; do   # pass 2: a thread is told apart only by cwd, so a shared cwd is never guessed
    label="${L[$i]}"; hub="${H[$i]}"; pane="${P[$i]}"; pid="${C[$i]}"; cwd="${D[$i]}"; i=$((i + 1))
    if [ "$(grep -cxF -- "$cwd" <<<"$cwds")" -gt 1 ]; then
      echo "$(date +%FT%T) START codex pane $label: cwd $cwd shared with another codex pane (want exactly 1)" >>"$LOG"
      MISSING+=("$label(cwd shared, see log)"); keep "$hub"; continue
    fi
    if t="$(codex_thread "$pid" "$cwd" "$(tidf "$hub")" 2>>"$LOG")"; then
      if [ -n "$t" ]; then TH+=("$hub"); TT+=("$t"); MAPS+=(--map "$hub=peer:$t+trusted")
      else MAPS+=(--map "$hub=herdr:$S:$pane+trusted"); fi   # no thread yet: typed until the first prompt makes one
    else MISSING+=("$label(thread unclear, see log)"); fi
  done
}

discover() {  # sets MAPS (array), TH/TT (codex route -> its thread), MISSING (array)
  MAPS=(); MISSING=(); TH=(); TT=()
  local label kv; local -a cx=("codex=$PREFIX-codex")
  for label in ${CLAUDES//,/ }; do named_claude "$label" "$PREFIX-$label"; done
  local seen=" $PREFIX-codex "; for label in ${CLAUDES//,/ }; do seen+="$PREFIX-$label "; done   # one route per name
  for kv in $(named); do
    case "$seen" in *" $PREFIX-${kv#*=} "*) MISSING+=("${kv%%=*}(route name $PREFIX-${kv#*=} taken)"); continue ;; esac
    seen+=" $PREFIX-${kv#*=} "
    case "$kv" in *-claude=*) named_claude "${kv%%=*}" "$PREFIX-${kv#*=}" ;; *) cx+=("${kv%%=*}=$PREFIX-${kv#*=}") ;; esac
  done
  codex_routes "${cx[@]}"
}

live_cmd() {  # cmdline of the live bridge; fails when the pid file is stale (dead, or the pid reused by another process)
  local p a; p="$(cat "$PIDF" 2>/dev/null)" || return 1
  case "$p" in ""|*[!0-9]*) return 1 ;; esac
  kill -0 "$p" 2>/dev/null && a="$(tr '\0' ' ' 2>/dev/null < "/proc/$p/cmdline")" || return 1
  case "$a" in *"/hub/agent-bridge.py --gate trusted "*) printf '%s' "$a" ;; *) return 1 ;; esac
}

tid_ok() {  # thread $2 of route $1 was exposed once already (its file is written only after a pb expose worked).
  [ "$(cat "$(tidf "$1")" 2>/dev/null)" = "$2" ]   # Never re-exposed after that: a `pb hide` by the owner sticks.
}

expose_tid() {  # pb expose thread $2 of route $1; only once that worked: hide the route's thread exposed before, remember $2
  local f old; f="$(tidf "$1")"; old="$(cat "$f" 2>/dev/null || true)"
  pb expose --thread "$2" >/dev/null || { say "ERROR pb expose --thread $2 ($1) failed (retried next pass)"; return 1; }
  [ -n "$old" ] && [ "$old" != "$2" ] && { pb hide --thread "$old" >/dev/null || say "ERROR pb hide --thread $old failed"; }
  echo "$2" > "$f"
}

expose_new() {  # every codex route's thread that was not exposed yet
  local i=0; while [ $i -lt ${#TH[@]} ]; do
    tid_ok "${TH[$i]}" "${TT[$i]}" || expose_tid "${TH[$i]}" "${TT[$i]}"; i=$((i + 1)); done; }

apply() {  # make the running bridge match MAPS/TH/TT
  local cmd=(python3 -u "$KIT/hub/agent-bridge.py" --gate trusted "${MAPS[@]}") p
  expose_new
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
    else pending=""; expose_new 9>&-; fi   # routes match: retry a failed/lost expose
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
  i=0; while [ $i -lt ${#TH[@]} ]; do
    tid_ok "${TH[$i]}" "${TT[$i]}" || echo "would run: pb expose --thread ${TT[$i]} (${TH[$i]})"; i=$((i + 1)); done
  echo "would run: python3 -u $KIT/hub/agent-bridge.py --gate trusted ${MAPS[*]}"
  echo "live bridge: $(live_cmd || echo none)"
  exit 0
fi
apply
