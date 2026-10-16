#!/bin/sh
# agent-bridge.py against fakes: a fake ccpeer module (PYTHONPATH) and a fake herdr (PATH). Offline, any POSIX box.
# Proves: ccpeer is used first, herdr is the fallback, a blocked (or dialog-showing "idle") pane is never typed
# into, --dry-run sends nothing, presence is kept, typed text is control-free. Also agent-bridge-start.sh --dry-run:
# a label on several panes is never guessed, --workspace scopes it, a stale (reused) pid is not taken for the bridge.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/agent-bridge-test.XXXXXX"); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/fakepy" "$T/bin" "$T/herdr" "$T/empty"
pass=0 fail=0
ok() { if [ "$1" = 0 ]; then pass=$((pass+1)); echo "PASS $2"; else fail=$((fail+1)); echo "FAIL $2"; fi; }

# ---- fake ccpeer: peers listed in $FAKE_PEERS (comma list); send_to appends frames to $T/ccpeer.log
cat > "$T/fakepy/ccpeer.py" <<'EOF'
import json, os
def records():
    return [{"name": n, "ref": "abcdef123456", "sessionId": "sid-" + n, "address": "uds:/x/" + n,
             "messagingSocketPath": "/x/" + n, "pid": 1} for n in os.environ.get("FAKE_PEERS", "").split(",") if n]
def resolve(to, recs=None):
    return [r for r in (records() if recs is None else recs) if r["name"] == to or r["sessionId"] == to]
def envelope(text, frm, from_name, from_mode):
    return '<cross-session-message from="%s" from-name="%s">\n%s\n</cross-session-message>' % (frm, from_name, text)
def user_frame(frm, env, session_id=None, msg_id=None):
    return {"type": "user", "from": frm, "session_id": session_id, "message": {"role": "user", "content": env}}
def send_to(rec, frames):
    if os.environ.get("FAKE_CCPEER_FAIL"):
        raise ConnectionRefusedError("fake")
    with open(os.environ["FAKE_CCPEER_LOG"], "a") as f:
        for fr in frames:
            f.write(json.dumps({"to": rec["name"], "frame": fr}) + "\n")
EOF

# ---- fake herdr: state in $T/herdr/<pane>.state, screen in <pane>.screen; every call logged; prompt/run log text
cat > "$T/bin/herdr" <<'EOF'
#!/usr/bin/env python3
import json, os, sys
d = os.environ["FAKE_HERDR_DIR"]
a = sys.argv[1:]
with open(os.path.join(d, "calls.log"), "a") as f: f.write(json.dumps(a) + "\n")
if a[:1] != ["--session"]: sys.exit(9)
a = a[2:]
def rd(p, n):
    try: return open(os.path.join(d, p + "." + n)).read().strip()
    except OSError: return None
if a[:2] == ["agent", "get"]:
    st = rd(a[2], "state")
    if st is None: print('{"error":{"code":"agent_not_found"}}'); sys.exit(1)
    print(json.dumps({"id": "cli:agent:get", "result": {"agent": {"pane_id": a[2], "agent_status": st}, "type": "agent_info"}}))
elif a[:2] == ["agent", "read"]:
    print(json.dumps({"id": "cli:agent:read", "result": {"text": rd(a[2], "screen") or ""}}))
elif a[:2] in (["agent", "prompt"], ["pane", "run"]):
    with open(os.path.join(d, "typed.log"), "a") as f: f.write(json.dumps({"pane": a[2], "text": a[3]}) + "\n")
elif a[:2] == ["pane", "list"]:
    panes = json.loads(rd("panes", "json") or "[]")
    if a[2:3] == ["--workspace"]: panes = [p for p in panes if p.get("workspace_id") == a[3]]
    print(json.dumps({"id": "cli:pane:list", "result": {"panes": panes}}))
else:
    sys.exit(9)
EOF
chmod +x "$T/bin/herdr"

export PATH="$T/bin:$PATH" FAKE_HERDR_DIR="$T/herdr" FAKE_CCPEER_LOG="$T/ccpeer.log" AGENT_HUB="$T/hub"
unset FAKE_CCPEER_FAIL
HUB="python3 $HERE/hub.py --root $T/hub"
BR() { python3 "$HERE/agent-bridge.py" --root "$T/hub" "$@"; }
typed() { cat "$T/herdr/typed.log" 2>/dev/null; }
ccsent() { cat "$T/ccpeer.log" 2>/dev/null; }
waiting() { ls "$T/hub/inbox/$1" 2>/dev/null | grep -c '\.json$'; }
reset_logs() { rm -f "$T/herdr/typed.log" "$T/herdr/calls.log" "$T/ccpeer.log"; }

$HUB here tester --harness test >/dev/null
for n in a-cc a-auto a-blocked a-dialog a-dry; do $HUB here "$n" >/dev/null; done
echo idle > "$T/herdr/p1.state"; echo "> " > "$T/herdr/p1.screen"
echo blocked > "$T/herdr/p2.state"; echo "> " > "$T/herdr/p2.screen"
echo idle > "$T/herdr/p3.state"; printf 'Do you trust the files in this folder?\n 1. Yes\n Enter to select, Esc to cancel\n' > "$T/herdr/p3.screen"

# ---- 1. ccpeer delivers (native first), herdr untouched
cat > "$T/cc.json" <<EOF
{"herdr_session": "main", "agents": [{"name": "a-cc", "adapter": "auto", "peer": "desk-codex", "pane": "p1"}]}
EOF
reset_logs
$HUB send a-cc "hello native" --from tester >/dev/null
OUT=$(PYTHONPATH="$T/fakepy" FAKE_PEERS=desk-codex BR --config "$T/cc.json" --once); RC=$?
echo "$OUT" | sed 's/^/    /'
[ $RC = 0 ] && echo "$OUT" | grep -q "^DELIVER a-cc <- tester id=.* via=ccpeer peer=desk-codex"; ok $? "ccpeer: delivered natively, one log line"
ccsent | grep -F '[tester via hub] hello native' | grep -F 'send tester' | grep -F -- '--from a-cc' | grep -F '"session_id": "sid-desk-codex"' >/dev/null
ok $? "ccpeer: envelope carries text + reply hint, frame targets the resolved session"
[ -z "$(typed)" ] && ! grep -q '"agent", "get"' "$T/herdr/calls.log" 2>/dev/null; ok $? "ccpeer: herdr never consulted when native works"
[ "$(waiting a-cc)" = 0 ]; ok $? "ccpeer: message consumed from the inbox"
$HUB who | grep -E '^up +a-cc ' >/dev/null; ok $? "presence: bridged name is up in hub who"

# ---- 2. herdr fallback when ccpeer is absent (not importable)
cat > "$T/auto.json" <<EOF
{"herdr_session": "main", "peerbridge": "$T/empty", "agents": [{"name": "a-auto", "adapter": "auto", "peer": "desk-codex", "pane": "p1"}]}
EOF
reset_logs
$HUB send a-auto "$(printf 'line one\nline two \033[2Jx')" --from tester >/dev/null
OUT=$(PYTHONPATH="$T/empty" BR --config "$T/auto.json" --once); RC=$?
echo "$OUT" | sed 's/^/    /'
echo "$OUT" | grep -q "ccpeer unavailable" && echo "$OUT" | grep -q "^DELIVER a-auto <- tester .*via=herdr session=main pane=p1"
ok $? "fallback: ccpeer absent -> herdr typed, log says why"
[ $RC = 0 ] && typed | grep -F '[tester via hub] line one line two' | grep -F -- '--from a-auto' >/dev/null; ok $? "fallback: one line, text + reply hint"
typed | python3 -c "import sys; d=sys.stdin.read(); sys.exit(1 if ('\\\\u001b' in d or '\x1b' in d) else 0)"; ok $? "fallback: ESC stripped before typing"
grep -n '"agent", "get", "p1"' "$T/herdr/calls.log" | head -1 | grep -q '^1:'; ok $? "fallback: pane state read BEFORE typing"

# ---- 2b. ccpeer importable but peer not live -> herdr; ccpeer send error -> herdr
reset_logs
$HUB send a-auto "peer gone" --from tester >/dev/null
sed 's/a-cc/a-auto/' "$T/cc.json" > "$T/auto2.json"
OUT=$(PYTHONPATH="$T/fakepy" FAKE_PEERS=someone-else BR --config "$T/auto2.json" --once)
echo "$OUT" | grep -q "via=herdr .*0 live matches" && typed | grep -qF 'peer gone'; ok $? "fallback: peer not live -> herdr"
reset_logs
$HUB send a-auto "send broke" --from tester >/dev/null
OUT=$(PYTHONPATH="$T/fakepy" FAKE_PEERS=desk-codex FAKE_CCPEER_FAIL=1 BR --config "$T/auto2.json" --once)
echo "$OUT" | grep -q "via=herdr .*ccpeer send failed (ConnectionRefusedError)" && typed | grep -qF 'send broke'; ok $? "fallback: ccpeer send error -> herdr"

# ---- 2c. adapter ccpeer only: no live peer -> held, herdr never used
cat > "$T/cconly.json" <<EOF
{"herdr_session": "main", "agents": [{"name": "a-cc", "adapter": "ccpeer", "peer": "desk-codex", "pane": "p1"}]}
EOF
reset_logs
$HUB send a-cc "native only" --from tester >/dev/null
OUT=$(PYTHONPATH="$T/fakepy" FAKE_PEERS= BR --config "$T/cconly.json" --once); RC=$?
[ $RC = 1 ] && echo "$OUT" | grep -q "^HOLD a-cc" && [ -z "$(typed)" ] && [ "$(waiting a-cc)" = 1 ]; ok $? "ccpeer-only: no peer -> held in inbox, never typed"

# ---- 3. blocked pane is NOT typed into; message stays; sender told once; later delivered
cat > "$T/blk.json" <<EOF
{"herdr_session": "main", "peerbridge": "$T/empty", "agents": [{"name": "a-blocked", "adapter": "herdr", "pane": "p2"},
                                                               {"name": "a-dialog", "adapter": "herdr", "pane": "p3"}]}
EOF
reset_logs
$HUB send a-blocked "do not type me" --from tester >/dev/null
$HUB send a-dialog "nor me" --from tester >/dev/null
OUT=$(PYTHONPATH="$T/empty" BR --config "$T/blk.json" --once); RC=$?
echo "$OUT" | sed 's/^/    /'
[ $RC = 1 ] && [ -z "$(typed)" ]; ok $? "blocked: nothing typed (exit 1 = held)"
! grep -q '"prompt"' "$T/herdr/calls.log"; ok $? "blocked: no prompt/Enter call ever reached herdr"
echo "$OUT" | grep -q "^HOLD a-blocked .*state=blocked" && [ "$(waiting a-blocked)" = 1 ]; ok $? "blocked: state=blocked held, message still in inbox"
echo "$OUT" | grep -q "^HOLD a-dialog .*state=idle but dialog on screen" && [ "$(waiting a-dialog)" = 1 ]; ok $? "blocked: herdr says idle but a dialog is up -> held"
$HUB read tester | grep -F 'NOT DELIVERED a-blocked' >/dev/null; ok $? "blocked: sender gets a NOT DELIVERED notice"
echo idle > "$T/herdr/p2.state"
OUT=$(PYTHONPATH="$T/empty" BR --config "$T/blk.json" --once)
typed | grep -qF 'do not type me' && ! typed | grep -qF 'nor me' && [ "$(waiting a-blocked)" = 0 ]; ok $? "blocked: once the pane is idle the held message goes through (dialog pane still held)"

# ---- 4. --dry-run sends nothing, claims nothing, writes no presence
cat > "$T/dry.json" <<EOF
{"herdr_session": "main", "agents": [{"name": "a-dry", "adapter": "auto", "peer": "desk-codex", "pane": "p1"},
                                     {"name": "a-dry2", "adapter": "herdr", "pane": "p1"}]}
EOF
reset_logs
$HUB send a-dry "dry one" --from tester >/dev/null
mkdir -p "$T/hub/inbox/a-dry2"; python3 -c "
import importlib.util,sys; s=importlib.util.spec_from_file_location('h', sys.argv[1]); h=importlib.util.module_from_spec(s); s.loader.exec_module(h)
h.Hub(sys.argv[2]).deliver('a-dry2','tester','dry two')" "$HERE/hub.py" "$T/hub"
OUT=$(PYTHONPATH="$T/fakepy" FAKE_PEERS=desk-codex BR --config "$T/dry.json" --once --dry-run); RC=$?
echo "$OUT" | sed 's/^/    /'
echo "$OUT" | grep -q "^DRY a-dry .*via=ccpeer .*not sent" && echo "$OUT" | grep -q "^DRY a-dry2 .*via=herdr .*not typed"; ok $? "dry-run: reports the route it would take"
[ -z "$(ccsent)" ] && [ -z "$(typed)" ] && ! grep -q '"prompt"' "$T/herdr/calls.log" 2>/dev/null; ok $? "dry-run: nothing sent, nothing typed"
[ "$(waiting a-dry)" = 1 ] && [ "$(waiting a-dry2)" = 1 ] && [ ! -e "$T/hub/agents/a-dry2.json" ]; ok $? "dry-run: messages left unclaimed, no presence written"

# ---- 4b. agent-bridge-start.sh --dry-run against the fake herdr + a fake kit (ccpeer, pb, flock)
mkdir -p "$T/kit/codex-bridge/peerbridge" "$T/home"
cp "$T/fakepy/ccpeer.py" "$T/kit/codex-bridge/peerbridge/ccpeer.py"
for c in pb flock; do printf '#!/bin/sh\nexit 0\n' > "$T/bin/$c"; chmod +x "$T/bin/$c"; done
ABS() { HOME="$T/home" AGENT_KIT="$T/kit" BRIDGE_DIR="$T/abr" FAKE_PEERS=claude bash "$HERE/agent-bridge-start.sh" --prefix t --wait 0 --dry-run "$@" 2>&1; }
echo '[{"pane_id": "p1", "label": "claude", "workspace_id": "w1"}, {"pane_id": "p9", "label": "shell", "workspace_id": "w2"}]' > "$T/herdr/panes.json"
OUT=$(ABS); RC=$?
echo "$OUT" | sed 's/^/    /'
[ $RC = 0 ] && echo "$OUT" | grep -q "^routes: --map t-claude=peer:claude$"; ok $? "start: one claude pane -> peer route"
echo '[{"pane_id": "p5", "label": "claude", "workspace_id": "w2"}, {"pane_id": "p1", "label": "claude", "workspace_id": "w1"}]' > "$T/herdr/panes.json"
OUT=$(ABS); RC=$?
echo "$OUT" | sed 's/^/    /'
[ $RC = 0 ] && echo "$OUT" | grep -q "^routes: --map t-claude=peer:claude$"; ok $? "start: claude label on 2 panes -> route kept (it reaches the ccpeer session, not a pane)"
grep -q "pane label claude: 2 panes p5 p1" "$T/abr/agent-bridge.log"; ok $? "start: ambiguity logged with the pane ids"
OUT=$(ABS --workspace w1); RC=$?
[ $RC = 0 ] && echo "$OUT" | grep -q "^routes: --map t-claude=peer:claude$" && grep -q '"--workspace", "w1"' "$T/herdr/calls.log"; ok $? "start: --workspace scopes the pane lookup"
echo $$ > "$T/abr/agent-bridge.pid"   # a live process that is not the bridge (a reused pid)
OUT=$(ABS --workspace w1)
echo "$OUT" | grep -q "^live bridge: none$"; ok $? "start: a reused pid is not taken for the live bridge"

# ---- 5. source hygiene
python3 -c "import sys; sys.exit(0 if all(b < 128 for b in open(sys.argv[1],'rb').read()) else 1)" "$HERE/agent-bridge.py"; ok $? "source: ASCII only"
! grep -n 'shell=True\|os.system\|/Users/' "$HERE/agent-bridge.py" >/dev/null; ok $? "source: no shell=True, os.system or private paths"
python3 "$HERE/agent-bridge.py" --config "$T/nope.json" >/dev/null 2>&1; [ $? = 2 ]; ok $? "config: missing file -> exit 2"
echo '{"agents":[{"name":"x","adapter":"herdr"}]}' > "$T/bad.json"
python3 "$HERE/agent-bridge.py" --config "$T/bad.json" 2>&1 | grep -q 'needs "session"'; ok $? "config: herdr without session/pane refused"

echo "$pass passed, $fail failed"; [ "$fail" = 0 ]
