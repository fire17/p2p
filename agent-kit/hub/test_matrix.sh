#!/bin/sh
# hub.py matrix end to end: background responder agents (each claims its own inbox and answers
# "MATRIX PING <tok> ..." with "MATRIX PONG <tok>" through `hub.py send`), then the table is asserted.
# Needs python3 only. Run: sh hub/test_matrix.sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/hub-matrix.XXXXXX")
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT INT TERM
HUB="$HERE/hub.py"; export PYTHONDONTWRITEBYTECODE=1   # the responders import hub.py: leave no __pycache__
PY() { python3 "$HUB" --root "$T" "$@"; }
pass=0 fail=0
ok() { if [ "$1" = 0 ]; then pass=$((pass+1)); echo "PASS $2"; else fail=$((fail+1)); echo "FAIL $2"; fi; }

# responder: stays present, claims its inbox, answers PINGs only (never PONGs), replies via the CLI
cat > "$T/responder.py" <<'EOF'
import re, subprocess, sys, time
hub_py, root, me = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, hub_py.rsplit("/", 1)[0])
import hub as H
h = H.Hub(root); last = 0.0
while True:
    if time.time() - last > 5: h.heartbeat(me, "sim", "matrix responder"); last = time.time()
    for m, _ in h.claim(me):
        mo = re.match(r"MATRIX PING ([0-9a-f]{12}) from ", str(m.get("text", "")))
        if mo:
            subprocess.run([sys.executable, hub_py, "--root", root, "send", str(m["from"]),
                            "MATRIX PONG " + mo.group(1), "--from", me], stdout=subprocess.DEVNULL, check=False)
    time.sleep(0.1)
EOF
for n in sim-a sim-b sim-c; do
  python3 "$T/responder.py" "$HUB" "$T" "$n" & PIDS="$PIDS $!"
done
PY here sim-quiet --harness sim >/dev/null           # present but never answers
i=0; while [ $i -lt 50 ]; do
  [ "$(PY who | grep -cE '^up +sim-[abc] ')" = 3 ] && break; i=$((i+1)); python3 -c 'import time; time.sleep(0.1)'
done
ok $([ $i -lt 50 ]; echo $?) "three responders up"

# 1) throwaway sender, all answer
PY matrix --names sim-a,sim-b,sim-c --timeout 20 --poll 0.2 > "$T/o1"; rc=$?
cat "$T/o1"
ok $rc "matrix: exit 0 when all pong"
grep -qE '^name +\| sent +\| pong \| seconds$' "$T/o1"; ok $? "matrix: table header"
for n in sim-a sim-b sim-c; do
  grep -qE "^$n +\| yes +\| yes +\| [0-9]+\.[0-9]$" "$T/o1"; ok $? "matrix: row $n sent+ponged with seconds"
done
grep -qF "MATRIX 3/3 ponged" "$T/o1"; ok $? "matrix: summary 3/3"
PY who --all | grep -q '^.* matrix-'; [ $? != 0 ]; ok $? "matrix: throwaway sender left the roster"

# 2) silent + unknown target: nonzero exit, rows say why
PY matrix --names sim-a,sim-quiet,ghost --timeout 2 --poll 0.2 > "$T/o2"; rc=$?
cat "$T/o2"
[ $rc = 1 ]; ok $? "matrix: exit 1 when someone is silent"
grep -qE '^sim-a +\| yes +\| yes ' "$T/o2"; ok $? "matrix: responder still pongs"
grep -qE '^sim-quiet +\| yes +\| NO +\| -$' "$T/o2"; ok $? "matrix: silent agent sent, no pong"
grep -qE '^ghost +\| no +\| NO +\| - +\(never here\)$' "$T/o2"; ok $? "matrix: unknown name not sent"
grep -qF "MATRIX 1/3 ponged  FAIL" "$T/o2"; ok $? "matrix: summary 1/3 FAIL"

# 3) named sender that is a live agent: its mail is peeked, not stolen
PY matrix --names sim-b,sim-c --from sim-a --timeout 20 --poll 0.2 > "$T/o3"; rc=$?
cat "$T/o3"
ok $rc "matrix --from sim-a: exit 0"
PY who | grep -qE '^up +sim-a '; ok $? "matrix --from: real sender not removed"

# 4) all pairs, JSON
PY matrix --names sim-a,sim-b,sim-c --pairs --timeout 20 --poll 0.2 > "$T/o4"; rc=$?
cat "$T/o4"
ok $rc "matrix --pairs: exit 0"
[ "$(grep -cE '^sim-[abc]->sim-[abc] +\| yes +\| yes ' "$T/o4")" = 6 ]; ok $? "matrix --pairs: 6 ordered pairs ponged"
grep -qE '^sim-(a->a|b->b|c->c) ' "$T/o4"; [ $? != 0 ]; ok $? "matrix --pairs: no self pairs"
PY matrix --names sim-a,sim-b --pairs --json --timeout 20 --poll 0.2 > "$T/o5"; rc=$?
python3 -c "import json,sys; j=json.load(open(sys.argv[1])); sys.exit(0 if j['ok'] and len(j['rows'])==2 and all(r['pong'] for r in j['rows']) else 1)" "$T/o5"
ok $? "matrix --pairs --json: ok and two rows"
PY matrix --names sim-a,sim-quiet --pairs --timeout 2 --poll 0.2 > "$T/o6"; [ $? = 1 ]; ok $? "matrix --pairs: silent agent fails the run"
PY matrix --names sim-a,ghost --pairs --timeout 2 >/dev/null 2>&1; [ $? = 2 ]; ok $? "matrix --pairs: refuses a name not on this hub"

echo "$pass passed, $fail failed"; [ "$fail" = 0 ]
