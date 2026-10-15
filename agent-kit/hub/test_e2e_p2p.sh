#!/bin/sh
# End-to-end test of hub.py uplink against the REAL p2p tunnel CLI, fully offline:
# two throwaway P2P_HOMEs on this machine ("remote" listener + "local" joiner) meet through
# p2p's --rendezvous-dir loopback carrier (no public relay, no internet), then the hub routes
# messages both ways and answers WHO?. Every daemon it starts is stopped at the end.
#
#   P2P="node /path/to/p2p/bin/p2p.js" sh test_e2e_p2p.sh      (default: p2p on PATH)
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
P2P=${P2P:-p2p}
T=$(mktemp -d "${TMPDIR:-/tmp}/hub-e2e.XXXXXX")
R="$T/remote" L="$T/local" RV="$T/rendezvous" HUBDIR="$T/hub"
mkdir -p "$R" "$L" "$RV"
pass=0 fail=0
ok() { if [ "$1" = 0 ]; then pass=$((pass+1)); echo "PASS $2"; else fail=$((fail+1)); echo "FAIL $2"; fi; }
rp2p() { P2P_HOME="$R" P2P_RENDEZVOUS_DIR="$RV" $P2P tunnel "$@"; }
lp2p() { P2P_HOME="$L" P2P_RENDEZVOUS_DIR="$RV" $P2P tunnel "$@"; }
cleanup() {
  [ -n "${UPID:-}" ] && kill "$UPID" 2>/dev/null
  rp2p stop --name remote >/dev/null 2>&1; [ -n "${KEY:-}" ] && lp2p stop --name "join-$KEY" >/dev/null 2>&1
  sleep 1; rm -rf "$T"
}
trap cleanup EXIT INT TERM

KEY=$(rp2p listen --name remote --profile remote-id 2>&1 | sed -n 's/.*tunnel join \([0-9A-Z]\{26\}\).*/\1/p' | head -1)
[ -n "$KEY" ]; ok $? "listener started (offline rendezvous)"
lp2p join "$KEY" --name "join-$KEY" --profile "join-$KEY" --say "hello from local" --connect-timeout 20 >/dev/null 2>&1
ok $? "joiner connected"

H="python3 $HERE/hub.py --root $HUBDIR"
$H here wsl-codex --harness codex >/dev/null && $H here win-claude --harness claude >/dev/null
P2P_HOME="$L" P2P_RENDEZVOUS_DIR="$RV" $H uplink --session "join-$KEY" --as shai --p2p "$P2P" --p2p-home "$L" --poll 1 > "$T/uplink.log" 2>&1 &
UPID=$!

wait_for() {  # wait_for <seconds> <command...>
  n=$1; shift; i=0
  while [ $i -lt $n ]; do "$@" >/dev/null 2>&1 && return 0; sleep 1; i=$((i+1)); done; return 1
}
remote_has() { rp2p recv --name remote --all 2>/dev/null | grep -F -- "$1"; }

wait_for 30 remote_has "PRESENCE"; ok $? "remote side sees PRESENCE roster"
remote_has "wsl-codex(" >/dev/null && remote_has "win-claude(" >/dev/null; ok $? "roster names both local agents"

rp2p send --name remote "@wsl-codex please run the tests" --wait 20 >/dev/null 2>&1
wait_for 20 sh -c "$H read wsl-codex | grep -F 'please run the tests'"; ok $? "remote @wsl-codex -> local agent"

$H send shai "ERROR npm test | 3 failing" --from wsl-codex >/dev/null
wait_for 30 remote_has "[wsl-codex] ERROR npm test | 3 failing"; ok $? "local agent -> remote, tagged with sender"

rp2p send --name remote "WHO?" --wait 20 >/dev/null 2>&1
wait_for 30 sh -c "[ \$(P2P_HOME='$R' $P2P tunnel recv --name remote --all 2>/dev/null | grep -c PRESENCE) -ge 2 ]"; ok $? "WHO? answered"

$H who | grep -E '^up +shai ' >/dev/null; ok $? "roster shows the remote side as up"
$H read win-claude | grep -F "WHO?" >/dev/null; [ $? != 0 ]; ok $? "WHO? not delivered to agents"

echo "--- uplink log"; sed 's/^/  /' "$T/uplink.log"
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
