#!/bin/sh
# Python <-> PowerShell interop on one hub folder: what a WSL agent (hub.py) and a Windows agent
# (hub.ps1) do on a real PC, run here on one machine. Needs python3 and pwsh (PowerShell 7).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/hub-interop.XXXXXX"); trap 'rm -rf "$T"' EXIT
PY="python3 $HERE/hub.py --root $T"
PS() { pwsh -NoProfile -File "$HERE/hub.ps1" "$@" -Root "$T"; }
pass=0 fail=0
ok() { if [ "$1" = 0 ]; then pass=$((pass+1)); echo "PASS $2"; else fail=$((fail+1)); echo "FAIL $2"; fi; }

PS here win-claude -Harness claude >/dev/null; ok $? "ps: here"
$PY here wsl-codex --harness codex >/dev/null; ok $? "py: here"
PS who | grep -E '^up +wsl-codex ' >/dev/null; ok $? "ps sees the python agent"
$PY who | grep -E '^up +win-claude ' >/dev/null; ok $? "py sees the powershell agent"

$PY send win-claude "from wsl: שלום 👋" --from wsl-codex >/dev/null
PS read win-claude | grep -F "from=wsl-codex" | grep -F "שלום 👋" >/dev/null; ok $? "py -> ps message (Hebrew + emoji)"
PS send wsl-codex "from windows: line1" -From win-claude >/dev/null
$PY read wsl-codex | grep -F "from=win-claude" | grep -F "line1" >/dev/null; ok $? "ps -> py message"
printf 'first\nsecond\nthird\n' > "$T/multi.txt"
PS send wsl-codex -File "$T/multi.txt" -From win-claude >/dev/null
$PY read wsl-codex | grep -F "+2 more lines" >/dev/null; ok $? "ps -File multi-line -> py"
PS send all "hi all" -From win-claude >/dev/null
$PY read wsl-codex | grep -F "hi all" >/dev/null; ok $? "ps broadcast reaches py"
PS send ghost "x" -From win-claude >/dev/null 2>&1; [ $? != 0 ]; ok $? "ps refuses unknown target"
PS ear win-claude -Once | grep -E '^up +wsl-codex ' >/dev/null; ok $? "ps ear -Once prints roster"
PS bye win-claude >/dev/null; $PY who | grep -F win-claude >/dev/null; [ $? != 0 ]; ok $? "ps bye removes presence"

# guards shared by both twins (docs/MESH-THREATS.md #3, #7, #8)
$PY here esc-agent --harness "$(printf '\033[2J\033]0;x\007codex')" --note "$(printf 'n\342\200\256ote')" >/dev/null
PS who | grep -F esc-agent | LC_ALL=C grep -q "$(printf '[\033\007]')"; [ $? != 0 ]; ok $? "ps who prints no ESC/BEL from fields python wrote"
$PY send esc-agent "$(printf 'ok\342\200\213\363\240\201\211\357\273\277')" --from wsl-codex >/dev/null
PS read esc-agent | grep -F ':: ok  (' | grep -F 'hidden/control chars removed' >/dev/null; ok $? "ps read strips zero-width, BOM and TAG chars and says so"
python3 -c "import json,sys,time; json.dump({'name':'laptop','remote':True,'beat':time.time(),'machine':'link','harness':'link','link':'peer-changed'}, open(sys.argv[1]+'/agents/laptop.json','w'))" "$T"
PS who | grep -E '^peer-changed +laptop ' >/dev/null; ok $? "ps who shows a held link as peer-changed"
PS here laptop >/dev/null 2>&1; [ $? != 0 ]; ok $? "ps refuses a link's name for a local agent"
$PY here laptop >/dev/null 2>&1; [ $? != 0 ]; ok $? "py refuses a link's name for a local agent"
echo "$pass passed, $fail failed"; [ "$fail" = 0 ]
