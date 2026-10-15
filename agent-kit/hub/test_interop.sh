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
echo "$pass passed, $fail failed"; [ "$fail" = 0 ]
