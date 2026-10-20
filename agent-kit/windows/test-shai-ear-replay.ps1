# test-shai-ear-replay.ps1 - fixture for shai-ear.ps1 Drain-OldDirs (LAP-SYM item 5, Shai f777d780 / 32d88cde).
# Scenario: the ear is down, a row lands in the session dir, then a re-join switches current.json to a new dir.
# On re-arm the ear must print that row once (late=<old dir>), never the row it had already printed, and move
# the old dir's cursor to the end; a second arm prints nothing again. Touches no real tunnel: fake P2P_HOME,
# fake p2p.cmd, temp state dir.
#   powershell -NoProfile -ExecutionPolicy Bypass -File test-shai-ear-replay.ps1 [-Ear <path>]
# Exit 0 = all checks pass.
param([string]$Ear = (Join-Path $PSScriptRoot '..\windows\shai-ear.ps1'))
$ErrorActionPreference = 'Stop'
$Root = Join-Path ([IO.Path]::GetTempPath()) ('ear-replay-' + [Guid]::NewGuid().ToString('N'))
$Name = 'join-0TESTEARREPLAY000000000000'
$Old = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; $New = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
$sess = Join-Path $Root "p2p\tunnel\$Name"
$Utf8 = New-Object System.Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force (Join-Path $sess $Old), (Join-Path $sess $New), (Join-Path $Root 'state') | Out-Null

$rowA = '{"v":1,"from":"0SHAI","id":"aaaa000000000001","t":"2026-10-20T00:00:00Z","text":"ROW-A already printed before the ear went down"}'
$rowB = '{"v":1,"from":"0SHAI","id":"bbbb000000000002","t":"2026-10-20T00:01:00Z","text":"ROW-B landed while the ear was down"}'
[IO.File]::WriteAllText((Join-Path $sess "$Old\inbox.jsonl"), "$rowA`n$rowB`n", $Utf8)
[IO.File]::WriteAllText((Join-Path $sess "$Old\cursor.json"), ('{"offset":' + ($Utf8.GetByteCount($rowA) + 1) + '}'), $Utf8)
[IO.File]::WriteAllText((Join-Path $sess "$New\inbox.jsonl"), '', $Utf8)
[IO.File]::WriteAllText((Join-Path $sess 'current.json'), ('{"id":"' + $New + '"}'), $Utf8)
Set-Content -LiteralPath (Join-Path $Root 'state\seen.txt') -Value 'aaaa000000000001' -Encoding ASCII
# fake p2p: recv returns no rows, status says connected; exit 0
$fake = Join-Path $Root 'p2p.cmd'
Set-Content -LiteralPath $fake -Encoding ASCII -Value "@echo off`r`nif /I `"%2`"==`"status`" echo {`"connected`":true,`"sent`":0,`"recv`":0}`r`nexit /b 0"

function Run-Ear {
  $env:P2P_HOME = Join-Path $Root 'p2p'
  try {
    $out = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Ear -Name $Name -Wait 1 -MaxIterations 1 -P2P $fake -StateDir (Join-Path $Root 'state') 2>&1 | Out-String
  } finally { Remove-Item Env:P2P_HOME -ErrorAction SilentlyContinue }
  $out
}

$fail = 0
function Check([bool]$ok, [string]$what) { if ($ok) { "PASS $what" } else { "FAIL $what"; $script:fail++ } }
try {
  $o1 = Run-Ear
  Check ($o1 -match 'ROW-B landed' -and $o1 -match 'late=aaaaaaaa') 'run 1: row that landed while the ear was down prints, tagged late=<old dir>'
  Check (-not ($o1 -match 'ROW-A')) 'run 1: the row printed before the outage does not print again'
  Check ($o1 -match 'REPLAY old session dir aaaaaaaa: 1 row') 'run 1: REPLAY line reports 1 row'
  $cur = ([IO.File]::ReadAllText((Join-Path $sess "$Old\cursor.json")) | ConvertFrom-Json).offset
  $len = (Get-Item (Join-Path $sess "$Old\inbox.jsonl")).Length
  Check ($cur -eq $len) "run 1: old dir cursor moved to the end ($cur of $len)"
  $o2 = Run-Ear
  Check (-not ($o2 -match 'ROW-B') -and -not ($o2 -match 'REPLAY old session dir')) 'run 2: nothing replays twice'
  if ($fail) { "--- run 1 output:`n$o1`n--- run 2 output:`n$o2" }
} finally {
  Remove-Item -Recurse -Force $Root -ErrorAction SilentlyContinue
  "RESULT ear=$Ear -> " + $(if ($fail -eq 0) { 'ALL PASS' } else { "$fail FAILED" })
}
exit $fail
