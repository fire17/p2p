<#
tests.ps1 - admin-runner checks WITHOUT elevation: request/approve/runner against a temp root (-TestRoot -NoElevate).

  powershell -NoProfile -ExecutionPolicy Bypass -File tests.ps1      exit 0 only if every check passes
#>
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
. (Join-Path $here 'common.ps1')
$T = Join-Path ([IO.Path]::GetTempPath()) ('aa-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$d = AA-Dirs $T
foreach ($k in 'root', 'queue', 'approved', 'done', 'results') { [void][IO.Directory]::CreateDirectory($d[$k]) }
$script:fails = 0; $script:n = 0
function Check([bool]$ok, [string]$what) { $script:n++; if ($ok) { "PASS $what" } else { "FAIL $what"; $script:fails++ } }
function Req([string]$cmd) { $o = & (Join-Path $here 'request.ps1') -Command $cmd -Reason 'test' -Root $T; ($o[0] -split '\s+')[1] }
function Sha8Of([string]$id) { (AA-Sha256 (AA-ReadJson (Join-Path $d.queue "$id.json")).command).Substring(0, 8) }
function Approve([string]$id, [string]$sha8) { & (Join-Path $here 'approve.ps1') -Id $id -Sha8 $sha8 -By 'TEST-MSG' -Root $T -NoStart | Out-Null }
function Runner { & (Join-Path $here 'runner.ps1') -TestRoot $T -NoElevate }
function WriteApproval([string]$id, [string]$sha8, [DateTime]$at) {
  AA-WriteJson (Join-Path $d.approved "$id.json") ([ordered]@{ id = $id; sha8 = $sha8; by = 'TEST-MSG'; at = $at.ToUniversalTime().ToString('o') })
}
$runs = Join-Path $T 'runs.txt'
$probe = "Add-Content -LiteralPath '$runs' -Value x; Write-Output 'hello-ok'; exit 3"

try {
  # 1. approved + matching -> runs once, result + audit written, moved to done
  $id1 = Req $probe; Approve $id1 (Sha8Of $id1); $o = Runner
  $r = AA-ReadJson (Join-Path $d.results "$id1.json")
  Check ($r.status -eq 'ok' -and $r.exit -eq 3 -and $r.stdout -match 'hello-ok') "approved + matching: ran, status ok, exit 3, stdout captured"
  Check ((Get-Content $runs).Count -eq 1) "approved + matching: the command ran exactly once"
  Check ((Test-Path (Join-Path $d.done "$id1.request.json")) -and -not (Test-Path (Join-Path $d.approved "$id1.json"))) "approved + matching: request + approval moved to done\"
  # 2. replay: a fresh approval for an id already handled -> refused, not run again
  WriteApproval $id1 ([string]$r.sha8) (Get-Date); $o = Runner
  Check ((Get-Content $runs).Count -eq 1 -and ($o -match 'already handled')) "replay of a handled id: refused, not run again"
  # 3. wrong sha8 -> approve.ps1 refuses; a hand-written wrong approval is refused by the runner
  $id3 = Req $probe; $bad = 'deadbeef'
  $threw = $false; try { Approve $id3 $bad } catch { $threw = $true }
  Check $threw "approve.ps1 refuses a sha8 that does not match the request"
  WriteApproval $id3 $bad (Get-Date); $o = Runner
  Check ((Get-Content $runs).Count -eq 1 -and ($o -match "REFUSED $id3 : sha8")) "runner refuses a wrong sha8 (not run)"
  # 4. stale approval (11 min old) -> refused
  $id4 = Req $probe; WriteApproval $id4 (Sha8Of $id4) ((Get-Date).AddMinutes(-11)); $o = Runner
  Check ((Get-Content $runs).Count -eq 1 -and ($o -match "REFUSED $id4 : approval stale")) "stale approval (>10 min): refused"
  # 5. command over the limit: request.ps1 refuses; a hand-written long request is refused by the runner
  $long = 'Write-Output ' + ('a' * 2001)
  $threw = $false; try { Req $long | Out-Null } catch { $threw = $true }
  Check $threw "request.ps1 refuses a command over 2000 chars"
  $id5 = AA-NewId
  AA-WriteJson (Join-Path $d.queue "$id5.json") ([ordered]@{ id = $id5; command = $long; reason = 'test'; created = (Get-Date).ToUniversalTime().ToString('o'); sha256 = (AA-Sha256 $long) })
  WriteApproval $id5 (AA-Sha256 $long).Substring(0, 8) (Get-Date); $o = Runner
  Check ($o -match "REFUSED $id5 : command empty or over") "runner refuses a queued command over 2000 chars"
  # 6. command changed AFTER approval (queue is user-writable) -> sha8 mismatch, refused
  $id6 = Req $probe; Approve $id6 (Sha8Of $id6)
  $q = AA-ReadJson (Join-Path $d.queue "$id6.json"); $q.command = "Write-Output 'swapped'"
  AA-WriteJson (Join-Path $d.queue "$id6.json") $q; $o = Runner
  Check ((Get-Content $runs).Count -eq 1 -and ($o -match "REFUSED $id6 : sha8")) "command swapped after approval: refused (sha8 recomputed at run time)"
  # 7. audit: one line per decision, with RAN and REFUSED entries
  $a = @(Get-Content $d.audit)
  Check (($a | ? { $_ -match "id=$id1 .* RAN status=ok exit=3" }).Count -eq 1 -and ($a | ? { $_ -match 'REFUSED' }).Count -ge 5) "audit.log: 1 RAN line for the run, a REFUSED line per refusal ($($a.Count) lines)"
  Check (-not @(Get-ChildItem $d.approved -File).Count) "approved\ is empty after the runner pass (nothing left to retry)"
} finally {
  Remove-Item -LiteralPath $T -Recurse -Force -ErrorAction SilentlyContinue
}
"$($script:n - $script:fails)/$($script:n) passed"
if ($script:fails) { exit 1 }
