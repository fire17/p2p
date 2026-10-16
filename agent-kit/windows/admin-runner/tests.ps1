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

  # ================= SIGNED MODE: <T>\bin\approver.pub.xml present -> every approval needs a valid signature
  [void][IO.Directory]::CreateDirectory((Join-Path $T 'bin'))
  $key = New-Object Security.Cryptography.RSACryptoServiceProvider(3072)
  $other = New-Object Security.Cryptography.RSACryptoServiceProvider(3072)
  [IO.File]::WriteAllText((Join-Path $T 'bin\approver.pub.xml'), $key.ToXmlString($false))
  function NowAt { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
  function SignedJson([string]$id, [string]$sha, [string]$by, [string]$at, $signer) {
    $sig = [Convert]::ToBase64String($signer.SignData([Text.Encoding]::UTF8.GetBytes((AA-SignedPayload $id $sha $by $at)), 'SHA256'))
    ([ordered]@{ id = $id; sha8 = $sha.Substring(0, 8); sha256 = $sha; by = $by; at = $at; sig = $sig } | ConvertTo-Json -Compress)
  }
  function ShaOf([string]$id) { AA-Sha256 (AA-ReadJson (Join-Path $d.queue "$id.json")).command }
  function ApproveSigned([string]$json) { & (Join-Path $here 'approve.ps1') -ApprovalJson $json -Root $T -NoStart | Out-Null }
  function PutApproval([string]$id, [string]$json) { [IO.File]::WriteAllText((Join-Path $d.approved "$id.json"), $json) }
  $base = (Get-Content $runs).Count

  # s1. valid signature (via approve.ps1 -ApprovalJson) -> runs exactly once
  $s1 = Req $probe; $j = SignedJson $s1 (ShaOf $s1) 'SIG-MSG-1' (NowAt) $key; ApproveSigned $j
  Check ([IO.File]::ReadAllText((Join-Path $d.approved "$s1.json")) -eq $j) "signed: approve.ps1 -ApprovalJson writes the approval verbatim"
  $o = Runner
  Check ((Get-Content $runs).Count -eq $base + 1 -and ($o -match "RAN $s1 status=ok exit=3")) "signed: valid signature runs exactly once"
  # s2. tampered command after approval -> sha256 mismatch
  $s2 = Req $probe; PutApproval $s2 (SignedJson $s2 (ShaOf $s2) 'SIG-MSG-2' (NowAt) $key)
  $q = AA-ReadJson (Join-Path $d.queue "$s2.json"); $q.command = "Write-Output 'swapped'"; AA-WriteJson (Join-Path $d.queue "$s2.json") $q
  $o = Runner; Check ((Get-Content $runs).Count -eq $base + 1 -and ($o -match "REFUSED $s2 : sha256 does not match")) "signed: command swapped after approval refused"
  # s3. tampered by / at / sha256 in the approval JSON (signature no longer covers it)
  $s3 = Req $probe; $sh = ShaOf $s3; $at = NowAt
  $ok = SignedJson $s3 $sh 'SIG-MSG-3' $at $key | ConvertFrom-Json
  $t1 = $ok.PSObject.Copy(); $t1.by = 'SIG-MSG-EVIL'; PutApproval $s3 ($t1 | ConvertTo-Json -Compress)
  $o = Runner; Check ($o -match "REFUSED $s3 : signature invalid") "signed: tampered 'by' refused (signature invalid)"
  $s4 = Req $probe; $ok = SignedJson $s4 (ShaOf $s4) 'SIG-MSG-4' (NowAt) $key | ConvertFrom-Json
  $ok.at = (Get-Date).ToUniversalTime().AddSeconds(-30).ToString('yyyy-MM-ddTHH:mm:ssZ'); PutApproval $s4 ($ok | ConvertTo-Json -Compress)
  $o = Runner; Check ($o -match "REFUSED $s4 : signature invalid") "signed: tampered 'at' refused (signature invalid)"
  $s5 = Req $probe; $ok = SignedJson $s5 (ShaOf $s5) 'SIG-MSG-5' (NowAt) $key | ConvertFrom-Json
  $ok.sha256 = ('0' * 64); PutApproval $s5 ($ok | ConvertTo-Json -Compress)
  $o = Runner; Check ($o -match "REFUSED $s5 : sha256 does not match") "signed: tampered sha256 in the approval refused"
  # s6. missing signature / unsigned-style approval while the public key is present
  $s6 = Req $probe; $ok = SignedJson $s6 (ShaOf $s6) 'SIG-MSG-6' (NowAt) $key | ConvertFrom-Json
  $ok.sig = ''; PutApproval $s6 ($ok | ConvertTo-Json -Compress)
  $o = Runner; Check ($o -match "REFUSED $s6 : signed mode: approval has no signature") "signed: missing signature refused"
  $s7 = Req $probe; WriteApproval $s7 ((ShaOf $s7).Substring(0, 8)) (Get-Date)
  $o = Runner; Check ($o -match "REFUSED $s7 : signed mode: approval has no full sha256") "signed: old unsigned approval (sha8 only) refused, no fallback"
  $threw = $false; try { Approve $s7 '00000000' } catch { $threw = $_.Exception.Message -match 'requires signed approvals' }
  Check $threw "signed: approve.ps1 -Sha8/-By path refuses on a signed install"
  # s8. signed with the wrong key
  $s8 = Req $probe; PutApproval $s8 (SignedJson $s8 (ShaOf $s8) 'SIG-MSG-8' (NowAt) $other)
  $o = Runner; Check ($o -match "REFUSED $s8 : signature invalid") "signed: signature from another key refused"
  Check ((Get-Content $runs).Count -eq $base + 1) "signed: only the one valid approval ever ran"
  # s9. approve.ps1 -ApprovalJson rejects a JSON whose sha256 does not match the queued request
  $s9 = Req $probe; $bad = SignedJson $s9 ('1' * 64) 'SIG-MSG-9' (NowAt) $key
  $threw = $false; try { ApproveSigned $bad } catch { $threw = $_.Exception.Message -match 'sha256 does not match' }
  Check $threw "signed: approve.ps1 rejects an approval whose sha256 differs from the request"
  # s10. cross-platform vector (python cryptography, RSA-3072 PKCS1v15 SHA256)
  $v = Get-Content -LiteralPath (Join-Path $here 'test-vector.json') -Raw | ConvertFrom-Json
  Check ((AA-Sha256 $v.command) -eq $v.sha256) "vector: sha256(command) matches"
  Check ((AA-SignedPayload '20261016-234500-a1b2c3' $v.sha256 '3A00000001' '2026-10-16T20:45:00Z') -eq $v.payload) "vector: payload layout agent-admin-v1|id|sha256|by|at matches"
  Check (AA-VerifySig $v.pub_xml $v.payload $v.sig) "vector: VerifyData(payload) = True (cross-platform signature)"
  Check (-not (AA-VerifySig $v.pub_xml $v.bad_payload $v.sig)) "vector: VerifyData(payload+'x') = False"
  $key.Dispose(); $other.Dispose()
} finally {
  Remove-Item -LiteralPath $T -Recurse -Force -ErrorAction SilentlyContinue
}
"$($script:n - $script:fails)/$($script:n) passed"
if ($script:fails) { exit 1 }
