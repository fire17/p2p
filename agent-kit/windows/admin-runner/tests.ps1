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
  # 8. an approval written WHILE a command runs (a 2nd agent) is handled by the same pass, not left to go stale
  $c0 = (Get-Content $runs).Count
  $b8 = Req $probe
  $j8 = [ordered]@{ id = $b8; sha8 = (Sha8Of $b8); by = 'TEST-MSG'; at = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json -Compress
  $a8 = Req ("[IO.File]::WriteAllText('" + (Join-Path $d.approved "$b8.json") + "', '" + $j8 + "'); " + $probe)
  Approve $a8 (Sha8Of $a8); $o = Runner
  Check ((Get-Content $runs).Count -eq $c0 + 2 -and ($o -match "RAN $a8 status=ok") -and ($o -match "RAN $b8 status=ok")) "approval written during a run: picked up by the same pass (re-list)"
  # 9. a failure AFTER the command ran (here audit.log is unwritable) still finishes the id: result written, never re-run
  $c0 = (Get-Content $runs).Count
  Move-Item -LiteralPath $d.audit -Destination "$($d.audit).keep"; [void][IO.Directory]::CreateDirectory($d.audit)
  $x9 = Req $probe; WriteApproval $x9 'deadbeef' (Get-Date)
  $i9 = Req $probe; $h9 = Sha8Of $i9; Approve $i9 $h9; $o = Runner
  Remove-Item -LiteralPath $d.audit -Recurse -Force; Move-Item -LiteralPath "$($d.audit).keep" -Destination $d.audit
  $r9 = AA-ReadJson (Join-Path $d.results "$i9.json")
  Check ($r9.status -eq 'ok' -and (Test-Path (Join-Path $d.done "$i9.request.json")) -and -not (Test-Path (Join-Path $d.approved "$i9.json"))) "failure after the run (audit.log): result written, request + approval in done\"
  Check ([string]$r9.audit_failed -and ((& (Join-Path $here 'status.ps1') -Id $i9 -Root $T) -match '^audit.log not written')) "failure after the run (audit.log): audit_failed in the result, shown by status.ps1"
  Check (($o -match "REFUSED $x9 : sha8") -and [string](AA-ReadJson (Join-Path $d.results "$x9.refused.json")).audit_failed) "audit.log unwritable: a refusal is recorded (audit_failed) and the pass goes on"
  WriteApproval $i9 $h9 (Get-Date); $o = Runner
  Check ((Get-Content $runs).Count -eq $c0 + 1 -and ($o -match "REFUSED $i9 : already handled")) "failure after the run: a later pass never runs it again"
  # 10. a child the command leaves running still holds the stdout file: output is read anyway (Windows sharing)
  $i10 = Req ("Start-Process -NoNewWindow -FilePath powershell.exe -ArgumentList '-NoProfile', '-Command', 'Start-Sleep 4'; " + $probe)
  Approve $i10 (Sha8Of $i10); $o = Runner
  $r10 = AA-ReadJson (Join-Path $d.results "$i10.json")
  Check ($r10.status -eq 'ok' -and $r10.stdout -match 'hello-ok' -and ($o -match "RAN $i10 status=ok")) "stdout still held by a child: read shared, result written"
  # 11. approvals already waiting when the pass starts are judged by that time, not when their turn comes
  $c0 = (Get-Content $runs).Count
  $a11 = Req ("Start-Sleep 15; " + $probe); Approve $a11 (Sha8Of $a11)
  $b11 = $a11.Substring(0, 16) + 'ffffff'   # sorts after a11; request + approval written 9m50s ago
  AA-WriteJson (Join-Path $d.queue "$b11.json") ([ordered]@{ id = $b11; command = $probe; reason = 'test'; created = (Get-Date).AddSeconds(-590).ToUniversalTime().ToString('o'); sha256 = (AA-Sha256 $probe) })
  WriteApproval $b11 (Sha8Of $b11) ((Get-Date).AddSeconds(-590)); $o = Runner
  Check ((Get-Content $runs).Count -eq $c0 + 2 -and ($o -match "RAN $b11 status=ok")) "approval 9m50s old at pass start, behind a 15 s command: still runs (age judged at listing)"

  # ================= SELF-APPROVE: only with the owner's policy.json (install.ps1 -SelfApprove)
  $sb = (Get-Content $runs).Count
  $p1 = Req $probe; $threw = $false
  try { & (Join-Path $here 'approve.ps1') -Id $p1 -Sha8 (Sha8Of $p1) -By 'self:test-agent' -Root $T -NoStart | Out-Null } catch { $threw = $_.Exception.Message -match 'self-approval is off' }
  Check $threw "self-approve: approve.ps1 refuses -By self:* without the owner's policy.json"
  AA-WriteJson (Join-Path $d.approved "$p1.json") ([ordered]@{ id = $p1; sha8 = (Sha8Of $p1); by = 'self:test-agent'; at = (Get-Date).ToUniversalTime().ToString('o') })
  $o = Runner; Check ((Get-Content $runs).Count -eq $sb -and ($o -match "REFUSED $p1 : self-approval is off")) "self-approve: runner refuses a hand-written self:* approval without policy.json"
  AA-WriteJson (Join-Path $T 'policy.json') ([ordered]@{ self_approve = $true; set_by = 'test'; set_at = (Get-Date).ToUniversalTime().ToString('o'); note = 'test' })
  $p2 = Req $probe; & (Join-Path $here 'approve.ps1') -Id $p2 -Sha8 (Sha8Of $p2) -By 'self:test-agent' -Root $T -NoStart | Out-Null
  $o = Runner; Check ((Get-Content $runs).Count -eq $sb + 1 -and ($o -match "RAN $p2 status=ok")) "self-approve: with the owner's policy.json, a self-approved request runs once"
  Remove-Item -LiteralPath (Join-Path $T 'policy.json')

  # ================= SIGNED MODE: <T>\bin\approver.pub.xml present -> every approval needs a valid signature
  [void][IO.Directory]::CreateDirectory((Join-Path $T 'bin'))
  $key = New-Object Security.Cryptography.RSACryptoServiceProvider(3072)
  $other = New-Object Security.Cryptography.RSACryptoServiceProvider(3072)
  [IO.File]::WriteAllText((Join-Path $T 'bin\approver.pub.xml'), $key.ToXmlString($false))
  $iid = -join ((1..16) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
  [IO.File]::WriteAllText((Join-Path $T 'bin\install_id'), $iid)
  function NowAt { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
  function SignedJson([string]$id, [string]$sha, [string]$by, [string]$at, $signer, [string]$forIid = $iid, [string]$payload) {
    if (-not $payload) { $payload = AA-SignedPayload $forIid $id $sha $by $at }
    $sig = [Convert]::ToBase64String($signer.SignData([Text.Encoding]::UTF8.GetBytes($payload), 'SHA256'))
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
  # s11. install binding: same key, approval signed for ANOTHER install (the other PC) or in the old v1 layout
  $q11 = AA-ReadJson (Join-Path $d.queue "$s9.json")
  Check ([string]$q11.install_id -eq $iid) "signed: request.ps1 records this PC's install id"
  $s11 = Req $probe; PutApproval $s11 (SignedJson $s11 (ShaOf $s11) 'SIG-MSG-11' (NowAt) $key ('f' * 32))
  $o = Runner; Check ($o -match "REFUSED $s11 : signature invalid") "signed: approval signed for another install refused (no cross-PC replay)"
  $s12 = Req $probe; $sh = ShaOf $s12; $at = NowAt
  PutApproval $s12 (SignedJson $s12 $sh 'SIG-MSG-12' $at $key $iid "agent-admin-v1|$s12|$sh|SIG-MSG-12|$at")
  $o = Runner; Check ($o -match "REFUSED $s12 : signature invalid") "signed: old v1 signature (no install id) refused"
  Remove-Item -LiteralPath (Join-Path $T 'bin\install_id')
  $s13 = Req $probe; PutApproval $s13 (SignedJson $s13 (ShaOf $s13) 'SIG-MSG-13' (NowAt) $key)
  $o = Runner; Check ($o -match "REFUSED $s13 : signed mode: no valid bin") "signed: no bin\install_id -> every approval refused"
  Check ((Get-Content $runs).Count -eq $base + 1) "signed: still only the one valid approval ever ran"
  # s10. cross-platform vector (python cryptography, RSA-3072 PKCS1v15 SHA256)
  $v = Get-Content -LiteralPath (Join-Path $here 'test-vector.json') -Raw | ConvertFrom-Json
  Check ((AA-Sha256 $v.command) -eq $v.sha256) "vector: sha256(command) matches"
  $vi = '0123456789abcdef0123456789abcdef'   # the vector is v1; v2 is the same fields with the install id after the prefix
  Check ((AA-SignedPayload $vi '20261016-234500-a1b2c3' $v.sha256 '3A00000001' '2026-10-16T20:45:00Z') -eq ('agent-admin-v2|' + $vi + '|' + $v.payload.Substring('agent-admin-v1|'.Length))) "vector: payload layout agent-admin-v2|install_id|id|sha256|by|at matches"
  Check (AA-VerifySig $v.pub_xml $v.payload $v.sig) "vector: VerifyData(payload) = True (cross-platform signature)"
  Check (-not (AA-VerifySig $v.pub_xml $v.bad_payload $v.sig)) "vector: VerifyData(payload+'x') = False"
  $key.Dispose(); $other.Dispose()
} finally {
  Remove-Item -LiteralPath $T -Recurse -Force -ErrorAction SilentlyContinue
}
"$($script:n - $script:fails)/$($script:n) passed"
if ($script:fails) { exit 1 }
