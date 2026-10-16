<#
runner.ps1 - the elevated part: one pass over approved\, then exit. Runs as \AgentAdmin\AgentAdmin-Runner
(RunLevel Highest) from <root>\bin, which only administrators can write.

  runner.ps1 [-Root <dir>]                      what the task runs
  runner.ps1 -TestRoot <dir> -NoElevate         test mode: same logic on a temp root, not elevated

For each approved\<id>.json it refuses unless ALL hold:
  the request queue\<id>.json exists; the approval's sha8 equals the first 8 hex of sha256(command as loaded now);
  the approval is <= 10 min old and the request <= 60 min old; the command is <= 2000 chars;
  the id was never handled before (no done\<id>.request.json).
SIGNED MODE (approver.pub.xml next to this runner, i.e. in bin\; test mode: <TestRoot>\bin\): every approval must
also carry the full sha256 (== sha256 of the command as loaded now) and an RSA PKCS#1 v1.5 / SHA-256 signature over
the UTF-8 bytes of "agent-admin-v1|<id>|<sha256>|<by>|<at>", where at is exactly "yyyy-MM-ddTHH:mm:ssZ".
There is no unsigned fallback in that mode.
Then it runs the command in a child powershell (10 min timeout), writes results\<id>.json, appends one audit
line and moves request + approval to done\. A refused approval is also moved to done\ (marked refused) and
audited, so nothing is retried or run twice.
#>
param(
  [string]$Root,
  [string]$TestRoot,
  [switch]$NoElevate
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
if ($TestRoot) { $Root = $TestRoot } elseif (-not $Root) { $Root = $AA_DefaultRoot }
if (-not $NoElevate) {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'runner.ps1 must run elevated (or use -TestRoot -NoElevate for tests)' }
}
$d = AA-Dirs $Root
foreach ($k in 'queue', 'approved', 'done', 'results') { if (-not (Test-Path -LiteralPath $d[$k])) { throw "missing folder $($d[$k])" } }
# Signed mode: the approver's public key next to this runner (bin\, admin-write only). In test mode: <TestRoot>\bin\.
$pubPath = if ($TestRoot) { Join-Path $TestRoot 'bin\approver.pub.xml' } else { Join-Path $PSScriptRoot 'approver.pub.xml' }
$pubXml = if (Test-Path -LiteralPath $pubPath) { [IO.File]::ReadAllText($pubPath) } else { $null }
if ($pubXml) { AA-CheckPublicKeyXml $pubXml }   # a bad installed key stops the pass loudly

function Audit([string]$id, [string]$sha8, [string]$by, [string]$outcome, [string]$cmd) {
  $c = if ($cmd) { ($cmd -replace '\s+', ' ') } else { '' }
  if ($c.Length -gt 200) { $c = $c.Substring(0, 200) }
  $line = '{0} id={1} sha8={2} by={3} {4} cmd="{5}"' -f (Get-Date).ToUniversalTime().ToString('o'), $id, $sha8, $by, $outcome, $c
  Add-Content -LiteralPath $d.audit -Value $line -Encoding UTF8
}

function Finish([string]$id, [string]$suffix) {
  # move the approval (and the request, if any) out of the live folders: never seen again
  $a = Join-Path $d.approved "$id.json"; $q = Join-Path $d.queue "$id.json"
  if (Test-Path -LiteralPath $q) { Move-Item -LiteralPath $q -Destination (Join-Path $d.done "$id.request$suffix.json") -Force }
  if (Test-Path -LiteralPath $a) { Move-Item -LiteralPath $a -Destination (Join-Path $d.done "$id.approval$suffix.json") -Force }
}

function Refuse([string]$id, [string]$sha8, [string]$by, [string]$why, [string]$cmd, [bool]$keepRequest) {
  AA-WriteJson (Join-Path $d.results "$id.refused.json") ([ordered]@{ id = $id; status = 'refused'; reason = $why; at = (Get-Date).ToUniversalTime().ToString('o') })
  Audit $id $sha8 $by "REFUSED($why)" $cmd
  if ($keepRequest) {   # replay of a handled id: leave done\ alone, just drop the new approval
    $a = Join-Path $d.approved "$id.json"
    if (Test-Path -LiteralPath $a) { Move-Item -LiteralPath $a -Destination (Join-Path $d.done ("$id.approval.replay-" + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.json')) -Force }
  } else { Finish $id '.refused' }
  "REFUSED $id : $why"
}

# one runner at a time
$lockPath = Join-Path $d.root 'runner.lock'
$lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
try {
  $now = (Get-Date).ToUniversalTime()
  foreach ($f in @(Get-ChildItem -LiteralPath $d.approved -Filter '*.json' -File | Sort-Object Name)) {
    $id = [IO.Path]::GetFileNameWithoutExtension($f.Name)
    if ($id -notmatch $AA_IdPattern) { Move-Item -LiteralPath $f.FullName -Destination (Join-Path $d.done ($f.Name + '.badname')) -Force; Audit $id '' '' 'REFUSED(bad id)' ''; continue }
    $ap = $null; $req = $null
    try { $ap = AA-ReadJson $f.FullName } catch { Refuse $id '' '' 'approval unreadable' '' $false; continue }
    $sha8 = [string]$ap.sha8; $by = [string]$ap.by
    if (Test-Path -LiteralPath (Join-Path $d.done "$id.request.json")) { Refuse $id $sha8 $by 'already handled (replay)' '' $true; continue }
    $qp = Join-Path $d.queue "$id.json"
    if (-not (Test-Path -LiteralPath $qp)) { Refuse $id $sha8 $by 'no such request' '' $false; continue }
    try { $req = AA-ReadJson $qp } catch { Refuse $id $sha8 $by 'request unreadable' '' $false; continue }
    $cmd = [string]$req.command
    if ($ap.id -ne $id -or $req.id -ne $id) { Refuse $id $sha8 $by 'id mismatch' $cmd $false; continue }
    if (-not $by.Trim()) { Refuse $id $sha8 $by 'approval has no -By reference' $cmd $false; continue }
    if (-not $cmd.Trim() -or $cmd.Length -gt $AA_MaxCommandChars) { Refuse $id $sha8 $by "command empty or over $AA_MaxCommandChars chars" $cmd $false; continue }
    $cmdSha = AA-Sha256 $cmd
    if ($pubXml) {
      # signed mode: full sha256 + a valid signature over agent-admin-v1|id|sha256|by|at, no unsigned fallback
      $apSha = [string]$ap.sha256; $sig = [string]$ap.sig; $atStr = [string]$ap.at
      if ($apSha -notmatch '^[0-9a-f]{64}$') { Refuse $id $sha8 $by 'signed mode: approval has no full sha256' $cmd $false; continue }
      if ($apSha -ne $cmdSha) { Refuse $id $sha8 $by 'sha256 does not match the command' $cmd $false; continue }
      if ($sha8 -and $sha8 -ne $cmdSha.Substring(0, 8)) { Refuse $id $sha8 $by 'sha8 does not match the command' $cmd $false; continue }
      $sha8 = $cmdSha.Substring(0, 8)
      if (-not $sig) { Refuse $id $sha8 $by 'signed mode: approval has no signature' $cmd $false; continue }
      if ($atStr -notmatch $AA_AtPattern) { Refuse $id $sha8 $by 'signed mode: at must be yyyy-MM-ddTHH:mm:ssZ' $cmd $false; continue }
      if (-not (AA-VerifySig $pubXml (AA-SignedPayload $id $apSha $by $atStr) $sig)) { Refuse $id $sha8 $by 'signature invalid' $cmd $false; continue }
    } elseif ($cmdSha.Substring(0, 8) -ne $sha8) { Refuse $id $sha8 $by 'sha8 does not match the command' $cmd $false; continue }
    elseif ($by -like 'self:*' -and -not (AA-SelfApproveOn $d)) { Refuse $id $sha8 $by 'self-approval is off (no owner policy.json)' $cmd $false; continue }
    try { $at = [DateTime]::Parse([string]$ap.at).ToUniversalTime(); $created = [DateTime]::Parse([string]$req.created).ToUniversalTime() }
    catch { Refuse $id $sha8 $by 'bad timestamps' $cmd $false; continue }
    if (($now - $at).TotalSeconds -gt $AA_ApprovalMaxAgeSec -or $at -gt $now.AddMinutes(1)) { Refuse $id $sha8 $by 'approval stale (>10 min) or in the future' $cmd $false; continue }
    if (($now - $created).TotalSeconds -gt $AA_RequestMaxAgeSec) { Refuse $id $sha8 $by 'request stale (>60 min)' $cmd $false; continue }
    # a signed "at" has whole seconds, "created" has fractions: allow the same second
    if ($at -lt $created.AddSeconds(-1)) { Refuse $id $sha8 $by 'approval older than the request' $cmd $false; continue }

    # run it: child powershell, the command passed encoded (no quoting issues), 10 min limit
    $out = Join-Path $d.results "$id.stdout.txt"; $err = Join-Path $d.results "$id.stderr.txt"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    $started = (Get-Date).ToUniversalTime()
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc) `
         -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Hidden -PassThru
    $null = $p.Handle   # PS 5.1: ExitCode is readable later only if the handle was opened while it ran
    $status = 'ok'
    if (-not $p.WaitForExit($AA_TimeoutSec * 1000)) { try { $p.Kill() } catch { }; $p.WaitForExit(); $status = 'timeout' }
    $code = $p.ExitCode
    $so = if (Test-Path -LiteralPath $out) { [IO.File]::ReadAllText($out) } else { '' }
    $se = if (Test-Path -LiteralPath $err) { [IO.File]::ReadAllText($err) } else { '' }
    AA-WriteJson (Join-Path $d.results "$id.json") ([ordered]@{
      id = $id; status = $status; exit = $code; sha8 = $sha8; by = $by; reason = [string]$req.reason
      started = $started.ToString('o'); ended = (Get-Date).ToUniversalTime().ToString('o'); stdout = $so; stderr = $se })
    Remove-Item -LiteralPath $out, $err -ErrorAction SilentlyContinue
    Audit $id $sha8 $by "RAN status=$status exit=$code" $cmd
    Finish $id ''
    "RAN $id status=$status exit=$code"
  }
} finally { $lock.Dispose() }
