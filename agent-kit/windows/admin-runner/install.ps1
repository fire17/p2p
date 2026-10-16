<#
install.ps1 - set up the admin-runner once. Run it ELEVATED, by the machine's owner (one UAC click).

  install.ps1 [-Root <dir>] [-WhatIf]     create folders + ACLs, copy runner.ps1/common.ps1 into <root>\bin,
                                          register \AgentAdmin\AgentAdmin-Runner (on demand, RunLevel Highest)
  install.ps1 -Uninstall [-Root <dir>]    remove the task and <root>\bin; keep audit.log, results\ and done\

ACLs (inheritance removed on the root):
  root, done\, results\, audit.log, bin\ : Administrators + SYSTEM full; the owner's user read-only
  queue\, approved\                      : Administrators + SYSTEM full; the owner's user modify
So a user-level process can queue and approve, but cannot change what runs elevated (bin\) or rewrite history.
Owner: Administrators on the whole tree. A user may create folders under ProgramData first; if any admin-only part
(root, done\, results\, bin\ and its files, audit.log, policy.json) exists and is not owned by Administrators/SYSTEM,
it was planted: its ACLs are reset and bin\ is recreated empty (a planted bin\ that held approver.pub.xml stops the
install unless -ApproverKey or -SelfApprove says which mode to use). Before the task is registered, bin\ gets its
owner and ACL forced again and every admin-only item is checked: owned by Administrators/SYSTEM, nobody else can
write it, and bin\runner.ps1 + common.ps1 equal the files being installed.
#>
param(
  [string]$Root,
  [string]$ApproverKey,      # path to the approver's PUBLIC key (RSA XML); installs signed mode (no unsigned fallback)
  [switch]$SelfApprove,       # the owner's temporary choice: agents approve their own requests (writes policy.json)
  [string]$Note,
  [switch]$Uninstall,
  [switch]$WhatIf
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
if (-not $Root) { $Root = $AA_DefaultRoot }
$d = AA-Dirs $Root
$TaskPath = '\AgentAdmin\'; $TaskName = 'AgentAdmin-Runner'
$user = "$env:USERDOMAIN\$env:USERNAME"

$pr = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $WhatIf -and -not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'install.ps1 must run elevated (right-click PowerShell -> Run as administrator), or use -WhatIf'
}

function Run([string]$what, [scriptblock]$do) {
  if ($WhatIf) { "WHATIF $what" } else { & $do; "done   $what" }
}

if ($SelfApprove -and $ApproverKey) { throw '-SelfApprove and -ApproverKey exclude each other' }
$policy = Join-Path $d.root 'policy.json'
if ($Uninstall) {
  Run "remove $policy" { if (Test-Path -LiteralPath $policy) { Remove-Item -LiteralPath $policy -Force } }
  Run "unregister task $TaskPath$TaskName" { if (Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false } }
  Run "remove $($d.bin)" { if (Test-Path -LiteralPath $d.bin) { Remove-Item -LiteralPath $d.bin -Recurse -Force } }
  "kept: $($d.audit), $($d.results), $($d.done)"
  return
}

$admins = '*S-1-5-32-544'; $system = '*S-1-5-18'
function OwnerOk([string]$p) {
  # owner is BUILTIN\Administrators or SYSTEM (by SID: names are localized)
  try { $o = (Get-Acl -LiteralPath $p).GetOwner([Security.Principal.SecurityIdentifier]).Value } catch { return $false }
  $o -eq 'S-1-5-32-544' -or $o -eq 'S-1-5-18'
}
function DaclOk([string]$p) {
  # no allow ACE outside Administrators/SYSTEM grants write, delete, WRITE_DAC, WRITE_OWNER or GENERIC_ALL/WRITE
  $w = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
  try { $rules = (Get-Acl -LiteralPath $p).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) } catch { return $false }
  foreach ($r in $rules) {
    if ($r.AccessControlType -ne 'Allow' -or $r.IdentityReference.Value -in 'S-1-5-32-544', 'S-1-5-18') { continue }
    if ([int64]$r.FileSystemRights -band $w) { return $false }
  }
  $true
}
function NotAdminOwned([switch]$Dacl) {
  # the admin-only items that exist and are not admin-owned (an owner keeps WRITE_DAC whatever the ACL says);
  # -Dacl: also those someone other than Administrators/SYSTEM can write
  $items = @($d.root, $d.done, $d.results, $d.bin, $d.audit, $policy | Where-Object { Test-Path -LiteralPath $_ })
  if (Test-Path -LiteralPath $d.bin) {
    try { $items += @(Get-ChildItem -LiteralPath $d.bin -Force -Recurse | ForEach-Object { $_.FullName }) } catch { return @($d.bin) }
  }
  if ($Dacl) { return @($items | Where-Object { -not (OwnerOk $_) -or -not (DaclOk $_) }) }
  @($items | Where-Object { -not (OwnerOk $_) })
}
Run "create $Root and its folders" {
  foreach ($k in 'root', 'queue', 'approved', 'done', 'results', 'bin') { [void][IO.Directory]::CreateDirectory($d[$k]) }
  if (-not (Test-Path -LiteralPath $d.audit)) { [IO.File]::WriteAllText($d.audit, '') }
}
Run "owner: Administrators on $Root and everything under it (planted folders: ACLs reset, bin\ recreated empty)" {
  $planted = @(NotAdminOwned)
  if ($planted.Count -and (Test-Path -LiteralPath (Join-Path $d.bin 'approver.pub.xml')) -and -not $ApproverKey -and -not $SelfApprove) {
    throw "planted items ($($planted -join ', ')) and bin\ holds approver.pub.xml: recreating bin\ would drop SIGNED mode. Re-run with -ApproverKey <pub.xml> (or -SelfApprove to choose that mode)"
  }
  & icacls $d.root /setowner $admins /T /C /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed on $($d.root) (exit $LASTEXITCODE); take ownership first: takeown /F `"$($d.root)`" /A /R" }
  if ($planted.Count) {
    "note   not admin-owned before install: $($planted -join ', ')"
    & icacls $d.root /reset /T /C /Q | Out-Null   # drop explicit ACEs a planter added; the grants below then apply
    if ($LASTEXITCODE -ne 0) { throw "icacls /reset failed on $($d.root) (exit $LASTEXITCODE)" }
    Remove-Item -LiteralPath $d.bin -Recurse -Force
    [void][IO.Directory]::CreateDirectory($d.bin)
    "note   $($d.bin) recreated empty: pass -ApproverKey again if this PC should be in signed mode"
  }
}
Run "ACL root/done/results/bin/audit.log: admins+SYSTEM full, $user read" {
  foreach ($p in $d.root, $d.done, $d.results, $d.bin) {
    & icacls $p /inheritance:r /grant:r "${admins}:(OI)(CI)F" "${system}:(OI)(CI)F" "${user}:(OI)(CI)RX" /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $p (exit $LASTEXITCODE)" }
  }
  # a file takes no (OI)(CI) inheritance flags
  & icacls $d.audit /inheritance:r /grant:r "${admins}:F" "${system}:F" "${user}:R" /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls failed on $($d.audit) (exit $LASTEXITCODE)" }
}
Run "ACL queue/approved: admins+SYSTEM full, $user modify" {
  foreach ($p in $d.queue, $d.approved) {
    & icacls $p /inheritance:r /grant:r "${admins}:(OI)(CI)F" "${system}:(OI)(CI)F" "${user}:(OI)(CI)M" /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $p (exit $LASTEXITCODE)" }
  }
}
Run "copy runner.ps1 + common.ps1 into $($d.bin)" {
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'runner.ps1'), (Join-Path $PSScriptRoot 'common.ps1') -Destination $d.bin -Force
}
$iidPath = Join-Path $d.bin 'install_id'
Run "install id $iidPath (kept if valid; signed approvals are bound to it, so they never replay on another PC)" {
  if (-not (AA-ReadInstallId $iidPath)) {
    $b = New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    [IO.File]::WriteAllText($iidPath, (-join ($b | ForEach-Object { $_.ToString('x2') })), (New-Object Text.UTF8Encoding($false)))
  }
}
if ($ApproverKey) {
  $keyXml = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ApproverKey).Path)
  AA-CheckPublicKeyXml $keyXml      # refuses a private key or a non-RSA / short key, before anything is copied
  Run "install approver public key -> $($d.bin)\approver.pub.xml (SIGNED mode: every approval needs a valid signature)" {
    [IO.File]::WriteAllText((Join-Path $d.bin 'approver.pub.xml'), $keyXml, (New-Object Text.UTF8Encoding($false)))
  }
} else { "note   no -ApproverKey: UNSIGNED mode (see README, the risk section)" }
Run "check: $Root, done\, results\, bin\ and its files, audit.log: owned by Administrators/SYSTEM, writable by no one else" {
  # files just written are owned by the token's default owner; force Administrators in case that is the user
  & icacls $d.bin /setowner $admins /T /C /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed on $($d.bin) (exit $LASTEXITCODE)" }
  # a file planted in bin\ before the step-3 ACL kept WRITE_DAC as its owner and may have added itself back: drop
  # every explicit ACE, then the same grants as above
  & icacls $d.bin /reset /T /C /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls /reset failed on $($d.bin) (exit $LASTEXITCODE)" }
  & icacls $d.bin /inheritance:r /grant:r "${admins}:(OI)(CI)F" "${system}:(OI)(CI)F" "${user}:(OI)(CI)RX" /T /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls failed on $($d.bin) (exit $LASTEXITCODE)" }
  $bad = @(NotAdminOwned -Dacl)
  if ($bad.Count) { throw "not admin-only after install (the task is NOT registered): $($bad -join ', ')" }
  foreach ($f in 'runner.ps1', 'common.ps1') {   # its content may have been changed while a planter could still write it
    if ((Get-FileHash -LiteralPath (Join-Path $d.bin $f)).Hash -ne (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $f)).Hash) { throw "$($d.bin)\$f differs from the file installed (the task is NOT registered); re-run install.ps1" }
  }
}
$runner = Join-Path $d.bin 'runner.ps1'
$arg = "--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runner`" -Root `"$Root`""
Run "register $TaskPath$TaskName (user $user, RunLevel Highest, no trigger): conhost.exe $arg" {
  $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\conhost.exe') -Argument $arg
  $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
  # Queue, not IgnoreNew: a start while a pass runs is queued, not dropped (runner.lock still serialises passes);
  # 2 h: one pass re-lists approved\ and may run several 10 min commands
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances Queue -ExecutionTimeLimit (New-TimeSpan -Hours 2)
  Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Action $action -Principal $principal -Settings $settings `
    -Description 'admin-runner: runs owner-approved commands from <root>\approved, one pass. See README.md.' -Force | Out-Null
}
if ($SelfApprove) {
  $n = if ($Note) { $Note } else { 'temporary: until the owner has his own approval channel' }
  Run "write $policy (self_approve = true, set by $user; agents may approve their own requests, every run in audit.log)" {
    AA-WriteJson $policy ([ordered]@{ self_approve = $true; set_by = $user; set_at = (Get-Date).ToUniversalTime().ToString('o'); note = $n })
    & icacls $policy /setowner $admins /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /setowner failed on $policy (exit $LASTEXITCODE)" }
  }
} else {
  Run "remove $policy (self-approve off)" { if (Test-Path -LiteralPath $policy) { Remove-Item -LiteralPath $policy -Force } }
}
