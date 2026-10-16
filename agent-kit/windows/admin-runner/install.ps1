<#
install.ps1 - set up the admin-runner once. Run it ELEVATED, by the machine's owner (one UAC click).

  install.ps1 [-Root <dir>] [-WhatIf]     create folders + ACLs, copy runner.ps1/common.ps1 into <root>\bin,
                                          register \AgentAdmin\AgentAdmin-Runner (on demand, RunLevel Highest)
  install.ps1 -Uninstall [-Root <dir>]    remove the task and <root>\bin; keep audit.log, results\ and done\

ACLs (inheritance removed on the root):
  root, done\, results\, audit.log, bin\ : Administrators + SYSTEM full; the owner's user read-only
  queue\, approved\                      : Administrators + SYSTEM full; the owner's user modify
So a user-level process can queue and approve, but cannot change what runs elevated (bin\) or rewrite history.
#>
param(
  [string]$Root,
  [string]$ApproverKey,      # path to the approver's PUBLIC key (RSA XML); installs signed mode (no unsigned fallback)
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

if ($Uninstall) {
  Run "unregister task $TaskPath$TaskName" { if (Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false } }
  Run "remove $($d.bin)" { if (Test-Path -LiteralPath $d.bin) { Remove-Item -LiteralPath $d.bin -Recurse -Force } }
  "kept: $($d.audit), $($d.results), $($d.done)"
  return
}

$admins = '*S-1-5-32-544'; $system = '*S-1-5-18'
Run "create $Root and its folders" {
  foreach ($k in 'root', 'queue', 'approved', 'done', 'results', 'bin') { [void][IO.Directory]::CreateDirectory($d[$k]) }
  if (-not (Test-Path -LiteralPath $d.audit)) { [IO.File]::WriteAllText($d.audit, '') }
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
if ($ApproverKey) {
  $keyXml = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ApproverKey).Path)
  AA-CheckPublicKeyXml $keyXml      # refuses a private key or a non-RSA / short key, before anything is copied
  Run "install approver public key -> $($d.bin)\approver.pub.xml (SIGNED mode: every approval needs a valid signature)" {
    [IO.File]::WriteAllText((Join-Path $d.bin 'approver.pub.xml'), $keyXml, (New-Object Text.UTF8Encoding($false)))
  }
} else { "note   no -ApproverKey: UNSIGNED mode (see README, the risk section)" }
$runner = Join-Path $d.bin 'runner.ps1'
$arg = "--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runner`" -Root `"$Root`""
Run "register $TaskPath$TaskName (user $user, RunLevel Highest, no trigger): conhost.exe $arg" {
  $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\conhost.exe') -Argument $arg
  $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
  Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Action $action -Principal $principal -Settings $settings `
    -Description 'admin-runner: runs owner-approved commands from <root>\approved, one pass. See README.md.' -Force | Out-Null
}
