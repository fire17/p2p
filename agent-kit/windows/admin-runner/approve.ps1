<#
approve.ps1 - record the owner's approval of one queued request and start the elevated runner (user level).

  Signed installs (bin\approver.pub.xml present):
    approve.ps1 -ApprovalJson <file | json text> [-Root <dir>] [-NoStart]
      the approver's JSON {id, sha8, sha256, by, at, sig}, written VERBATIM to approved\<id>.json
      (the signature covers the exact "at" string, so it is never re-serialized)
  Unsigned installs only:
    approve.ps1 -Id <id> -Sha8 <8 hex> -By "<approval reference>" [-Root <dir>] [-NoStart]

Run ONLY after the owner approved exactly this request. It starts the on-demand task \AgentAdmin\AgentAdmin-Runner
(unless -NoStart). The runner checks everything again, including the signature, before running anything.
#>
[CmdletBinding(DefaultParameterSetName = 'Unsigned')]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'Signed')][string]$ApprovalJson,
  [Parameter(Mandatory = $true, ParameterSetName = 'Unsigned')][string]$Id,
  [Parameter(Mandatory = $true, ParameterSetName = 'Unsigned')][string]$Sha8,
  [Parameter(Mandatory = $true, ParameterSetName = 'Unsigned')][string]$By,
  [string]$Root,
  [switch]$NoStart
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
if (-not $Root) { $Root = $AA_DefaultRoot }
$d = AA-Dirs $Root
$signedInstall = Test-Path -LiteralPath (Join-Path $d.bin 'approver.pub.xml')

function Load-Request([string]$rid) {
  AA-CheckId $rid
  $q = Join-Path $d.queue "$rid.json"
  if (-not (Test-Path -LiteralPath $q)) { throw "no queued request $rid" }
  AA-ReadJson $q
}

if ($PSCmdlet.ParameterSetName -eq 'Signed') {
  $text = if (Test-Path -LiteralPath $ApprovalJson -PathType Leaf) { [IO.File]::ReadAllText($ApprovalJson) } else { $ApprovalJson }
  $ap = $text | ConvertFrom-Json
  $rid = [string]$ap.id
  $req = Load-Request $rid
  $sha = AA-Sha256 $req.command
  if ([string]$ap.sha256 -ne $sha) { throw "approval sha256 does not match request ${rid}: refusing" }
  if ($ap.sha8 -and [string]$ap.sha8 -ne $sha.Substring(0, 8)) { throw "approval sha8 does not match request ${rid}: refusing" }
  if (-not [string]$ap.sig) { throw 'approval has no signature' }
  if (-not [string]$ap.by) { throw 'approval has no by reference' }
  # verbatim: the signature covers the exact strings in this JSON
  $tmp = Join-Path $d.approved ("$rid.json.tmp-" + [guid]::NewGuid().ToString('N'))
  [IO.File]::WriteAllText($tmp, $text, (New-Object Text.UTF8Encoding($false)))
  Move-Item -LiteralPath $tmp -Destination (Join-Path $d.approved "$rid.json") -Force
  "approved $rid (sha8 $($sha.Substring(0, 8)), signed) by $($ap.by)"
  $Id = $rid
} else {
  if ($signedInstall) { throw 'this install requires signed approvals: use -ApprovalJson' }
  $req = Load-Request $Id
  if ($By -like 'self:*' -and -not (AA-SelfApproveOn $d)) { throw 'self-approval is off: the owner enables it with install.ps1 -SelfApprove, elevated, on this PC' }
  if ($Sha8 -notmatch '^[0-9a-f]{8}$') { throw "sha8 must be 8 lower-case hex chars, got '$Sha8'" }
  if (-not $By.Trim()) { throw '-By (the approval reference) is required' }
  if ((AA-Sha256 $req.command).Substring(0, 8) -ne $Sha8) { throw "sha8 $Sha8 does not match request ${Id}: refusing to approve" }
  AA-WriteJson (Join-Path $d.approved "$Id.json") ([ordered]@{
    id = $Id; sha8 = $Sha8; by = $By; at = (Get-Date).ToUniversalTime().ToString('o') })
  "approved $Id (sha8 $Sha8) by $By"
}
if (-not $NoStart) {
  # a pass already running re-lists approved\ before it exits, so this approval is not lost
  $busy = $false
  try { $busy = [string](Get-ScheduledTask -TaskPath '\AgentAdmin\' -TaskName 'AgentAdmin-Runner').State -eq 'Running' } catch { }
  Start-ScheduledTask -TaskPath '\AgentAdmin\' -TaskName 'AgentAdmin-Runner'
  if ($busy) { 'runner busy (a pass is running), it picks this up before it exits; check: status.ps1 -Id ' + $Id }
  else { 'runner started; check: status.ps1 -Id ' + $Id }
}
