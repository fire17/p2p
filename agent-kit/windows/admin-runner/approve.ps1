<#
approve.ps1 - record the owner's approval of one queued request and start the elevated runner (user level).

  approve.ps1 -Id <id> -Sha8 <8 hex> -By "<id of the owner's approval, e.g. a chat message id>" [-Root <dir>] [-NoStart]

Run ONLY after the owner approved exactly this id + sha8. It writes approved\<id>.json and starts the on-demand
task \AgentAdmin\AgentAdmin-Runner (unless -NoStart). The runner checks everything again before running.
#>
param(
  [Parameter(Mandatory = $true)][string]$Id,
  [Parameter(Mandatory = $true)][string]$Sha8,
  [Parameter(Mandatory = $true)][string]$By,
  [string]$Root,
  [switch]$NoStart
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
if (-not $Root) { $Root = $AA_DefaultRoot }
$d = AA-Dirs $Root
AA-CheckId $Id
if ($Sha8 -notmatch '^[0-9a-f]{8}$') { throw "sha8 must be 8 lower-case hex chars, got '$Sha8'" }
if (-not $By.Trim()) { throw '-By (the approval reference) is required' }
$q = Join-Path $d.queue "$Id.json"
if (-not (Test-Path -LiteralPath $q)) { throw "no queued request $Id" }
$req = AA-ReadJson $q
if ((AA-Sha256 $req.command).Substring(0, 8) -ne $Sha8) { throw "sha8 $Sha8 does not match request ${Id}: refusing to approve" }

AA-WriteJson (Join-Path $d.approved "$Id.json") ([ordered]@{
  id = $Id; sha8 = $Sha8; by = $By; at = (Get-Date).ToUniversalTime().ToString('o') })
"approved $Id (sha8 $Sha8) by $By"
if (-not $NoStart) {
  Start-ScheduledTask -TaskPath '\AgentAdmin\' -TaskName 'AgentAdmin-Runner'
  'runner started; check: status.ps1 -Id ' + $Id
}
