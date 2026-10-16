<#
request.ps1 - queue one PowerShell command for elevated execution (user level; runs nothing).

  request.ps1 -Command "<powershell text>" -Reason "<why>" [-Root <dir>]

Writes queue\<id>.json and prints the id, the sha8 and the exact command. The owner approves exactly that
id + sha8 (approve.ps1); anything else is refused by the runner.
#>
param(
  [Parameter(Mandatory = $true)][string]$Command,
  [Parameter(Mandatory = $true)][string]$Reason,
  [string]$Root
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
if (-not $Root) { $Root = $AA_DefaultRoot }
$d = AA-Dirs $Root
if (-not (Test-Path -LiteralPath $d.queue)) { throw "no queue folder $($d.queue): is admin-runner installed?" }
if (-not $Command.Trim()) { throw 'empty command' }
if ($Command.Length -gt $AA_MaxCommandChars) { throw "command is $($Command.Length) chars; the limit is $AA_MaxCommandChars" }
if (-not $Reason.Trim()) { throw 'a reason is required' }

$id = AA-NewId
$sha = AA-Sha256 $Command
AA-WriteJson (Join-Path $d.queue "$id.json") ([ordered]@{
  id = $id; command = $Command; reason = $Reason; created = (Get-Date).ToUniversalTime().ToString('o'); sha256 = $sha })
"id:     $id"
"sha8:   $($sha.Substring(0, 8))"
"reason: $Reason"
"command (exact, $($Command.Length) chars):"
$Command
