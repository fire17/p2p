<#
status.ps1 - show what happened to a request (user level, read-only).

  status.ps1 -Id <id> [-Root <dir>]
#>
param(
  [Parameter(Mandatory = $true)][string]$Id,
  [string]$Root
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
if (-not $Root) { $Root = $AA_DefaultRoot }
$d = AA-Dirs $Root
AA-CheckId $Id
$r = Join-Path $d.results "$Id.json"; $x = Join-Path $d.results "$Id.refused.json"
if (Test-Path -LiteralPath $r) {
  $j = AA-ReadJson $r
  "id $($j.id): $($j.status), exit $($j.exit), $($j.started) -> $($j.ended), approved by $($j.by)"
  if ($j.error) { "error: $($j.error)" }
  if ($j.audit_failed) { "audit.log not written: $($j.audit_failed)" }
  '--- stdout'; $j.stdout
  if ($j.stderr) { '--- stderr'; $j.stderr }
} elseif (Test-Path -LiteralPath $x) {
  $j = AA-ReadJson $x; "id $($j.id): REFUSED ($($j.reason)) at $($j.at)"
  if ($j.audit_failed) { "audit.log not written: $($j.audit_failed)" }
} elseif (Test-Path -LiteralPath (Join-Path $d.approved "$Id.json")) { "id ${Id}: approved, waiting for the runner"
} elseif (Test-Path -LiteralPath (Join-Path $d.queue "$Id.json")) { "id ${Id}: queued, not approved"
} else { "id ${Id}: unknown" }
