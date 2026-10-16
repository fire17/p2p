<#
health.ps1 - one-screen health board for this PC's agent setup (user level, read-only: it changes nothing).
  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\health.ps1 [-Json]
Checks: keepers + hub links, hub who, ledger, our scheduled tasks, admin-runner, WSL bridge + herdr, disk, clock.
One OK / WARN / FAIL line each, then a verdict. Exit 0 all OK, 1 any WARN, 2 any FAIL. -Json: one JSON object.
Never prints secrets: mesh.json is read for link names and sessions only; task arguments are never shown.
#>
[CmdletBinding()]
param([switch]$Json)
$ErrorActionPreference = 'Stop'

$OnWindows = ($PSVersionTable.PSVersion.Major -le 5) -or ((Test-Path variable:IsWindows) -and $IsWindows)
$UserHome = [Environment]::GetFolderPath('UserProfile')
$MeshDir = if ($env:AGENT_MESH_HOME) { $env:AGENT_MESH_HOME } else { Join-Path $UserHome '.agent-mesh' }
$MeshJson = Join-Path $MeshDir 'mesh.json'
$LogDir = Join-Path $MeshDir 'logs'
$RunDir = Join-Path $MeshDir 'run'
$HubRoot = if ($env:AGENT_HUB) { $env:AGENT_HUB } else { Join-Path $UserHome '.agent-hub' }
$SentDir = Join-Path $UserHome '.agent-sentinel'
$PD = if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }
$AdminRoot = [IO.Path]::Combine($PD, 'AgentAdmin')   # not Join-Path: it needs drive C: to exist
$KitRoot = Split-Path $PSScriptRoot -Parent
$KitHubPy = Join-Path (Join-Path $KitRoot 'hub') 'hub.py'
$Utf8 = New-Object Text.UTF8Encoding($false)
$Now = [DateTime]::Now
$NowUtc = [DateTime]::UtcNow
$Results = New-Object System.Collections.ArrayList

# ------------------------------------------------------------------ helpers
# Every printed string: secrets masked, then ASCII printable only, then cut.
function Safe-Text([string]$s, [int]$max = 120) {
  if ($null -eq $s) { return '' }
  $s = $s -replace '\b[0-9A-Z]{26}\b', '<key>'
  $s = $s -replace '(?i)\b(token|secret|password|passwd|api[_-]?key|bearer|authorization)\b(["'']?\s*[:=]\s*["'']?|\s+)[^\s;,)"'']+', '$1=<hidden>'
  $s = $s -replace '\b(sk-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.-]+)', '<hidden>'
  $s = ($s -replace '[\r\n\t]+', ' ') -replace '[^\x20-\x7E]', '?'
  $s = $s.Trim()
  if ($s.Length -gt $max) { $s = $s.Substring(0, $max - 3) + '...' }
  $s
}
function Add-Result([string]$name, [string]$status, [string]$reason, [string[]]$details = @()) {
  [void]$Results.Add([pscustomobject]@{ check = $name; status = $status; reason = (Safe-Text $reason 140)
      details = @($details | Where-Object { $_ } | ForEach-Object { Safe-Text $_ 130 }) })
}
function Worst([string[]]$s) { if ($s -contains 'FAIL') { 'FAIL' } elseif ($s -contains 'WARN') { 'WARN' } else { 'OK' } }
function Prop($o, [string]$n) { if ($null -ne $o -and $o.PSObject.Properties[$n]) { $o.PSObject.Properties[$n].Value } else { $null } }

# Windows command-line quoting (CommandLineToArgvW rules), as in mesh-setup.ps1.
function Format-Arg([string]$a) {
  if ($a -eq '') { return '""' }
  if ($a -notmatch '[\s"]') { return $a }
  $sb = New-Object Text.StringBuilder
  [void]$sb.Append('"'); $bs = 0
  foreach ($c in $a.ToCharArray()) {
    if ($c -eq [char]92) { $bs++; continue }
    if ($c -eq [char]34) { [void]$sb.Append(('\' * (2 * $bs + 1)) + '"'); $bs = 0; continue }
    if ($bs) { [void]$sb.Append('\' * $bs); $bs = 0 }
    [void]$sb.Append($c)
  }
  [void]$sb.Append(('\' * (2 * $bs)) + '"')
  $sb.ToString()
}
# Run one fixed argv with a hard timeout; never throws (rc 127 = could not start, 124 = timeout).
function Invoke-Fixed([string[]]$argv, [int]$TimeoutSec = 10) {
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $argv[0]
  $psi.Arguments = (@($argv | Select-Object -Skip 1) | ForEach-Object { Format-Arg $_ }) -join ' '
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
  try { $psi.StandardOutputEncoding = $Utf8; $psi.StandardErrorEncoding = $Utf8 } catch {}
  $p = New-Object Diagnostics.Process; $p.StartInfo = $psi
  try { [void]$p.Start() } catch { return [pscustomobject]@{ rc = 127; out = ''; err = $_.Exception.Message } }
  $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    try { $p.Kill() } catch {}
    return [pscustomobject]@{ rc = 124; out = ''; err = "timed out after $TimeoutSec s" }
  }
  $out = ''; $err = ''
  try { if ($o.Wait(3000)) { $out = $o.Result } } catch {}
  try { if ($e.Wait(3000)) { $err = $e.Result } } catch {}
  $rc = 0; try { $rc = $p.ExitCode } catch { $rc = -1 }
  # wsl.exe prints its own messages in UTF-16: drop the NULs
  [pscustomobject]@{ rc = $rc; out = ([string]$out -replace "`0", ''); err = ([string]$err -replace "`0", '') }
}
# Run a script block in its own runspace with a hard timeout (Task Scheduler / CIM queries can hang).
function Invoke-Bounded([string]$script, [int]$TimeoutSec = 10) {
  $ps = [PowerShell]::Create()
  [void]$ps.AddScript($script)
  $h = $ps.BeginInvoke()
  if (-not $h.AsyncWaitHandle.WaitOne($TimeoutSec * 1000)) {
    try { [void]$ps.BeginStop($null, $null) } catch {}
    throw "timed out after $TimeoutSec s"
  }
  $r = $ps.EndInvoke($h)
  if (-not $r -and $ps.HadErrors -and $ps.Streams.Error.Count) { $m = $ps.Streams.Error[0].ToString(); $ps.Dispose(); throw $m }
  $ps.Dispose()
  $r
}
# Last bytes of a file, shared with its writer (keepers and links hold their logs open).
function Read-Tail([string]$path, [int]$bytes = 65536) {
  $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  try {
    $start = [Math]::Max([long]0, $fs.Length - $bytes)
    [void]$fs.Seek($start, [IO.SeekOrigin]::Begin)
    $buf = New-Object byte[] ([int]($fs.Length - $start))
    $n = 0; while ($n -lt $buf.Length) { $k = $fs.Read($buf, $n, $buf.Length - $n); if ($k -le 0) { break }; $n += $k }
    $lines = @(($Utf8.GetString($buf, 0, $n)) -split "`r?`n")
    if ($start -gt 0 -and $lines.Count -gt 1) { $lines = @($lines | Select-Object -Skip 1) }   # first line is cut
    $lines | Where-Object { $_ -ne '' }
  } finally { $fs.Dispose() }
}
function Read-Shared([string]$path) {
  $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
  try { $sr = New-Object IO.StreamReader($fs, $Utf8); $sr.ReadToEnd() } finally { $fs.Dispose() }
}
function Sha8([string]$path) {
  $sha = [Security.Cryptography.SHA256]::Create()
  $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try { $h = $sha.ComputeHash($fs) } finally { $fs.Dispose(); $sha.Dispose() }
  (-join ($h | ForEach-Object { $_.ToString('x2') })).Substring(0, 8)
}
function Parse-LocalTs([string]$line) {
  if ($line -match '^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)') {
    try { return [DateTime]::ParseExact(($Matches[1] -replace 'T', ' '), 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) } catch {}
  }
  $null
}
function Age([double]$sec) {
  if ($sec -lt 0) { $sec = 0 }
  if ($sec -lt 120) { return ('{0}s' -f [int]$sec) }
  if ($sec -lt 7200) { return ('{0}m' -f [int]($sec / 60)) }
  if ($sec -lt 172800) { return ('{0}h' -f [int]($sec / 3600)) }
  '{0}d' -f [int]($sec / 86400)
}
function ConvertTo-WslPath([string]$p) {
  if ($p -match '^([A-Za-z]):\\(.*)$') { return '/mnt/' + $Matches[1].ToLowerInvariant() + '/' + ($Matches[2] -replace '\\', '/') }
  $p
}
function Run-Check([string]$name, [scriptblock]$body) {
  try { $null = & $body } catch { Add-Result $name 'WARN' ("check failed: " + $_.Exception.Message) }
}

# mesh.json: ONLY link names, roles, sessions, hub names and the python to use. Its keys are never read out.
$Mesh = $null; $MeshErr = ''
if (Test-Path -LiteralPath $MeshJson) {
  try {
    $raw = [IO.File]::ReadAllText($MeshJson, $Utf8) | ConvertFrom-Json
    $links = @()
    $lk = Prop $raw 'links'
    if ($lk) { foreach ($p in $lk.PSObject.Properties) { $links += [pscustomobject]@{ name = [string]$p.Name; role = [string](Prop $p.Value 'role'); session = [string](Prop $p.Value 'session'); as = [string](Prop $p.Value 'as') } } }
    $Mesh = [pscustomobject]@{ links = $links; python = @(Prop $raw 'python'); hubPy = [string](Prop $raw 'hubPy'); wsl = [bool](Prop $raw 'wsl') }
    $raw = $null
  } catch { $MeshErr = 'mesh.json unreadable: ' + $_.Exception.Message }
}

# Our scheduled tasks, read once (checks 3 and 4). Arguments are reduced to "headless or not" inside the runspace.
$Tasks = $null; $TasksErr = ''
if ($OnWindows) {
  try {
    $Tasks = @(Invoke-Bounded @'
Get-ScheduledTask -ErrorAction Stop | Where-Object {
  $_.TaskName -like 'Shai-*' -or $_.TaskName -eq 'Gony-Herdr-Autostart' -or $_.TaskPath -eq '\AgentMesh\' -or $_.TaskPath -eq '\AgentAdmin\'
} | ForEach-Object {
  $i = $null; try { $i = $_ | Get-ScheduledTaskInfo -ErrorAction Stop } catch {}
  $a = @($_.Actions)[0]; $exe = ''; $hl = $false
  if ($a -and $a.PSObject.Properties['Execute']) { $exe = [string]$a.Execute; $hl = ($exe -match 'conhost(\.exe)?"?$') -and ([string]$a.Arguments -match '^\s*--headless\b') }
  [pscustomobject]@{ path = [string]$_.TaskPath; name = [string]$_.TaskName; state = [string]$_.State
    exe = $(if ($exe) { Split-Path ($exe -replace '"', '') -Leaf } else { '(none)' }); headless = $hl
    last = $(if ($i) { [long]$i.LastTaskResult } else { $null }); lastRun = $(if ($i) { $i.LastRunTime } else { $null }) }
}
'@ 15)
  } catch { $TasksErr = $_.Exception.Message }
} else { $TasksErr = 'Task Scheduler needs Windows' }

# ------------------------------------------------------------------ 1. keeper + hub link per link
Run-Check 'mesh' {
  if (-not (Test-Path -LiteralPath $MeshJson)) { Add-Result 'mesh' 'WARN' "no mesh.json at $MeshJson (mesh not set up on this PC)"; return }
  if ($MeshErr) { Add-Result 'mesh' 'WARN' $MeshErr; return }
  if (-not $Mesh.links.Count) { Add-Result 'mesh' 'WARN' 'mesh.json has no links'; return }
  foreach ($l in $Mesh.links) {
    $n = $l.name; $st = @(); $why = @()
    if ($n -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,30}$') { Add-Result "link ?" 'WARN' 'mesh.json has a link with a bad name'; continue }
    # keeper pid file + live process
    $pf = Join-Path $RunDir ($n + '.pid')
    if (-not (Test-Path -LiteralPath $pf)) { $st += 'FAIL'; $why += 'keeper not running (no pid file)' }
    else {
      $kp = 0; [void][int]::TryParse(([IO.File]::ReadAllText($pf)).Trim(), [ref]$kp)
      $proc = $null; if ($kp -gt 0) { $proc = Get-Process -Id $kp -ErrorAction SilentlyContinue }
      if (-not $proc) { $st += 'FAIL'; $why += "keeper pid $kp dead (stale pid file)" }
      elseif ($proc.ProcessName -notmatch '^(powershell|pwsh)$') { $st += 'FAIL'; $why += "keeper pid $kp is now $($proc.ProcessName) (stale pid file)" }
      else { $st += 'OK'; $why += "keeper pid $kp up" }
    }
    # last LINK UP/DOWN line in the hub link log
    $hl = Join-Path $LogDir ($n + '.hub.log')
    if (-not (Test-Path -LiteralPath $hl)) { $st += 'WARN'; $why += 'no hub log' }
    else {
      $last = @(Read-Tail $hl | Where-Object { $_ -match '\bLINK \S+ (UP|DOWN) \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ' }) | Select-Object -Last 1
      if (-not $last) { $st += 'WARN'; $why += 'no LINK UP/DOWN line in hub log yet' }
      else {
        [void]($last -match '\bLINK \S+ (UP|DOWN) (\S+)(.*)$'); $ud = $Matches[1]; $at = $Matches[2]; $rest = $Matches[3]
        $ago = ''; try { $ago = ' ' + (Age ($NowUtc - [DateTime]::Parse($at, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)).TotalSeconds) + ' ago' } catch {}
        if ($ud -eq 'UP') { $st += 'OK'; $why += "LINK UP$ago" } else { $st += 'FAIL'; $why += "LINK DOWN$ago$rest" }
      }
    }
    # keeper log: link exits in the last 10 minutes
    $kl = Join-Path $LogDir ($n + '.keeper.log')
    if (Test-Path -LiteralPath $kl) {
      $ex = @(Read-Tail $kl | Where-Object { $_ -match 'exited \(code' } | Where-Object { $t = Parse-LocalTs $_; $t -and ($Now - $t).TotalMinutes -le 10 })
      if ($ex.Count) { $st += 'WARN'; $why += "$($ex.Count) link exit(s) in 10 min" } else { $why += 'no exits 10 min' }
    } else { $st += 'WARN'; $why += 'no keeper log' }
    Add-Result "link $n" (Worst $st) ("$($l.role) $($l.session) @$($l.as): " + ($why -join '; '))
  }
}

# ------------------------------------------------------------------ 2. hub who
Run-Check 'hub who' {
  if (-not (Test-Path -LiteralPath (Join-Path $HubRoot 'agents'))) { Add-Result 'hub who' 'WARN' "no hub folder $HubRoot (not calling hub.py: it would create it)"; return }
  $argv = $null; $hub = ''
  if ($Mesh -and $Mesh.python.Count -and $Mesh.python[0] -and $Mesh.hubPy) { $argv = @($Mesh.python | ForEach-Object { [string]$_ }); $hub = $Mesh.hubPy }
  elseif ($OnWindows) {
    $py = Get-Command 'py.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($py) {
      $r = Invoke-Fixed @($py.Path, '-3', '-c', 'import sys; print(sys.executable if sys.version_info >= (3, 8) else "")') 10
      $exe = ([string]$r.out).Trim(); if ($r.rc -eq 0 -and $exe -and (Test-Path -LiteralPath $exe)) { $argv = @($exe); $hub = $KitHubPy }
    }
    if (-not $argv) { $pc = Get-Command 'python.exe' -ErrorAction SilentlyContinue | Where-Object { $_.Path -notmatch '\\WindowsApps\\' } | Select-Object -First 1; if ($pc) { $argv = @($pc.Path); $hub = $KitHubPy } }
    if (-not $argv) { $w = Get-Command 'wsl.exe' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($w) { $argv = @($w.Path, '-e', 'python3'); $hub = ConvertTo-WslPath $KitHubPy } }
  } else { $p3 = Get-Command 'python3' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($p3) { $argv = @($p3.Path); $hub = $KitHubPy } }
  if (-not $argv) { Add-Result 'hub who' 'WARN' 'no python found to run hub.py'; return }
  $r = Invoke-Fixed (@($argv) + @($hub, 'who', '--json')) 15
  if ($r.rc -ne 0) { Add-Result 'hub who' 'WARN' ("hub.py who failed rc=$($r.rc): " + ([string]$r.err).Trim()); return }
  $parsed = ([string]$r.out).Trim() | ConvertFrom-Json   # PS 5.1 emits a JSON array as ONE object: unwrap it
  $rows = @(@($parsed) | Where-Object { $null -ne $_ })
  $up = @($rows | Where-Object { (Prop $_ 'state') -eq 'up' })
  $rem = @($up | Where-Object { Prop $_ 'mesh' }).Count
  $other = $rows.Count - $up.Count
  $names = (@($up | ForEach-Object { $a = Prop $_ 'addr'; if ($a) { $a } else { Prop $_ 'name' } }) -join ', ')
  $s = if ($up.Count) { 'OK' } else { 'WARN' }
  Add-Result 'hub who' $s ("$($up.Count) up ($($up.Count - $rem) here, $rem via mesh), $other not up" + $(if ($names) { ": $names" } else { '' }))
}

# ------------------------------------------------------------------ 3. ledger (sentinel)
Run-Check 'ledger' {
  $st = @(); $why = @(); $det = @()
  if ($null -ne $Tasks) {
    $t = @($Tasks | Where-Object { $_.path -eq '\AgentMesh\' -and $_.name -eq 'Agent-Sentinel' })
    if ($t.Count) { $why += "task $($t[0].state)" } else { $st += 'WARN'; $why += 'task \AgentMesh\Agent-Sentinel absent' }
  } else { $st += 'WARN'; $why += "task not checked ($TasksErr)" }
  if ($OnWindows) {
    try {
      $pr = Invoke-Bounded "@(Get-CimInstance Win32_Process -Filter `"CommandLine like '%ledger.py%watch%'`" -OperationTimeoutSec 10 -ErrorAction Stop | Where-Object { `$_.Name -match 'python' } | ForEach-Object { [int]`$_.ProcessId })" 15
      $pr = @($pr | Where-Object { $_ })
      if ($pr.Count) { $why += "process pid $($pr -join ',')" } else { $st += 'WARN'; $why += 'no ledger.py watch process' }
    } catch { $st += 'WARN'; $why += "process not checked ($($_.Exception.Message))" }
  } else { $st += 'WARN'; $why += 'process check needs Windows' }
  $sf = Join-Path $SentDir 'state.json'
  if (Test-Path -LiteralPath $sf) {
    $s = (Read-Shared $sf) | ConvertFrom-Json
    $nowEpoch = ([DateTimeOffset]::UtcNow).ToUnixTimeSeconds()
    $open = @(); $fps = Prop $s 'fps'
    if ($fps) { foreach ($p in $fps.PSObject.Properties) { $l = Prop $p.Value 'last'; if ($null -ne $l -and ($nowEpoch - [double]$l) -lt 1200) { $open += [string](Prop $p.Value 'cls') } } }
    if ($open.Count) { $st += 'WARN'; $why += "$($open.Count) open incident(s): " + (($open | Sort-Object -Unique) -join ',') } else { $why += '0 open incidents' }
    $cnt = @{}; if ($fps) { foreach ($p in $fps.PSObject.Properties) { $cnt[$p.Name] = Prop $p.Value 'count' } }
    $inc = Join-Path $SentDir 'incidents.jsonl'
    if (Test-Path -LiteralPath $inc) {
      foreach ($ln in @(Read-Tail $inc 32768 | Select-Object -Last 3)) {
        try {
          $j = $ln | ConvertFrom-Json; $c = $cnt[[string](Prop $j 'fp')]; if (-not $c) { $c = Prop $j 'count' }
          $ts = if ($ln -match '"ts_utc"\s*:\s*"([^"]*)"') { $Matches[1] } else { '?' }   # raw: PS 7 would turn it into a local date
          $det += ('{0} {1} {2} x{3}: {4}' -f $ts, (Prop $j 'cls'), (Prop $j 'file'), $c, (Prop $j 'evidence'))
        } catch { $det += 'unreadable incident line' }
      }
    }
  } else { $st += 'WARN'; $why += "no $sf" }
  Add-Result 'ledger' (Worst $st) ($why -join '; ') $det
}

# ------------------------------------------------------------------ 4. our scheduled tasks
Run-Check 'tasks' {
  if ($null -eq $Tasks) { Add-Result 'tasks' 'WARN' "not checked: $TasksErr"; return }
  $list = @($Tasks | Where-Object { $_ })
  if (-not $list.Count) { Add-Result 'tasks' 'WARN' 'no Shai-*, Gony-Herdr-Autostart, \AgentMesh\ or \AgentAdmin\ task visible'; return }
  foreach ($t in ($list | Sort-Object path, name)) {
    $st = @(); $why = @()
    if ($t.headless) { $why += 'conhost --headless' } else { $st += 'WARN'; $why += "action is $($t.exe), not conhost --headless" }
    if ($t.state -eq 'Running') { $why += 'running' }
    elseif ($null -eq $t.last) { $st += 'WARN'; $why += "state $($t.state), last result unknown" }
    elseif ($t.last -eq 0) { $why += "$($t.state), last result 0" }
    elseif ($t.last -eq 267011) { $st += 'WARN'; $why += "$($t.state), never run (0x41303)" }
    else { $st += 'WARN'; $why += ("{0}, last result 0x{1:X}" -f $t.state, $t.last) }
    if ($t.lastRun -and $t.lastRun.Year -gt 2000) { $why += 'ran ' + (Age ($Now - $t.lastRun).TotalSeconds) + ' ago' }
    Add-Result ("task " + $t.path.TrimStart('\') + $t.name) (Worst $st) ($why -join '; ')
  }
}

# ------------------------------------------------------------------ 5. admin-runner (reported, never judged)
Run-Check 'admin-runner' {
  if (-not (Test-Path -LiteralPath $AdminRoot)) { Add-Result 'admin-runner' 'WARN' "not installed (no $AdminRoot)"; return }
  $st = @(); $why = @()
  $pol = Join-Path $AdminRoot 'policy.json'
  if (Test-Path -LiteralPath $pol) {
    try { $pj = (Read-Shared $pol) | ConvertFrom-Json; $why += 'self_approve ' + $(if ([bool](Prop $pj 'self_approve')) { 'on' } else { 'off' }) }
    catch { $st += 'WARN'; $why += 'policy.json unreadable' }
  } else { $why += 'self_approve off (no policy.json)' }
  $aud = Join-Path $AdminRoot 'audit.log'
  if (Test-Path -LiteralPath $aud) {
    $ran = @(Read-Tail $aud 131072 | Where-Object { $_ -match '^\S+ id=\S+ sha8=\S* by=.* RAN status=' }) | Select-Object -Last 1
    if ($ran -and $ran -match '^(\S+) id=(\S+) .* RAN (status=\S+ exit=\S+)') {
      $ago = ''; try { $ago = ' (' + (Age ($NowUtc - [DateTime]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal)).TotalSeconds) + ' ago)' } catch {}
      $why += "last RAN $($Matches[1].Substring(0, [Math]::Min(19, $Matches[1].Length)))$ago $($Matches[3])"
    } else { $why += 'no RAN line in audit.log' }
  } else { $why += 'no audit.log yet' }
  $con = Join-Path $AdminRoot 'CONTRACT.md'
  if (Test-Path -LiteralPath $con) { $why += 'CONTRACT ' + (Sha8 $con) } else { $st += 'WARN'; $why += 'no CONTRACT.md' }
  Add-Result 'admin-runner' (Worst $st) ($why -join '; ')
}

# ------------------------------------------------------------------ 6. WSL side (best effort, 10 s each)
$Wsl = $null
if ($OnWindows) { $Wsl = Get-Command 'wsl.exe' -ErrorAction SilentlyContinue | Select-Object -First 1 }
$WslWhy = if ($OnWindows) { 'wsl.exe not found' } else { 'wsl.exe needs Windows' }
Run-Check 'wsl bridge' {
  if (-not $Wsl) { Add-Result 'wsl bridge' 'WARN' $WslWhy; return }
  # one line, no double quotes (it travels as one argv element); agent-bridg[e] keeps pgrep from matching this sh itself
  $sh = 'for d in $HOME/.agent-bridge $HOME/herdr-gony-ws; do if [ -f $d/agent-bridge.pid ]; then p=$(cat $d/agent-bridge.pid); ' +
    'if kill -0 $p 2>/dev/null; then echo PID $p alive; else echo PID $p dead; fi; break; fi; done; ' +
    'if pgrep -f agent-bridg[e].py >/dev/null 2>&1; then echo PGREP yes; else echo PGREP no; fi; ' +
    'for L in $HOME/.agent-bridge/agent-bridge.log $HOME/herdr-gony-ws/agent-bridge.log; do ' +
    'if [ -f $L ]; then echo LOG $L; grep -a ''START bridge'' $L | tail -n 1; break; fi; done'
  $r = Invoke-Fixed @($Wsl.Path, '-e', 'sh', '-c', $sh) 10
  if ($r.rc -ne 0 -and -not ([string]$r.out).Trim()) { Add-Result 'wsl bridge' 'WARN' ("wsl.exe rc=$($r.rc): " + ([string]$r.err).Trim()); return }
  $lines = @(([string]$r.out) -split "`r?`n" | Where-Object { $_ })
  $pidl = $lines | Where-Object { $_ -match '^PID ' } | Select-Object -First 1
  $pg = [bool]($lines | Where-Object { $_ -eq 'PGREP yes' })
  $start = $lines | Where-Object { $_ -match 'START bridge' } | Select-Object -Last 1
  $st = @(); $why = @()
  if ($pidl -match '^PID (\d+) alive') { $why += "bridge pid $($Matches[1]) alive" }
  elseif ($pg) { $st += 'WARN'; $why += 'agent-bridge.py runs, but its pid file is missing or stale' }
  else { $st += 'FAIL'; $why += $(if ($pidl) { 'bridge ' + $pidl.Substring(4) } else { 'no bridge pid file, no agent-bridge.py process' }) }
  # route maps are not shown: the START line is cut to its time and what happened
  if ($start -and $start -match '^(\S+) START bridge (pid \d+ (started|already runs))') { $why += "last START $($Matches[1]): $($Matches[2])" }
  elseif ($start) { $why += 'last START: ' + ($start -replace '(started|routes):.*$', '$1') }
  else { $st += 'WARN'; $why += 'no START bridge line in agent-bridge.log' }
  Add-Result 'wsl bridge' (Worst $st) ($why -join '; ')
}
Run-Check 'wsl herdr' {
  if (-not $Wsl) { Add-Result 'wsl herdr' 'WARN' $WslWhy; return }
  $sh = 'PATH=$HOME/.local/bin:$HOME/.cargo/bin:$HOME/bin:/usr/local/bin:$PATH; herdr --session gony pane list 2>&1'
  $r = Invoke-Fixed @($Wsl.Path, '-e', 'sh', '-c', $sh) 10
  $o = ([string]$r.out).Trim()
  $labels = @()
  try { $j = $o | ConvertFrom-Json; $labels = @((Prop (Prop $j 'result') 'panes') | ForEach-Object { [string](Prop $_ 'label') }) } catch {
    $labels = @([regex]::Matches($o, '"label"\s*:\s*"([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
  }
  if ($r.rc -ne 0 -and -not $labels.Count) { Add-Result 'wsl herdr' 'WARN' ("herdr session gony: rc=$($r.rc) " + $(if ($o) { $o } else { ([string]$r.err).Trim() })); return }
  if (-not $labels.Count) { Add-Result 'wsl herdr' 'WARN' ('herdr session gony: no panes listed ' + $o); return }
  $named = @($labels | ForEach-Object { if ($_) { $_ } else { '(none)' } })
  Add-Result 'wsl herdr' 'OK' ("session gony, $($labels.Count) pane(s): " + ($named -join ', '))
}

# ------------------------------------------------------------------ 7. disk + clock
Run-Check 'disk C:' {
  if (-not $OnWindows) { Add-Result 'disk C:' 'WARN' 'no drive C: (not Windows)'; return }
  $d = New-Object IO.DriveInfo('C')
  if (-not $d.IsReady) { Add-Result 'disk C:' 'WARN' 'drive C: not ready'; return }
  $gb = [Math]::Round($d.AvailableFreeSpace / 1GB, 1); $tot = [Math]::Round($d.TotalSize / 1GB, 0)
  $s = if ($gb -lt 15) { 'FAIL' } elseif ($gb -lt 30) { 'WARN' } else { 'OK' }
  Add-Result 'disk C:' $s "$gb GB free of $tot GB (WARN < 30, FAIL < 15)"
}
Run-Check 'clock' {
  if (-not $Wsl) { Add-Result 'clock' 'WARN' ("WSL vs Windows not compared: " + $WslWhy); return }
  $t0 = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
  $r = Invoke-Fixed @($Wsl.Path, '-e', 'date', '+%s.%N') 10
  $t1 = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0
  $w = 0.0
  if ($r.rc -ne 0 -or -not [double]::TryParse(([string]$r.out).Trim(), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$w)) {
    Add-Result 'clock' 'WARN' ("WSL date failed rc=$($r.rc): " + ([string]$r.err).Trim()); return
  }
  $off = $w - ($t0 + $t1) / 2; $unc = ($t1 - $t0) / 2
  $s = if ([Math]::Abs($off) - $unc -gt 5) { 'WARN' } else { 'OK' }
  Add-Result 'clock' $s ('WSL - Windows = {0:+0.0;-0.0} s (+/- {1:0.0} s; WARN > 5 s)' -f $off, $unc)
}

# ------------------------------------------------------------------ report
$nF = @($Results | Where-Object { $_.status -eq 'FAIL' }).Count
$nW = @($Results | Where-Object { $_.status -eq 'WARN' }).Count
$nO = @($Results | Where-Object { $_.status -eq 'OK' }).Count
$verdict = if ($nF) { 'FAIL' } elseif ($nW) { 'WARN' } else { 'OK' }
$code = if ($nF) { 2 } elseif ($nW) { 1 } else { 0 }
$hostName = Safe-Text ([Environment]::MachineName) 40
if ($Json) {
  [pscustomobject]@{ host = $hostName; at = $NowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'); verdict = $verdict; exit = $code
    ok = $nO; warn = $nW; fail = $nF; checks = @($Results) } | ConvertTo-Json -Depth 5
} else {
  Write-Output ('agent health  {0}  {1}  (read-only)' -f $hostName, $Now.ToString('yyyy-MM-dd HH:mm:ss'))
  foreach ($r in $Results) {
    Write-Output ('{0,-4} {1,-26} {2}' -f $r.status, $r.check, $r.reason)
    foreach ($d in $r.details) { Write-Output ('     {0,-26} {1}' -f '', $d) }
  }
  Write-Output ('VERDICT {0}: {1} ok, {2} warn, {3} fail' -f $verdict, $nO, $nW, $nF)
}
exit $code
