<#
.SYNOPSIS
  mesh-setup.ps1 - owner-run setup for "your own network" of agent hubs (PRESENCE.md option c).
  Agents on Windows, WSL and your other computers see each other ("who") and message by @name.

.DESCRIPTION
  Shape: a star. One MAIN PC runs one Agent Tunnel listener per extra machine. Every extra
  machine joins its listener. On every PC, one hub link per tunnel bridges the tunnel into the
  local hub folder (%USERPROFILE%\.agent-hub), which Windows and WSL agents share.

  Messages and files only. This script starts the p2p tunnel daemon and the hub link, and keeps
  them alive. It never reads, runs or interprets message text. It never runs anything remote.
  Nothing happens unless you run it yourself with one of the modes below.

  Each hub link trusts the far machine it meets first (its tunnel key and hub id are pinned in
  .agent-hub\uplinks\<link>.pin.json). If another machine shows up on that tunnel later, the link
  holds (who shows it as peer-changed) until you run: hub.py unpin <link>. -Uninstall unpins.

  MODES (pick one)
    -Machines laptop,pc2 -MainName desktop
                 MAIN PC: one listener per extra machine; prints one join line per machine
    -Join <KEY> -MainName desktop -Name laptop
                 EXTRA PC: join the main PC with the line the main PC printed
    -Status      show links, keepers, tunnels, autostart entries (read-only; with -WhatIf it only
                 prints the tunnel status command instead of running it)
    -Uninstall [-Link name]
                 remove exactly what this script added (all links, or just one)
    -Keep -Link name
                 the keeper loop itself (what the logon task runs)
    -Restart -Link name
                 restart one keeper safely: stop request, wait, start it again through its task
                 (never Stop-ScheduledTask alone: it can leave the old keeper running)

  OPTIONS
    -MainName name     what the extra machines call the main PC (default: main). On the MAIN PC it
                       is also the main PC's own name in every hub's "who".
    -Name name         EXTRA PC only: this machine's name (default: host name). The main PC's join
                       line fills it in with the name you gave in -Machines.
    -Autostart Task    (default) a Scheduled Task per link: current user, at logon, not elevated
    -Autostart Startup a .cmd in your Startup folder instead (use if Task registration is refused)
    -Autostart None    no autostart; run -Keep -Link name yourself
    -P2P path          the p2p launcher (default %USERPROFILE%\.local\bin\p2p.cmd)
    -Python path       python.exe to run hub.py (default: py -3's interpreter, else python.exe,
                       else WSL's python3 through wsl.exe with --wsl-interop)
    -HubVerb auto      auto | link | uplink. auto uses "hub.py link" when hub.py has it, else "uplink"
    -WhatIf            dry run: print every step and every command, change nothing, run nothing

  FILES IT ADDS (and -Uninstall removes)
    %USERPROFILE%\.agent-mesh\mesh.json            links and how to run them; it holds each link's tunnel
                                                   key (the join line): keep it private like a password
    %USERPROFILE%\.agent-mesh\logs\<link>.*.log    keeper + hub link logs
    %USERPROFILE%\.agent-mesh\run\<link>.*      keeper bookkeeping (pid, lock, stop)
    Task Scheduler \AgentMesh\AgentMesh-<link>     or Startup\AgentMesh-<link>.cmd
    p2p tunnel sessions mesh-<link>                stopped on uninstall (history files are kept)
  It never deletes p2p identity keys (%USERPROFILE%\.p2p\...): keeping them keeps your keys stable.

  Windows PowerShell 5.1 and PowerShell 7. Meant to need no admin rights; if Task Scheduler
  refuses the task, rerun with -Autostart Startup.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\mesh-setup.ps1 -Machines laptop -MainName desktop
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\mesh-setup.ps1 -Join ABCDEFGHJKMNPQRSTVWXYZ0123 -MainName desktop -Name laptop
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string[]]$Machines = @(),
  [string]$Join = '',
  [string]$MainName = 'main',
  [string]$Name = '',
  [switch]$Status,
  [switch]$Uninstall,
  [switch]$Keep,
  [switch]$Restart,
  [string]$Link = '',
  [ValidateSet('Task', 'Startup', 'None')][string]$Autostart = 'Task',
  [string]$P2P = '',
  [string]$Python = '',
  [ValidateSet('auto', 'link', 'uplink')][string]$HubVerb = 'auto'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$Utf8 = New-Object Text.UTF8Encoding($false)
try { [Console]::OutputEncoding = $Utf8 } catch {}

$DryRun = [bool]$WhatIfPreference
$OnWindows = ($PSVersionTable.PSVersion.Major -le 5) -or ((Test-Path variable:IsWindows) -and $IsWindows)
$UserHome = [Environment]::GetFolderPath('UserProfile')
$StateDir = if ($env:AGENT_MESH_HOME) { $env:AGENT_MESH_HOME } else { Join-Path $UserHome '.agent-mesh' }
$ConfigPath = Join-Path $StateDir 'mesh.json'
$LogDir = Join-Path $StateDir 'logs'
$RunDir = Join-Path $StateDir 'run'
$Marker = 'agent-mesh: added by mesh-setup.ps1; remove with mesh-setup.ps1 -Uninstall'
$TaskPath = '\AgentMesh\'
$NameRe = '^[A-Za-z0-9][A-Za-z0-9-]{0,30}$'
$KitRoot = Split-Path $PSScriptRoot -Parent
$HubPy = Join-Path (Join-Path $KitRoot 'hub') 'hub.py'
$Self = $PSCommandPath

# ------------------------------------------------------------------ small helpers
# Write-Host, not the pipeline: functions here also return values, and status text must never mix into them.
function Say([string]$s) { Write-Host $s }
function Plan([string]$s) { Write-Host ('WHATIF: ' + $s) }

function Check-Name([string]$n, [string]$what) {
  if ($n -notmatch $NameRe -or $n -eq 'all') { throw "bad $what name '$n': letters, digits and - only, max 31, not 'all' (e.g. laptop)" }
  $n.ToLowerInvariant()
}

# Windows command-line quoting (CommandLineToArgvW rules), so every argv element arrives intact.
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
function Join-Args([string[]]$argv) { (@($argv) | ForEach-Object { Format-Arg $_ }) -join ' ' }
function Show-Argv([string[]]$argv) { Join-Args $argv }

# Kill a process and its children (p2p.cmd -> node); Kill() alone stops only cmd.exe and leaves node holding the pipes.
function Stop-Tree($p) {
  $ErrorActionPreference = 'Continue'   # PS 5.1: native stderr under 'Stop' would end taskkill's output early
  $tk = Join-Path ([string]$env:SystemRoot) 'System32\taskkill.exe'
  if ($OnWindows) { try { & $tk /PID $p.Id /T /F 2>&1 | Out-Null } catch {} }
  try { if (-not $p.HasExited) { $p.Kill() } } catch {}
  try { [void]$p.WaitForExit(5000) } catch {}
}

# Run one fixed argv, capture output, never through a shell string we build from data.
function Invoke-Fixed([string[]]$argv, [int]$TimeoutSec = 60) {
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $argv[0]
  $psi.Arguments = Join-Args @($argv | Select-Object -Skip 1)
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
  try { $psi.StandardOutputEncoding = $Utf8; $psi.StandardErrorEncoding = $Utf8 } catch {}
  $p = New-Object Diagnostics.Process; $p.StartInfo = $psi
  try { [void]$p.Start() } catch { return [pscustomobject]@{ rc = 127; out = ''; err = $_.Exception.Message } }
  $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    Stop-Tree $p
    return [pscustomobject]@{ rc = 124; out = ''; err = 'timeout' }
  }
  $p.WaitForExit()
  $out = ''; $err = ''
  if ($o.Wait(5000)) { $out = $o.Result }; if ($e.Wait(5000)) { $err = $e.Result }
  [pscustomobject]@{ rc = $p.ExitCode; out = $out; err = $err }
}

$ReplaceTries = 20   # = hub.py REPLACE_TRIES
function Write-Atomic([string]$path, [string]$text) {
  $dir = Split-Path $path -Parent; [void][IO.Directory]::CreateDirectory($dir)
  $tmp = Join-Path $dir ('.tmp-' + [Guid]::NewGuid().ToString('N'))
  [IO.File]::WriteAllText($tmp, $text, $Utf8)
  # Not Move-Item -Force: on PS 5.1 that deletes the target, then renames (readers see it missing), and the delete
  # fails while a reader (keeper, status, hub.py) has the file open. Replace it in place and retry those sharing
  # violations for ~1 s, then clean up, as hub/hub.ps1 Write-Atomic does. ([NullString]: PS turns $null into ''.)
  for ($i = 1; ; $i++) {
    try {
      if ([IO.File]::Exists($path)) { [IO.File]::Replace($tmp, $path, [NullString]::Value) } else { [IO.File]::Move($tmp, $path) }
      return
    } catch {
      $e = $_; $c = Win32-Code $e   # 5/32: open elsewhere; 2: target just removed; 80/183: target just created;
      # 1176/1177: Replace moved the target away but kept the tmp, so the next try Moves the tmp into place
      if ($i -ge $ReplaceTries -or @(2, 5, 32, 80, 183, 1175, 1176, 1177) -notcontains $c) { try { [IO.File]::Delete($tmp) } catch {}; throw $e }
      Start-Sleep -Milliseconds 50
    }
  }
}
function Win32-Code($err) { $e = $err.Exception; while ($e.InnerException) { $e = $e.InnerException }; $e.HResult -band 0xFFFF }

# PS 5.1 has no ConvertFrom-Json -AsHashtable.
function ConvertTo-Hash($o) {
  if ($null -eq $o) { return $null }
  if ($o -is [System.Management.Automation.PSCustomObject]) {
    $h = [ordered]@{}; foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = ConvertTo-Hash $p.Value }; return $h
  }
  if ($o -is [System.Collections.IEnumerable] -and $o -isnot [string]) { return ,@(@($o) | ForEach-Object { ConvertTo-Hash $_ }) }
  $o
}
function Load-Config {
  if (-not (Test-Path -LiteralPath $ConfigPath)) { return [ordered]@{ v = 1; links = [ordered]@{} } }
  $c = ConvertTo-Hash ([IO.File]::ReadAllText($ConfigPath, $Utf8) | ConvertFrom-Json)
  if (-not $c.Contains('links') -or $null -eq $c.links) { $c.links = [ordered]@{} }
  $c
}
function Save-Config($c) { Write-Atomic $ConfigPath ($c | ConvertTo-Json -Depth 8) }

function Log-Line([string]$link, [string]$s) {
  $line = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + '  ' + $s
  Write-Host $line
  try {
    [void][IO.Directory]::CreateDirectory($LogDir)
    $f = Join-Path $LogDir ($link + '.keeper.log')
    # Rotate to <link>.keeper.prev.log (the name sentinel/ledger.py treats as rotation, not a log_reset; mtime set so it
    # counts as fresh). A reader holding the file can block the rename: then keep appending and retry on the next line.
    if ((Test-Path -LiteralPath $f) -and (Get-Item -LiteralPath $f).Length -gt 2MB) {
      $prev = Join-Path $LogDir ($link + '.keeper.prev.log')
      try { Move-Item -LiteralPath $f -Destination $prev -Force; [IO.File]::SetLastWriteTimeUtc($prev, [DateTime]::UtcNow); $script:KeeperRotateNoted = $false }
      catch {   # note it once per stuck stretch, not on every line (StrictMode: the flag may not exist yet)
        if (-not (Get-Variable -Scope Script -Name KeeperRotateNoted -ValueOnly -ErrorAction SilentlyContinue)) {
          $script:KeeperRotateNoted = $true; $line += "  (log rotation postponed: $($_.Exception.Message))" }
      }
    }
    # Another process (e.g. a WSL tail on /mnt/c) can hold the file for a moment: retry, then say so on stderr.
    for ($i = 0; ; $i++) {
      try { [IO.File]::AppendAllText($f, $line + [Environment]::NewLine, $Utf8); break }
      catch { if ($i -ge 4) { throw }; Start-Sleep -Milliseconds 200 }
    }
  } catch { [Console]::Error.WriteLine("keeper log write failed ($($_.Exception.Message)): $line") }
}

# ------------------------------------------------------------------ tools: p2p and python
function Get-P2PArgv {
  if ($P2P) { return ,@($P2P) }
  ,@((Join-Path (Join-Path (Join-Path $UserHome '.local') 'bin') 'p2p.cmd'))
}
function Test-P2P([string[]]$argv) {
  if (Test-Path -LiteralPath $argv[0]) { return $true }
  [bool](Get-Command $argv[0] -ErrorAction SilentlyContinue)
}
function ConvertTo-WslPath([string]$p) {
  # Assumes WSL's default automount root /mnt (C:\x\y -> /mnt/c/x/y).
  if ($p -match '^([A-Za-z]):\\(.*)$') { return '/mnt/' + $Matches[1].ToLowerInvariant() + '/' + ($Matches[2] -replace '\\', '/') }
  $p
}
# Returns @{ argv = python argv; hub = hub.py path as that python sees it; wsl = bool }.
function Resolve-Python {
  if ($Python) { return @{ argv = @($Python); hub = $HubPy; wsl = $false } }
  if ($OnWindows) {
    $py = Get-Command 'py.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($py) {
      # Store the real interpreter, not the py launcher, so the keeper stops the right process.
      $r = Invoke-Fixed @($py.Path, '-3', '-c', 'import sys; print(sys.executable if sys.version_info >= (3, 8) else "")') 30
      $exe = ([string]$r.out).Trim()
      if ($r.rc -eq 0 -and $exe -and (Test-Path -LiteralPath $exe)) { return @{ argv = @($exe); hub = $HubPy; wsl = $false } }
    }
    $pc = Get-Command 'python.exe' -ErrorAction SilentlyContinue | Where-Object { $_.Path -notmatch '\\WindowsApps\\' } | Select-Object -First 1
    if ($pc) { return @{ argv = @($pc.Path); hub = $HubPy; wsl = $false } }
    $w = Get-Command 'wsl.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($w) { return @{ argv = @($w.Path, '-e', 'python3'); hub = (ConvertTo-WslPath $HubPy); wsl = $true } }
    throw 'no Python found: install Python 3 (py -3) or WSL with python3, or pass -Python C:\path\python.exe'
  }
  $p3 = Get-Command 'python3' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($p3) { return @{ argv = @($p3.Path); hub = $HubPy; wsl = $false } }
  throw 'no python3 found; pass -Python /path/to/python3'
}
function Describe-Python {
  if ($Python) { return $Python }
  if ($OnWindows) {
    if (Get-Command 'py.exe' -ErrorAction SilentlyContinue) { return '<python.exe that py -3 resolves to>' }
    if (Get-Command 'python.exe' -ErrorAction SilentlyContinue) { return 'python.exe' }
    return 'wsl.exe -e python3 (hub link with --wsl-interop)'
  }
  'python3'
}

# ------------------------------------------------------------------ tunnel
function Get-TunnelStatus($cfg, [string]$session) {
  $r = Invoke-Fixed (@($cfg.p2p) + @('tunnel', 'status', '--name', $session)) 30
  $st = $null
  try { $st = ([string]$r.out).Trim() | ConvertFrom-Json } catch {}
  [pscustomobject]@{ rc = $r.rc; alive = ($r.rc -eq 0); connected = [bool]($st -and $st.PSObject.Properties['connected'] -and $st.connected); key = $(if ($st -and $st.PSObject.Properties['self']) { [string]$st.self } else { '' }); err = ([string]$r.err).Trim() }
}
function Start-Tunnel($cfg, $l) {
  if ($l.role -eq 'listen') {
    $argv = @($cfg.p2p) + @('tunnel', 'listen', '--name', $l.session, '--profile', $l.profile)
  } else {
    # First line asks the main hub for its roster (answered automatically, delivered to no agent).
    $argv = @($cfg.p2p) + @('tunnel', 'join', $l.key, '--name', $l.session, '--profile', $l.profile, '--say', 'WHO?', '--connect-timeout', '30')
  }
  Invoke-Fixed $argv 90
}
function Stop-Tunnel($cfg, [string]$session) { Invoke-Fixed (@($cfg.p2p) + @('tunnel', 'stop', '--name', $session)) 30 }

# ------------------------------------------------------------------ hub link child process
function Get-HubVerb($cfg) {
  if ($cfg.hubVerb -ne 'auto') { return $cfg.hubVerb }
  $r = Invoke-Fixed (@($cfg.python) + @($cfg.hubPy, 'link', '--help')) 60
  if ($r.rc -eq 0) { 'link' } else { 'uplink' }
}
function Get-HubArgv($cfg, $l, [string]$verb) {
  $a = @($cfg.python) + @($cfg.hubPy, $verb, '--session', $l.session, '--as', $l.as)
  if ($verb -eq 'link' -and $l.self) { $a += @('--label', $l.self) }   # this machine's name in the other hubs' who
  if ($cfg.wsl) { $a += '--wsl-interop' }
  elseif ($cfg.Contains('p2pCustom') -and $cfg.p2pCustom) { $a += @('--p2p', $cfg.p2p[0]) }   # same launcher as the keeper
  ,$a
}
function Start-HubChild([string[]]$argv, [string]$link) {
  [void][IO.Directory]::CreateDirectory($LogDir)
  $out = Join-Path $LogDir ($link + '.hub.log'); $err = Join-Path $LogDir ($link + '.hub.err.log')
  # Each start truncates the logs: keep the last 5 runs as *.prev.log, *.prev.2.log .. *.prev.5.log (newest first),
  # so a link exit can still be diagnosed after a few more restarts.
  foreach ($f in @($out, $err)) {
    if (Test-Path -LiteralPath $f) {
      try {
        $base = $f -replace '\.log$', ''
        for ($i = 4; $i -ge 1; $i--) {
          $from = if ($i -eq 1) { "$base.prev.log" } else { "$base.prev.$i.log" }
          if (Test-Path -LiteralPath $from) { Move-Item -LiteralPath $from -Destination "$base.prev.$($i + 1).log" -Force }
        }
        Move-Item -LiteralPath $f -Destination "$base.prev.log" -Force
      }
      catch { Log-Line $link "could not keep $f as .prev.log ($($_.Exception.Message)); it is overwritten" }
    }
  }
  $sp = @{ FilePath = $argv[0]; PassThru = $true; RedirectStandardOutput = $out; RedirectStandardError = $err }
  $rest = @($argv | Select-Object -Skip 1)
  if ($rest.Count) { $sp.ArgumentList = (Join-Args $rest) }
  if ($OnWindows) { $sp.WindowStyle = 'Hidden' }
  $p = Start-Process @sp
  # PS 5.1: ExitCode reads blank later unless the handle is opened while the process runs.
  if ($p) { $null = $p.Handle }
  $p
}

# ------------------------------------------------------------------ keeper control
# Ask a running keeper to stop (it stops its hub link and says bye), and wait until it has.
function Stop-Keeper([string]$name) {
  $stop = Join-Path $RunDir ($name + '.stop'); $pidFile = Join-Path $RunDir ($name + '.pid')
  if ($DryRun) { Plan "ask the keeper to stop: create $stop, wait up to 20 s for $pidFile to go"; return }
  if (-not (Test-Path -LiteralPath $pidFile)) { Say '  keeper: not running'; return }
  Write-Atomic $stop 'stop'
  $end = [DateTime]::UtcNow.AddSeconds(20)
  while ((Test-Path -LiteralPath $pidFile) -and [DateTime]::UtcNow -lt $end) { Start-Sleep -Milliseconds 500 }
  if (Test-Path -LiteralPath $pidFile) { Say '  keeper did not confirm within 20 s (it may have been killed earlier)' } else { Say '  keeper stopped' }
}
# A keeper that was killed outright (task stopped, crash) leaves its hub link running. The next keeper
# stops that one process, identified by pid AND start time, before it starts a new link.
function Stop-OrphanLink([string]$name) {
  $cf = Join-Path $RunDir ($name + '.child')
  if (-not (Test-Path -LiteralPath $cf)) { return }
  $parts = @(([IO.File]::ReadAllText($cf)).Trim() -split ' ')
  Remove-Item -LiteralPath $cf -Force -ErrorAction SilentlyContinue
  if ($parts.Count -ne 2) { return }
  $p = Get-Process -Id ([int]$parts[0]) -ErrorAction SilentlyContinue
  if (-not $p) { return }
  try { $same = [Math]::Abs($p.StartTime.ToUniversalTime().Ticks - [long]$parts[1]) -lt 20000000 } catch { $same = $false }
  if ($same) { try { $p.Kill(); Log-Line $name "stopped a hub link left over from an earlier keeper (pid $($parts[0]))" } catch {} }
}

# ------------------------------------------------------------------ autostart
function Get-UserId {
  $d = [Environment]::UserDomainName; $u = [Environment]::UserName
  if ($d) { "$d\$u" } else { $u }
}
function Get-KeeperArgs([string]$link) {
  @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', $Self, '-Keep', '-Link', $link)
}
function Get-StartupFile([string]$link) {
  $dir = [Environment]::GetFolderPath('Startup')
  if (-not $dir) { $dir = Join-Path $StateDir 'startup' }   # non-Windows test hosts only
  Join-Path $dir ('AgentMesh-' + $link + '.cmd')
}
function Install-Autostart([string]$link, [string]$mode) {
  $taskName = 'AgentMesh-' + $link
  $psArgs = Get-KeeperArgs $link
  if ($mode -eq 'Task') {
    $line = Join-Args $psArgs
    # Win11's default terminal (Windows Terminal) ignores -WindowStyle Hidden and leaves an empty window open.
    # conhost.exe --headless (Windows 10 1903+) runs the keeper without any window.
    $exe = 'powershell.exe'
    $conhost = Join-Path ([string]$env:SystemRoot) 'System32\conhost.exe'
    if ($OnWindows -and [Environment]::OSVersion.Version.Build -ge 18362 -and (Test-Path -LiteralPath $conhost)) {
      $exe = $conhost; $line = '--headless powershell.exe ' + $line
    }
    if ($DryRun) {
      Plan "register Scheduled Task $TaskPath$taskName (user $(Get-UserId), at logon, RunLevel Limited, no time limit, restart every 1 min on failure)"
      Plan "  action: $exe $line"
      Plan "  start it now: Start-ScheduledTask -TaskPath $TaskPath -TaskName $taskName"
      return @{ kind = 'task'; name = $taskName; path = $TaskPath }
    }
    $old = Get-ScheduledTask -TaskPath $TaskPath -TaskName $taskName -ErrorAction SilentlyContinue
    if ($old -and ([string]$old.Description) -ne $Marker) { throw "a task $TaskPath$taskName exists that this script did not add; not touching it" }
    $user = Get-UserId
    $action = New-ScheduledTaskAction -Execute $exe -Argument $line -WorkingDirectory $KitRoot
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
      -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    try {
      [void](Register-ScheduledTask -TaskPath $TaskPath -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description $Marker -Force)
    } catch {
      throw ("Task Scheduler refused the task ($($_.Exception.Message)). Rerun the same command with -Autostart Startup.")
    }
    Say "  autostart: Scheduled Task $TaskPath$taskName (at logon, not elevated)"
    Start-ScheduledTask -TaskPath $TaskPath -TaskName $taskName
    Say "  started:   $TaskPath$taskName"
    return @{ kind = 'task'; name = $taskName; path = $TaskPath }
  }
  if ($mode -eq 'Startup') {
    $f = Get-StartupFile $link
    $selfRef = $Self
    if ($selfRef.StartsWith($UserHome + '\', [StringComparison]::OrdinalIgnoreCase)) { $selfRef = '%USERPROFILE%' + $selfRef.Substring($UserHome.Length) }
    $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', $selfRef, '-Keep', '-Link', $link)
    $body = "@echo off`r`nrem $Marker`r`nstart `"`" /min powershell.exe " + (Join-Args $psArgs) + "`r`n"
    if ($DryRun) { Plan "write $f :"; ($body -split "`r`n") | Where-Object { $_ } | ForEach-Object { Plan "  $_" }; return @{ kind = 'startup'; file = $f } }
    if ((Test-Path -LiteralPath $f) -and -not ([IO.File]::ReadAllText($f).Contains($Marker))) { throw "$f exists and was not added by this script; not touching it" }
    Write-Atomic $f $body
    Say "  autostart: $f"
    if ($OnWindows) {
      $p = Start-Process -FilePath 'powershell.exe' -ArgumentList (Join-Args @($psArgs | ForEach-Object { $_.Replace('%USERPROFILE%', $UserHome) })) -WindowStyle Hidden -PassThru
      Say "  started:   keeper pid $($p.Id)"
    }
    return @{ kind = 'startup'; file = $f }
  }
  if ($DryRun) { Plan "no autostart for $link; run it yourself: powershell $(Join-Args (@('-NoProfile','-ExecutionPolicy','Bypass','-File',$Self,'-Keep','-Link',$link)))" }
  else { Say "  autostart: none. Run the keeper yourself: powershell -NoProfile -ExecutionPolicy Bypass -File $(Format-Arg $Self) -Keep -Link $link" }
  @{ kind = 'none' }
}
function Remove-Autostart($a) {
  if (-not $a -or $a.kind -eq 'none') { return }
  if ($a.kind -eq 'task') {
    if ($DryRun) { Plan "stop and unregister Scheduled Task $($a.path)$($a.name) (only if its description is this script's marker)"; return }
    $t = Get-ScheduledTask -TaskPath $a.path -TaskName $a.name -ErrorAction SilentlyContinue
    if (-not $t) { Say "  task $($a.path)$($a.name): already gone"; return }
    if (([string]$t.Description) -ne $Marker) { Say "  task $($a.path)$($a.name): not ours (description differs); left alone"; return }
    try { Stop-ScheduledTask -TaskPath $a.path -TaskName $a.name } catch {}
    Unregister-ScheduledTask -TaskPath $a.path -TaskName $a.name -Confirm:$false
    Say "  removed task $($a.path)$($a.name)"
  } elseif ($a.kind -eq 'startup') {
    if ($DryRun) { Plan "delete $($a.file) (only if it carries this script's marker)"; return }
    if (-not (Test-Path -LiteralPath $a.file)) { Say "  $($a.file): already gone"; return }
    if (-not ([IO.File]::ReadAllText($a.file).Contains($Marker))) { Say "  $($a.file): not ours; left alone"; return }
    Remove-Item -LiteralPath $a.file -Force
    Say "  removed $($a.file)"
  }
}

# ------------------------------------------------------------------ setup (main or extra PC)
function Get-BaseConfig {
  $c = Load-Config
  if ($DryRun) {
    $c.p2p = @(Get-P2PArgv); $c.python = @(Describe-Python); $c.hubPy = $HubPy; $c.wsl = $false; $c.hubVerb = $HubVerb
    $c.p2pCustom = [bool]$P2P
    return $c
  }
  $c.p2p = @(Get-P2PArgv)
  if (-not (Test-P2P $c.p2p)) {
    throw ("p2p launcher not found at $($c.p2p[0]). Install the Agent Tunnel CLI first:" + [Environment]::NewLine +
      '  irm https://p2p.akeyo.io/init.ps1 | iex' + [Environment]::NewLine + 'or pass -P2P <path>.')
  }
  if (-not (Test-Path -LiteralPath $HubPy)) { throw "hub.py not found at $HubPy (run this script from the kit's windows folder)" }
  $py = Resolve-Python
  $c.python = @($py.argv); $c.hubPy = $py.hub; $c.wsl = [bool]$py.wsl; $c.hubVerb = $HubVerb; $c.p2pCustom = [bool]$P2P
  $c
}

function Add-Link($cfg, $l) {
  $name = $l.link
  $existing = $null; if ($cfg.links.Contains($name)) { $existing = $cfg.links[$name] }
  if ($existing -and $existing.role -ne $l.role) { throw "link '$name' already exists as a $($existing.role) link; run -Uninstall -Link $name first" }
  if ($existing -and $existing.Contains('autostart')) { $l.autostart = $existing.autostart }
  Say ''
  Say "== link $name ($($l.role)): tunnel $($l.session), hub name @$($l.as)"
  if ($DryRun) {
    Plan "check: $(Show-Argv (@($cfg.p2p) + @('tunnel','status','--name',$l.session)))"
    if ($l.role -eq 'listen') { Plan "if not running: $(Show-Argv (@($cfg.p2p) + @('tunnel','listen','--name',$l.session,'--profile',$l.profile)))" }
    else { Plan "if not running: $(Show-Argv (@($cfg.p2p) + @('tunnel','join',$l.key,'--name',$l.session,'--profile',$l.profile,'--say','WHO?','--connect-timeout','30')))" }
    $verb = if ($cfg.hubVerb -eq 'auto') { 'link' } else { $cfg.hubVerb }
    Plan "keeper runs: $(Show-Argv (Get-HubArgv $cfg $l $verb))$(if ($cfg.hubVerb -eq 'auto') { '   (uplink instead if this hub.py has no link verb)' })"
    Plan "save link '$name' to $ConfigPath"
  } else {
    $st = Get-TunnelStatus $cfg $l.session
    if ($st.alive) { Say "  tunnel $($l.session): already running (connected=$($st.connected))" }
    else {
      $r = Start-Tunnel $cfg $l
      if ($r.rc -eq 0) { Say "  tunnel $($l.session): started" }
      elseif ($l.role -eq 'join') { Say "  tunnel $($l.session): main PC not reachable right now (rc=$($r.rc): $(([string]$r.err).Trim())). The keeper retries until it is." }
      else { throw "tunnel listen failed (rc=$($r.rc)): $(([string]$r.err).Trim()) $(([string]$r.out).Trim())" }
      $st = Get-TunnelStatus $cfg $l.session
    }
    if ($l.role -eq 'listen') { $l.key = $st.key }
    $cfg.links[$name] = $l; Save-Config $cfg
  }
  $want = $Autostart.ToLowerInvariant()
  if ($existing -and $existing.Contains('autostart') -and $existing.autostart -and $existing.autostart.kind -ne $want) {
    Say "  switching autostart from $($existing.autostart.kind) to $want"
    Stop-Keeper $name
    Remove-Autostart $existing.autostart
  }
  $a = Install-Autostart $name $Autostart
  if (-not $DryRun) { $l.autostart = $a; $cfg.links[$name] = $l; Save-Config $cfg }
  $l
}

function Setup-Main {
  $cfg = Get-BaseConfig
  $main = Check-Name $MainName 'main'
  $joinLines = @()
  foreach ($m in @($Machines | ForEach-Object { $_ -split ',' } | Where-Object { $_ })) {
    $m = Check-Name $m.Trim() 'machine'
    if ($m -eq $main) { throw "machine '$m' has the same name as the main PC (-MainName)" }
    $l = [ordered]@{ link = $m; role = 'listen'; session = "mesh-$m"; profile = "mesh-$m"; as = $m; self = $main; key = '' }
    $l = Add-Link $cfg $l
    $key = if ($DryRun) { '<KEY printed by tunnel listen>' } else { $l.key }
    $joinLines += "  on '$m':  powershell -NoProfile -ExecutionPolicy Bypass -File .\windows\mesh-setup.ps1 -Join $key -MainName $main -Name $m"
  }
  Say ''
  Say 'JOIN LINES - run each on that machine, from the kit folder (one listener = one machine):'
  $joinLines | ForEach-Object { Say $_ }
  Say 'Keep these keys private: before a machine first connects, whoever has its key can take that slot.'
}

function Setup-Member {
  $key = $Join.Trim().ToUpperInvariant()
  if ($key -notmatch '^[0-9A-Z]{26}$') { throw "-Join needs the 26-character key the main PC printed (got '$Join')" }
  $cfg = Get-BaseConfig
  $main = Check-Name $MainName 'main'
  $me = if ($Name) { $Name } else { [Environment]::MachineName -replace '[^A-Za-z0-9-]', '-' -replace '^-+', '' -replace '^(.{1,31}).*$', '$1' }
  $me = Check-Name $me 'this machine'
  if ($me -eq $main) { throw "this machine's name '$me' equals -MainName; pass -Name <this machine>" }
  $l = [ordered]@{ link = $main; role = 'join'; session = "mesh-$main"; profile = "mesh-$main-me"; as = $main
    self = $me; key = $key }
  [void](Add-Link $cfg $l)
  Say ''
  Say "Done. Agents here reach agents on the main PC (and on its other machines) by name: hub.py send <agent> `"text`" --from <me>"
  Say "  or name@machine (hub.py send <agent>@$main ...); hub.py who lists them all."
}

# ------------------------------------------------------------------ status / uninstall
function Show-Status {
  $cfg = Load-Config
  if (-not $cfg.links.Count) { Say "no mesh links configured ($ConfigPath)"; return }
  foreach ($name in @($cfg.links.Keys)) {
    $l = $cfg.links[$name]
    $pidFile = Join-Path $RunDir ($name + '.pid'); $kp = ''
    if (Test-Path -LiteralPath $pidFile) { $kp = ([IO.File]::ReadAllText($pidFile)).Trim() }
    $keeper = if ($kp -and (Get-Process -Id ([int]$kp) -ErrorAction SilentlyContinue)) { "running (pid $kp)" } else { 'not running' }
    if ($DryRun) {   # -WhatIf runs nothing, not even the read-only status query
      Plan "check: $(Show-Argv (@($cfg.p2p) + @('tunnel', 'status', '--name', $l.session)))"
      $tun = 'tunnel not checked (-WhatIf)'
    } else {
      $st = Get-TunnelStatus $cfg $l.session
      $tun = if ($st.alive) { "daemon up, peer connected=$($st.connected)" } else { "daemon down (rc=$($st.rc))" }
    }
    $auto = if ($l.Contains('autostart') -and $l.autostart) { $l.autostart.kind } else { 'none' }
    Say ('{0,-12} {1,-6} tunnel {2,-16} @{3,-12} keeper {4,-22} {5}  autostart={6}' -f $name, $l.role, $l.session, $l.as, $keeper, $tun, $auto)
  }
}

function Remove-Links {
  $cfg = Load-Config
  $names = @($cfg.links.Keys)
  if ($Link) { $one = Check-Name $Link 'link'; $names = @($names | Where-Object { $_ -eq $one }); if (-not $names) { Say "no link '$one' in $ConfigPath"; return } }
  if (-not $names) { Say "nothing to remove: no mesh links in $ConfigPath" }
  foreach ($name in $names) {
    $l = $cfg.links[$name]
    Say "== removing link $name"
    $stop = Join-Path $RunDir ($name + '.stop'); $pidFile = Join-Path $RunDir ($name + '.pid')
    Stop-Keeper $name
    if ($l.Contains('autostart')) { Remove-Autostart $l.autostart }
    if ($DryRun) {
      Plan "stop tunnel: $(Show-Argv (@($cfg.p2p) + @('tunnel','stop','--name',$l.session)))"
      Plan "forget the far end this link pinned: $(Show-Argv (@($cfg.python) + @($cfg.hubPy, 'unpin', $l.as)))"
    } else {
      $r = Stop-Tunnel $cfg $l.session; Say "  tunnel $($l.session): stop rc=$($r.rc)"
      $r = Invoke-Fixed (@($cfg.python) + @($cfg.hubPy, 'unpin', $l.as)) 60; Say "  hub pin for $($l.as): $(([string]$r.out).Trim())"
    }
    $files = @($stop, $pidFile, (Join-Path $RunDir ($name + '.lock')), (Join-Path $RunDir ($name + '.child'))) + @(@('keeper.log', 'keeper.prev.log', 'keeper.log.1', 'hub.log', 'hub.err.log') + @('hub', 'hub.err' | ForEach-Object { "$_.prev.log"; foreach ($g in 2..5) { "$_.prev.$g.log" } }) | ForEach-Object { Join-Path $LogDir ($name + '.' + $_) })
    if ($DryRun) { Plan "delete this link's files: $($files -join ', ')"; Plan "drop '$name' from $ConfigPath" }
    else {
      foreach ($f in $files) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
      $cfg.links.Remove($name); Save-Config $cfg
    }
  }
  if (-not $DryRun -and -not $cfg.links.Count) {
    Remove-Item -LiteralPath $ConfigPath -Force -ErrorAction SilentlyContinue
    foreach ($d in @($LogDir, $RunDir, (Join-Path $StateDir 'startup'), $StateDir)) {
      if ((Test-Path -LiteralPath $d) -and -not (Get-ChildItem -LiteralPath $d -Force)) { Remove-Item -LiteralPath $d -Force }
    }
    Say "removed $StateDir"
  } elseif ($DryRun -and $names.Count -and $names.Count -eq $cfg.links.Count) { Plan "delete $ConfigPath and the empty folders under $StateDir" }
  Say 'Kept on purpose: p2p identity keys and tunnel history under your p2p home (.p2p). Delete them yourself if you want new keys.'
}

# ------------------------------------------------------------------ keeper (what the logon task runs)
function Run-Keeper {
  $name = Check-Name $Link 'link'
  $cfg = Load-Config
  if (-not $cfg.links.Contains($name)) { throw "no link '$name' in $ConfigPath (run setup first)" }
  $l = $cfg.links[$name]
  if ($DryRun) { Plan "keeper for $name would loop: ensure tunnel $($l.session) every 30 s; keep the hub link running; stop on $(Join-Path $RunDir ($name + '.stop'))"; return }
  # One keeper per link: an exclusive handle on run\<link>.lock, released by the OS when the keeper dies.
  [void][IO.Directory]::CreateDirectory($RunDir)
  $lock = $null
  try { $lock = [IO.File]::Open((Join-Path $RunDir ($name + '.lock')), 'OpenOrCreate', 'ReadWrite', 'None') }
  catch { Write-Host "keeper for $name is already running"; return }
  $pidFile = Join-Path $RunDir ($name + '.pid'); $stop = Join-Path $RunDir ($name + '.stop')
  Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue
  Write-Atomic $pidFile ([string]$PID)
  Stop-OrphanLink $name
  $child = $null; $verb = ''; $next = [DateTime]::MinValue; $wait = 30; $downTicks = 0
  Log-Line $name "KEEPER $name up (pid $PID): tunnel $($l.session), hub name @$($l.as). Text only; nothing received is run."
  try {
    while (-not (Test-Path -LiteralPath $stop)) {
      if ([DateTime]::UtcNow -ge $next) {
        $next = [DateTime]::UtcNow.AddSeconds(30)
        $st = Get-TunnelStatus $cfg $l.session
        if (-not $st.alive) {
          $r = Start-Tunnel $cfg $l
          if ($r.rc -eq 0) { Log-Line $name "tunnel $($l.session) started ($($l.role))"; $wait = 30; $st = Get-TunnelStatus $cfg $l.session }
          else {
            Log-Line $name "tunnel $($l.session) start failed rc=$($r.rc): $(([string]$r.err).Trim()); retry in $wait s"
            $next = [DateTime]::UtcNow.AddSeconds($wait); $wait = [Math]::Min(300, $wait * 2)
          }
          $downTicks = 0
        } elseif ($l.role -eq 'join' -and -not $st.connected) {
          # A joiner whose main PC restarted can sit unconnected; after ~3 minutes, rejoin.
          $downTicks++
          if ($downTicks -ge 6) {
            Log-Line $name "tunnel $($l.session) not connected for ~3 min; rejoining"
            [void](Stop-Tunnel $cfg $l.session); $downTicks = 0; $next = [DateTime]::UtcNow.AddSeconds(2)
          }
        } else { $downTicks = 0 }
        if (($null -eq $child -or $child.HasExited) -and $st.alive) {
          if ($child) { Log-Line $name "hub link exited (code $($child.ExitCode)); restarting" }
          if (-not $verb) { $verb = Get-HubVerb $cfg }
          $argv = Get-HubArgv $cfg $l $verb
          try {
            $child = Start-HubChild $argv $name
            Write-Atomic (Join-Path $RunDir ($name + '.child')) ("$($child.Id) " + $child.StartTime.ToUniversalTime().Ticks)
            Log-Line $name "hub link started (pid $($child.Id)): $(Show-Argv $argv)"
          }
          catch { $child = $null; Log-Line $name "hub link failed to start: $($_.Exception.Message)" }
        }
      }
      Start-Sleep -Seconds 1
    }
    Log-Line $name 'stop requested'
  } finally {
    if ($child -and -not $child.HasExited) {
      try { $child.Kill() } catch {}
      # A killed link cannot say goodbye itself; remove its presence row so 'who' is honest at once.
      [void](Invoke-Fixed (@($cfg.python) + @($cfg.hubPy, 'bye', $l.as)) 30)
    }
    Remove-Item -LiteralPath (Join-Path $RunDir ($name + '.child')) -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue
    Log-Line $name "KEEPER $name down"
    $lock.Dispose()
    Remove-Item -LiteralPath (Join-Path $RunDir ($name + '.lock')) -Force -ErrorAction SilentlyContinue
  }
}

# Restart one link's keeper the safe way: ask it to stop (it stops its hub link and says bye), then start it again
# through its autostart. Stop-ScheduledTask alone kills the conhost wrapper but can leave the keeper's powershell
# running, and the next start then exits at once ("already running").
function Restart-Keeper([string]$name) {
  $cfg = Load-Config
  if (-not $cfg.links.Contains($name)) { throw "no link '$name' in $ConfigPath" }
  Stop-Keeper $name
  $pidFile = Join-Path $RunDir ($name + '.pid')
  if ($DryRun) { Plan "start the keeper again: Task $TaskPath`AgentMesh-$name, else Startup\AgentMesh-$name.cmd"; return }
  if (Test-Path -LiteralPath $pidFile) { throw "keeper $name is still running after the stop request; not starting a second one" }
  $t = Get-ScheduledTask -TaskPath $TaskPath -TaskName ('AgentMesh-' + $name) -ErrorAction SilentlyContinue
  $su = Get-StartupFile $name
  if ($t) { Start-ScheduledTask -TaskPath $TaskPath -TaskName ('AgentMesh-' + $name); $how = 'task' }
  elseif (Test-Path -LiteralPath $su) { Start-Process -FilePath $su -WindowStyle Hidden; $how = 'startup file' }
  else { throw "no autostart for $name; start it with -Keep -Link $name" }
  $end = [DateTime]::UtcNow.AddSeconds(20)
  while (-not (Test-Path -LiteralPath $pidFile) -and [DateTime]::UtcNow -lt $end) { Start-Sleep -Milliseconds 500 }
  if (Test-Path -LiteralPath $pidFile) { Say "  keeper $name started again ($how), pid $([IO.File]::ReadAllText($pidFile).Trim())" }
  else { Say "  keeper $name did not write its pid file within 20 s; see $(Join-Path $LogDir ($name + '.keeper.log'))" }
}

# ------------------------------------------------------------------ dispatch
$modes = @(@(@($Machines).Count -gt 0), [bool]$Join, [bool]$Status, [bool]$Uninstall, [bool]$Keep, [bool]$Restart) | Where-Object { $_ }
if (@($modes).Count -ne 1) {
  foreach ($h in (Get-Content -LiteralPath $PSCommandPath | Select-Object -Skip 1)) { if ($h -eq '#>') { break }; if ($h -notmatch '^\.[A-Z]+$') { Write-Host $h } }
  if (@($modes).Count -gt 1) { throw 'pick exactly one mode' }
  return
}
if ($DryRun) { Say "DRY RUN (-WhatIf): nothing is changed and no command is run. State folder: $StateDir" }
if (@($Machines).Count) { Setup-Main }
elseif ($Join) { Setup-Member }
elseif ($Status) { Show-Status }
elseif ($Uninstall) { Remove-Links }
elseif ($Keep) { if (-not $Link) { throw '-Keep needs -Link <name>' }; Run-Keeper }
elseif ($Restart) { if (-not $Link) { throw '-Restart needs -Link <name>' }; Restart-Keeper $Link }
