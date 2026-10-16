<#
.SYNOPSIS
  shai-ear.ps1 - long-running watcher that prints every Agent Tunnel message from Shai
  as ONE line prefixed "[SHAI] ". Built to be armed by a Claude Code agent's Monitor tool
  (persistent): each stdout line becomes a notification.

.DESCRIPTION
  Messages and files only. This script never runs anything it receives: it reads,
  sanitizes and prints. Your own agent decides what (if anything) to do with a message.

  Loop: p2p tunnel recv --name <session> --wait <Wait>
    * recv prints one JSON object per new chat message and advances the tunnel's own
      read cursor (cursor.json), so a message is printed once. The ear additionally
      de-duplicates by message id (kept across restarts in <StateDir>\seen.txt).
    * exit 0 = messages, 4 = wait timed out (normal), 5 = no tunnel session.
  After every recv it runs "p2p tunnel status" and prints a [SHAI-EAR] line whenever the
  link changes (UP / LINK DOWN / DAEMON DOWN / NO SESSION). Transient errors back off
  (5s doubling to 60s) and never kill the ear.

  Output lines (only these two prefixes are ever printed to stdout):
    [SHAI-EAR] ARMED ...                 first line, once
    [SHAI-EAR] <status/warning>          link changes, errors, takeover
    [SHAI] <message text>  {id=<16hex>}  one per message; newlines shown as " \n ",
                                         control characters stripped; long or multi-line
                                         messages are cut and the full text is saved to
                                         <StateDir>\inbox\<id>.txt (path printed).
  Every message line starts with "[SHAI] " so message text can never pose as an ear line.

  IMPORTANT: while the ear is armed, do NOT run "p2p tunnel recv" yourself - recv consumes
  the cursor and the ear would miss those messages. To re-read history use
  "p2p tunnel recv --name <session> --all" (does not move the cursor) or the saved files
  in <StateDir>\inbox.

  Only one ear runs per StateDir: a newly started ear takes over and the older one exits
  with "[SHAI-EAR] SUPERSEDED".

  Works on Windows PowerShell 5.1 and PowerShell 7+. No admin rights needed.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\shai-ear.ps1
.EXAMPLE
  pwsh -NoProfile -File .\shai-ear.ps1 -Name join-XXXX -Wait 60
#>
[CmdletBinding()]
param(
  # Tunnel session name (the join line creates "join-<KEY>"). Auto-detected when omitted.
  [string]$Name = '',
  # Seconds each recv waits for a message (p2p accepts 0..86400).
  [ValidateRange(1, 3600)][int]$Wait = 60,
  # Path to the p2p launcher. Default: the one the generic join installs.
  [string]$P2P = '',
  # Where the ear keeps its lock, seen-ids and full message copies.
  [string]$StateDir = '',
  # Longest message line printed before cutting (full text is saved to a file).
  [ValidateRange(80, 20000)][int]$MaxLine = 1500,
  # Test/diagnostic hook: stop after N loop iterations (0 = run forever).
  [int]$MaxIterations = 0,
  # Backoff ceiling in seconds after errors.
  [ValidateRange(1, 600)][int]$MaxBackoff = 60
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

# ---------- paths ----------
$UserHome = $env:USERPROFILE
if (-not $UserHome) { $UserHome = [Environment]::GetFolderPath('UserProfile') }
if (-not $P2P) { $P2P = Join-Path (Join-Path (Join-Path $UserHome '.local') 'bin') 'p2p.cmd' }
if (-not $StateDir) { $StateDir = Join-Path $UserHome '.shai-kit' }
$InboxDir = Join-Path $StateDir 'inbox'
$P2PHome = $env:P2P_HOME
if (-not $P2PHome) { $P2PHome = Join-Path $UserHome '.p2p' }
$TunnelRoot = Join-Path $P2PHome 'tunnel'
$NameRe = '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'   # p2p src/tunnel.js:49 NAME_RE

try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

# ---------- output ----------
function Emit([string]$line) {
  [Console]::Out.WriteLine($line)
  [Console]::Out.Flush()
}
function Ear([string]$msg) { Emit ('[SHAI-EAR] ' + $msg) }

function Short([string]$s, [int]$n) {
  if ($null -eq $s) { return '' }
  if ($s.Length -le $n) { return $s }
  return $s.Substring(0, $n) + '...'
}

# Strip terminal-control characters (C0 except TAB/LF, DEL, C1 incl. ESC sequences' lead bytes),
# bidi marks/overrides/isolates (they can visually reorder a line) and invisible characters a model
# reads but a person cannot see (zero-width, word joiner, BOM, TAG block U+E0000-E007F as its UTF-16
# surrogate pair, variation selectors U+FE00-FE0F and U+E0100-E01EF). Unicode line breaks become LF.
function Clean([string]$s) {
  if ($null -eq $s) { return '' }
  $s = $s -replace "`r`n", "`n"
  $s = $s -replace '[\r\u0085\u2028\u2029]', "`n"
  return ($s -replace '\uDB40[\uDC00-\uDC7F\uDD00-\uDDEF]|[\x00-\x08\x0B-\x1F\x7F-\x9F\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFE00-\uFE0F\uFEFF\uFFF9-\uFFFB]', '')
}

# ---------- run p2p (Process API: UTF-8 decode, separate stderr, hard timeout) ----------
function Invoke-P2P([string[]]$argList, [int]$timeoutSec) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $P2P
  $quoted = @()
  foreach ($a in $argList) {
    if ($a -match '[\s"]') { $quoted += '"' + ($a -replace '"', '\"') + '"' } else { $quoted += $a }
  }
  $psi.Arguments = ($quoted -join ' ')
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $psi.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
  $psi.StandardErrorEncoding = New-Object System.Text.UTF8Encoding($false)
  $r = @{ Code = -1; Out = @(); Err = '' }
  try {
    $p = [System.Diagnostics.Process]::Start($psi)
  } catch {
    $r.Err = 'cannot start ' + $P2P + ': ' + $_.Exception.Message
    return $r
  }
  $outTask = $p.StandardOutput.ReadToEndAsync()
  $errTask = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($timeoutSec * 1000)) {
    try { $p.Kill() } catch { }
    $r.Err = 'p2p did not return within ' + $timeoutSec + 's (killed)'
    return $r
  }
  $p.WaitForExit()
  $out = ''; $err = ''
  try { if ($outTask.Wait(5000)) { $out = $outTask.Result } } catch { }
  try { if ($errTask.Wait(5000)) { $err = $errTask.Result } } catch { }
  $r.Code = $p.ExitCode
  $r.Out = @($out -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
  $r.Err = $err.Trim()
  return $r
}

function Get-Field($obj, [string]$field) {
  if ($null -eq $obj) { return $null }
  $prop = $obj.PSObject.Properties[$field]
  if ($null -eq $prop) { return $null }
  return $prop.Value
}

# Returns @{ State = 'UP'|'LINK DOWN'|'DAEMON DOWN'|'NO SESSION'|'UNKNOWN'; Detail = '...' }
function Get-Link([string]$n) {
  if (-not $n) { return @{ State = 'NO SESSION'; Detail = 'no tunnel session found' } }
  $r = Invoke-P2P @('tunnel', 'status', '--name', $n) 30
  $j = $null
  foreach ($line in $r.Out) { try { $j = $line | ConvertFrom-Json } catch { } }
  if ($null -eq $j) {
    if ($r.Code -eq 5) { return @{ State = 'NO SESSION'; Detail = (Short $r.Err 200) } }
    return @{ State = 'UNKNOWN'; Detail = ('status exit ' + $r.Code + ' ' + (Short $r.Err 200)) }
  }
  $alive = [bool](Get-Field $j 'alive')
  $conn = [bool](Get-Field $j 'connected')
  $tr = Get-Field $j 'transport'
  $err = Get-Field $j 'error'
  $d = 'sent=' + (Get-Field $j 'sent') + ' recv=' + (Get-Field $j 'recv')
  if ($tr) { $d += ' via=' + $tr }
  if ($err) { $d += ' error=' + (Short (Clean ([string]$err)) 160) }
  if (-not $alive) { return @{ State = 'DAEMON DOWN'; Detail = $d } }
  if (-not $conn) { return @{ State = 'LINK DOWN'; Detail = $d } }
  return @{ State = 'UP'; Detail = $d }
}

# Session discovery: explicit -Name, else the live+connected session, else live, else newest.
# mesh-* sessions belong to mesh-setup.ps1 hub links (machine-to-machine), never to Shai: skip them.
function Find-Session {
  if ($Name) { return $Name }
  $cands = @()
  if (Test-Path -LiteralPath $TunnelRoot) {
    $cands = @(Get-ChildItem -LiteralPath $TunnelRoot -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match $NameRe -and $_.Name -notlike 'mesh-*' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'current.json')) } |
      Sort-Object LastWriteTime -Descending | Select-Object -First 16)
  }
  if ($cands.Count -eq 0) { return '' }
  $alive = ''
  foreach ($c in $cands) {
    $l = Get-Link $c.Name
    if ($l.State -eq 'UP') { return $c.Name }
    if ($l.State -eq 'LINK DOWN' -and -not $alive) { $alive = $c.Name }
  }
  if ($alive) { return $alive }
  return $cands[0].Name
}

# ---------- state: lock (takeover), seen ids ----------
New-Item -ItemType Directory -Force -Path $InboxDir | Out-Null
$LockFile = Join-Path $StateDir 'ear.lock'
$SeenFile = Join-Path $StateDir 'seen.txt'
$Token = [guid]::NewGuid().ToString('N')
Set-Content -LiteralPath $LockFile -Value ($Token + ' ' + $PID) -Encoding ASCII

$Seen = New-Object 'System.Collections.Generic.HashSet[string]'
$SeenOrder = New-Object 'System.Collections.Generic.Queue[string]'
if (Test-Path -LiteralPath $SeenFile) {
  foreach ($sid in @(Get-Content -LiteralPath $SeenFile -Tail 2000 -ErrorAction SilentlyContinue)) {
    if ($sid -and $Seen.Add($sid)) { $SeenOrder.Enqueue($sid) }
  }
}
function Remember([string]$id) {
  if (-not $Seen.Add($id)) { return }
  $SeenOrder.Enqueue($id)
  while ($SeenOrder.Count -gt 5000) { [void]$Seen.Remove($SeenOrder.Dequeue()) }
  try { Add-Content -LiteralPath $SeenFile -Value $id -Encoding ASCII } catch { }
}

function Still-Owner {
  try {
    $cur = (Get-Content -LiteralPath $LockFile -TotalCount 1 -ErrorAction Stop)
    return ($cur -like ($Token + ' *'))
  } catch { return $true }   # lock unreadable: keep running rather than go deaf
}

function Print-Message($row) {
  $id = [string](Get-Field $row 'id')
  $text = Get-Field $row 'text'
  if ($null -eq $text) { return }
  $chan = Get-Field $row 'channel'
  if ($chan -and $chan -ne 'chat') { return }             # p2p already drops 'term' (bin/p2p-tunnel.js:428)
  if ($id -and $Seen.Contains($id)) { return }
  $clean = Clean ([string]$text)
  $flat = ($clean.TrimEnd("`n") -replace "`n", ' \n ')
  $saved = ''
  $safeId = $id
  if (-not ($safeId -match '^[a-f0-9]{16}$')) { $safeId = 'msg-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff') }
  $file = Join-Path $InboxDir ($safeId + '.txt')
  try {
    [IO.File]::WriteAllText($file, $clean, (New-Object System.Text.UTF8Encoding($false)))
    $saved = $file
  } catch { }
  $line = $flat
  if ($flat.Length -gt $MaxLine) {
    $line = $flat.Substring(0, $MaxLine) + ' ...(+' + ($flat.Length - $MaxLine) + ' chars)'
  }
  $suffix = '  {id=' + $id
  $re = Get-Field $row 'reply_to'                      # set by send --reply-to (bin/p2p-tunnel.js:398)
  if ($re) { $suffix += ' re=' + (Short ([string]$re) 16) }
  if ($saved -and ($flat.Length -gt $MaxLine -or $clean.TrimEnd("`n").Contains("`n"))) { $suffix += ' full=' + $saved }
  $suffix += '}'
  Emit ('[SHAI] ' + $line + $suffix)
  if ($id) { Remember $id }
}

# ---------- arm ----------
if (-not (Test-Path -LiteralPath $P2P)) {
  Ear ('WARN p2p launcher not found at ' + $P2P + ' - the owner must run the join line first. Retrying.')
}
$Session = Find-Session
$link = Get-Link $Session
$sesShow = $Session
if ($sesShow.Length -gt 17) { $sesShow = $sesShow.Substring(0, 17) + '...' }
if (-not $sesShow) { $sesShow = '(none yet)' }
Ear ('ARMED pid=' + $PID + ' ps=' + $PSVersionTable.PSVersion.ToString() + ' session=' + $sesShow +
  ' link=' + $link.State + ' wait=' + $Wait + 's - Shai messages print as [SHAI] lines. Do not run "p2p tunnel recv" while armed.')
$lastState = $link.State
if ($lastState -ne 'UP') { Ear ('STATUS ' + $lastState + ' ' + $link.Detail + ' (waiting; if it stays down, ask the PC owner to re-run the join line)') }

# ---------- loop ----------
$backoff = 0
$lastWarn = ''
$iter = 0
while ($true) {
  $iter++
  if ($MaxIterations -gt 0 -and $iter -gt $MaxIterations) { break }
  if (-not (Still-Owner)) { Ear ('SUPERSEDED by a newer ear (pid in ' + $LockFile + '); exiting.'); break }

  if (-not $Session) {
    $Session = Find-Session
    if (-not $Session) {
      if ($lastState -ne 'NO SESSION') { Ear 'STATUS NO SESSION - no tunnel session on this PC yet (owner runs the join line once).'; $lastState = 'NO SESSION' }
      Start-Sleep -Seconds ([Math]::Min($MaxBackoff, 30)); continue
    }
    Ear ('SESSION found ' + (Short $Session 17))
  }

  $r = Invoke-P2P @('tunnel', 'recv', '--name', $Session, '--wait', [string]$Wait) ($Wait + 45)
  $problem = ''
  if ($r.Code -eq 0) {
    foreach ($line in $r.Out) {
      $row = $null
      try { $row = $line | ConvertFrom-Json } catch { $row = $null }
      if ($null -eq $row) { $problem = 'unparsable recv line: ' + (Short (Clean $line) 120); continue }
      Print-Message $row
    }
  } elseif ($r.Code -eq 4) {
    # wait timed out with no message: normal
  } elseif ($r.Code -eq 5) {
    $problem = 'NO SESSION'
    if (-not $Name) { $Session = '' }   # re-discover (a re-join may have made a new one)
  } else {
    $problem = 'recv exit ' + $r.Code + ': ' + (Short (Clean $r.Err) 200)
  }

  $link = Get-Link $Session
  if ($link.State -ne $lastState) {
    if ($link.State -eq 'UP') { Ear ('STATUS UP (reconnected) ' + $link.Detail) }
    else { Ear ('STATUS ' + $link.State + ' ' + $link.Detail + ' (ear keeps listening; if it stays down, ask the PC owner to re-run the join line)') }
    $lastState = $link.State
  }

  if ($problem -and $problem -ne 'NO SESSION') {
    if ($problem -ne $lastWarn) { Ear ('WARN ' + $problem + ' (retrying)') }
    $lastWarn = $problem
    if ($backoff -eq 0) { $backoff = 5 } else { $backoff = [Math]::Min($MaxBackoff, $backoff * 2) }
    Start-Sleep -Seconds $backoff
  } elseif ($problem -eq 'NO SESSION') {
    if ($backoff -eq 0) { $backoff = 5 } else { $backoff = [Math]::Min($MaxBackoff, $backoff * 2) }
    Start-Sleep -Seconds $backoff
  } else {
    if ($lastWarn) { Ear 'OK recv healthy again'; $lastWarn = '' }
    $backoff = 0
  }
}
exit 0
