<#
.SYNOPSIS
  shai-send.ps1 - send one tagged message (or a UTF-8 file) to Shai over Agent Tunnel.

.DESCRIPTION
  Messages only: this sends text, nothing else. It always hands the text to p2p as a
  UTF-8 file ("p2p tunnel send --file"), because p2p.cmd re-parses %* through cmd.exe,
  where characters like & | % " in a plain argument can break or change the command.

  The message must start with one tag:  HELLO | ASK | ERROR | LOG | DONE | FIX | ACK
  (an optional "G1 " envelope prefix is accepted; the G1 verbs NOTE | FILE | RETEST are accepted too).

  Secrets: the text is scanned for token-like strings (API keys, GitHub tokens, bearer
  tokens, JWTs, private keys, password=/token= values). With -Redact they are masked as
  *** before sending (and your user-profile path becomes ~). Without -Redact the send is
  REFUSED if anything token-like is found - nothing is sent.

  Exit codes: 0 delivered (acknowledged), 2 usage / tag / secret refusal,
  3 not connected or delivery failed, 4 queued but no acknowledgment within -Wait,
  5 no tunnel session (owner must run the join line).

.EXAMPLE
  .\shai-send.ps1 "HELLO MACHINE=pc OS=Windows 11 AGENT=claude-code"
.EXAMPLE
  .\shai-send.ps1 -File .\error.txt -Redact
.EXAMPLE
  .\shai-send.ps1 -ReplyTo 0123456789abcdef "ACK got it"
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0, ValueFromRemainingArguments = $true)][string[]]$Text,
  [string]$File = '',
  [switch]$Redact,
  [string]$Name = '',
  [ValidateRange(0, 600)][int]$Wait = 15,
  [string]$ReplyTo = '',
  [string]$P2P = '',
  # Retries only when NOTHING was queued (peer not connected yet). Never re-sends a queued message.
  [ValidateRange(0, 10)][int]$Retries = 2,
  # Print the final (redacted) text instead of sending it.
  [switch]$DryRun
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

$Tags = 'HELLO|ASK|ERROR|LOG|DONE|FIX|ACK|NOTE|FILE|RETEST'
$UserHome = $env:USERPROFILE
if (-not $UserHome) { $UserHome = [Environment]::GetFolderPath('UserProfile') }
if (-not $P2P) { $P2P = Join-Path (Join-Path (Join-Path $UserHome '.local') 'bin') 'p2p.cmd' }
$P2PHome = $env:P2P_HOME
if (-not $P2PHome) { $P2PHome = Join-Path $UserHome '.p2p' }
$TunnelRoot = Join-Path $P2PHome 'tunnel'
$NameRe = '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'   # p2p src/tunnel.js:49
$Utf8 = New-Object System.Text.UTF8Encoding($false)
try { [Console]::OutputEncoding = $Utf8 } catch { }

function Say([string]$m) { [Console]::Out.WriteLine('[SHAI-SEND] ' + $m); [Console]::Out.Flush() }
function Die([string]$m, [int]$code) { [Console]::Error.WriteLine('[SHAI-SEND] ' + $m); exit $code }

# ---------- text ----------
if ($File -and $Text -and $Text.Count -gt 0) { Die 'give either text or -File, not both' 2 }
if ($File) {
  if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { Die ('file not found: ' + $File) 2 }
  try { $body = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $File).ProviderPath, $Utf8) }
  catch { Die ('cannot read file as UTF-8: ' + $_.Exception.Message) 2 }
} elseif ($Text -and $Text.Count -gt 0) {
  $body = ($Text -join ' ')
} else {
  Die ('usage: shai-send.ps1 "<TAG> text" | -File path [-Redact] [-ReplyTo id]   TAG = ' + $Tags) 2
}
$body = $body.TrimStart([char]0xFEFF)
if (-not $body.Trim()) { Die 'empty message' 2 }
if (-not ($body.TrimStart() -cmatch ('^(G1\s+)?(' + $Tags + ')\b'))) {
  Die ('message must start with a tag: ' + ($Tags -replace '\|', ' | ') + '  (got: "' + ($body.TrimStart().Split("`n")[0] -replace '^(.{40}).*$', '$1...') + '")') 2
}
if ($ReplyTo -and -not ($ReplyTo -match '^[a-f0-9]{16}$')) { Die '-ReplyTo must be a 16-hex message id (shown as {id=...} on [SHAI] lines)' 2 }

# ---------- secrets ----------
# Each rule: regex, and the group(s) kept. Order matters (specific before generic).
$Rules = @(
  @{ re = '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)'; rep = '***PRIVATE-KEY***' },
  @{ re = '\bsk-(ant-)?[A-Za-z0-9_\-]{16,}'; rep = 'sk-***' },
  @{ re = '\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}'; rep = '$1_***' },
  @{ re = '\bgithub_pat_[A-Za-z0-9_]{20,}'; rep = 'github_pat_***' },
  @{ re = '\bglpat-[A-Za-z0-9_\-]{16,}'; rep = 'glpat-***' },
  @{ re = '\bxox[abposr]-[A-Za-z0-9\-]{10,}'; rep = 'xox-***' },
  @{ re = '\bAKIA[0-9A-Z]{16}\b'; rep = 'AKIA***' },
  @{ re = '\bAIza[0-9A-Za-z_\-]{30,}'; rep = 'AIza***' },
  @{ re = '\bnpm_[A-Za-z0-9]{30,}'; rep = 'npm_***' },
  @{ re = '\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}'; rep = '***JWT***' },
  @{ re = '(?i)\b(bearer)\s+[A-Za-z0-9._~+/=\-]{12,}'; rep = '$1 ***' },
  @{ re = '(?i)\b(authorization\s*:\s*)\S.*'; rep = '$1***' },
  @{ re = '(?i)((?:password|passwd|pwd|secret|client_secret|token|access_token|refresh_token|api[_-]?key|apikey|auth[_-]?token)\s*[:=]\s*)("[^"]*"|''[^'']*''|[^\s,;&]+)'; rep = '$1***' },
  @{ re = '(?i)(://[^/\s:@]+:)[^@\s/]+@'; rep = '$1***@' }
)
$hits = 0
$out = $body
foreach ($rule in $Rules) {
  $m = [regex]::Matches($out, $rule.re)
  if ($m.Count -gt 0) { $hits += $m.Count; $out = [regex]::Replace($out, $rule.re, $rule.rep) }
}
if ($hits -gt 0 -and -not $Redact) {
  Die ('refused: ' + $hits + ' token-like string(s) found. Re-run with -Redact to mask them, or remove them. Nothing was sent.') 2
}
if ($Redact) {
  if ($UserHome) { $out = $out.Replace($UserHome, '~') }
  if ($hits -gt 0) { Say ('redacted ' + $hits + ' token-like string(s)') }
}
$body = $out
if ($Utf8.GetByteCount($body) -gt 1048576) { Die 'message exceeds 1 MiB (p2p limit); split it' 2 }   # bin/p2p-tunnel.js:396

if ($DryRun) { [Console]::Out.WriteLine($body); exit 0 }

# ---------- run p2p ----------
function Invoke-P2P([string[]]$argList, [int]$timeoutSec) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $P2P
  $q = @()
  # Quote anything cmd.exe would act on: p2p.cmd re-parses %* (e.g. a profile path containing '&').
  foreach ($a in $argList) { if ($a -match '[\s"&|<>^(),;=]') { $q += '"' + ($a -replace '"', '\"') + '"' } else { $q += $a } }
  $psi.Arguments = ($q -join ' ')
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $psi.StandardOutputEncoding = $Utf8
  $psi.StandardErrorEncoding = $Utf8
  $r = @{ Code = -1; Out = @(); Err = '' }
  try { $p = [System.Diagnostics.Process]::Start($psi) } catch { $r.Err = 'cannot start ' + $P2P + ': ' + $_.Exception.Message; return $r }
  $ot = $p.StandardOutput.ReadToEndAsync(); $et = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($timeoutSec * 1000)) { try { $p.Kill() } catch { }; $r.Err = 'p2p timed out (killed)'; return $r }
  $p.WaitForExit()
  $o = ''; $e = ''
  try { if ($ot.Wait(5000)) { $o = $ot.Result } } catch { }
  try { if ($et.Wait(5000)) { $e = $et.Result } } catch { }
  $r.Code = $p.ExitCode; $r.Out = @($o -split "`r?`n" | Where-Object { $_.Trim() -ne '' }); $r.Err = $e.Trim()
  return $r
}
function Field($o, [string]$f) { if ($null -eq $o) { return $null }; $p = $o.PSObject.Properties[$f]; if ($null -eq $p) { return $null }; return $p.Value }

function Find-Session {
  if ($Name) { return $Name }
  if (-not (Test-Path -LiteralPath $TunnelRoot)) { return '' }
  $cands = @(Get-ChildItem -LiteralPath $TunnelRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match $NameRe -and (Test-Path -LiteralPath (Join-Path $_.FullName 'current.json')) } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 16)
  $fallback = ''
  foreach ($c in $cands) {
    $r = Invoke-P2P @('tunnel', 'status', '--name', $c.Name) 30
    foreach ($l in $r.Out) {
      try { $j = $l | ConvertFrom-Json } catch { continue }
      if ((Field $j 'alive') -and (Field $j 'connected')) { return $c.Name }
      if ((Field $j 'alive') -and -not $fallback) { $fallback = $c.Name }
    }
  }
  if ($fallback) { return $fallback }
  if ($cands.Count -gt 0) { return $cands[0].Name }
  return ''
}

$Session = Find-Session
if (-not $Session) { Die 'no tunnel session on this PC (the owner runs the join line once).' 5 }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('shai-send-' + $PID + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
[IO.File]::WriteAllText($tmp, $body, $Utf8)
$code = 3
try {
  for ($try = 0; $try -le $Retries; $try++) {
    $a = @('tunnel', 'send', '--file', $tmp, '--name', $Session, '--wait', [string]$Wait)
    if ($ReplyTo) { $a += @('--reply-to', $ReplyTo) }
    $r = Invoke-P2P $a ($Wait + 45)
    $queuedId = ''; $ack = $null
    foreach ($l in $r.Out) {
      try { $j = $l | ConvertFrom-Json } catch { continue }
      if (Field $j 'queued') { $queuedId = [string](Field $j 'id') }
      if ($null -ne (Field $j 'delivered')) { $ack = $j }
    }
    $code = $r.Code
    if ($code -eq 0) { Say ('DELIVERED id=' + $queuedId); break }
    if ($queuedId) {
      if ($code -eq 4) { Say ('QUEUED id=' + $queuedId + ' - no acknowledgment within ' + $Wait + 's (it may still arrive; do not resend blindly)') }
      else { Say ('FAILED id=' + $queuedId + ' delivery error: ' + (Field $ack 'error') + ' ' + $r.Err) }
      break
    }
    if ($code -eq 5) { Die ('no live tunnel daemon (' + $r.Err + '). Ask the PC owner to re-run the join line.') 5 }
    if ($try -lt $Retries) { Say ('not queued (exit ' + $code + ': ' + $r.Err + '); retry in 5s'); Start-Sleep -Seconds 5 }
    else { Say ('NOT SENT (exit ' + $code + ': ' + $r.Err + ')') }
  }
} finally {
  Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
}
if ($code -lt 0) { $code = 3 }
exit $code
