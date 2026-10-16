# common.ps1 - shared helpers for the admin-runner scripts (dot-sourced; PowerShell 5.1, ASCII).
# Layout under the root (default C:\ProgramData\AgentAdmin):
#   queue\<id>.json      request  {id, command, reason, created, sha256}      written by the user-level agent
#   approved\<id>.json   approval {id, sha8, by, at}                          written by the user-level agent
#   done\                handled requests/approvals (moved there by the runner, never run again)
#   results\<id>.json    {id, status, exit, stdout, stderr, ...}              written by the runner
#   audit.log            one line per runner decision                         written by the runner
#   bin\                 runner.ps1 + common.ps1, admin-write only            what actually runs elevated

$AA_DefaultRoot = Join-Path $env:ProgramData 'AgentAdmin'
$AA_MaxCommandChars = 2000
$AA_ApprovalMaxAgeSec = 600      # an approval is valid for 10 min
$AA_RequestMaxAgeSec = 3600      # a request is valid for 60 min
$AA_TimeoutSec = 600             # a command gets 10 min, then it is killed
$AA_IdPattern = '^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$'

function AA-Dirs([string]$root) {
  @{ root = $root; queue = (Join-Path $root 'queue'); approved = (Join-Path $root 'approved')
     done = (Join-Path $root 'done'); results = (Join-Path $root 'results'); audit = (Join-Path $root 'audit.log')
     bin = (Join-Path $root 'bin') }
}

function AA-Sha256([string]$text) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
  -join ($h | ForEach-Object { $_.ToString('x2') })
}

function AA-NewId {
  $b = New-Object byte[] 3; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  (Get-Date).ToString('yyyyMMdd-HHmmss') + '-' + (-join ($b | ForEach-Object { $_.ToString('x2') }))
}

function AA-WriteJson([string]$path, $obj) {
  # write to a temp file, then rename: a reader never sees half a file
  $tmp = $path + '.tmp-' + [guid]::NewGuid().ToString('N')
  [IO.File]::WriteAllText($tmp, ($obj | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
  Move-Item -LiteralPath $tmp -Destination $path -Force
}

function AA-ReadJson([string]$path) {
  Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function AA-CheckId([string]$id) {
  if ($id -notmatch $AA_IdPattern) { throw "bad id '$id' (expected yyyyMMdd-HHmmss-xxxxxx)" }
}
