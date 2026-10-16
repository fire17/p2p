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

function AA-SelfApproveOn($d) {
  # the owner's own elevated choice (install.ps1 -SelfApprove), in an admin-write file the user can only read
  $p = Join-Path $d.root 'policy.json'
  if (-not (Test-Path -LiteralPath $p)) { return $false }
  try { return [bool](AA-ReadJson $p).self_approve } catch { return $false }
}

function AA-CheckId([string]$id) {
  if ($id -notmatch $AA_IdPattern) { throw "bad id '$id' (expected yyyyMMdd-HHmmss-xxxxxx)" }
}

# ---- signed approvals (bin\approver.pub.xml present = signed mode, no unsigned fallback)
$AA_SigPrefix = 'agent-admin-v1'
$AA_AtPattern = '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'

function AA-SignedPayload([string]$id, [string]$sha256, [string]$by, [string]$at) {
  # exactly what the approver signs (UTF-8 bytes); at = the approval's "at" string as written
  "$AA_SigPrefix|$id|$sha256|$by|$at"
}

function AA-VerifySig([string]$pubXml, [string]$payload, [string]$sigB64) {
  # RSA PKCS#1 v1.5 + SHA-256. A malformed SIGNATURE is an invalid signature ($false); a malformed installed KEY
  # is a setup error and throws (the runner then refuses with that reason).
  try { $sig = [Convert]::FromBase64String($sigB64) } catch [FormatException] { return $false }
  $r = New-Object Security.Cryptography.RSACryptoServiceProvider
  try {
    $r.FromXmlString($pubXml)
    try { return $r.VerifyData([Text.Encoding]::UTF8.GetBytes($payload), 'SHA256', $sig) }
    catch [Security.Cryptography.CryptographicException] { return $false }   # e.g. wrong signature length
  } finally { $r.Dispose() }
}

function AA-CheckPublicKeyXml([string]$xml) {
  # refuse a private key (it must never be on the PC) and anything that is not an RSA public key
  if ($xml -match '<(D|P|Q|DP|DQ|InverseQ)>') { throw 'this XML holds a PRIVATE key; only the public key may be installed' }
  $r = New-Object Security.Cryptography.RSACryptoServiceProvider
  try { $r.FromXmlString($xml); if ($r.KeySize -lt 2048) { throw "RSA key is $($r.KeySize) bits; at least 2048 required" } } finally { $r.Dispose() }
}
