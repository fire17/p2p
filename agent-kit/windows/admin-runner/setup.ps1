<#
setup.ps1 - the owner's ONE step per PC: install admin-runner with self-approve, from files pinned to one commit.

  setup.ps1            run it in any PowerShell; it asks for elevation (one UAC "Yes") and then:
                       1. downloads the admin-runner files of commit $Commit and checks each sha256 below;
                       2. runs install.ps1 -SelfApprove from them (folders, ACLs, bin\, the task, policy.json);
                       3. prints what was done and how to turn it off.
  setup.ps1 -Off       turn self-approve off again (same files, install.ps1 without -SelfApprove)

Running it elevated at the PC IS the owner's decision: policy.json can only be written by an administrator.
#>
param([switch]$Off)
$ErrorActionPreference = 'Stop'
$Commit = '5d421cdbf3147efa5542254b0a296f57e9d74345'
$Base = "https://raw.githubusercontent.com/fire17/p2p/$Commit/agent-kit/windows/admin-runner"
$Files = [ordered]@{
  'README.md'        = '8eb9ad7cf85abb59d850827414205dc7a30ea7b02185eaca8f1f78240a92856e'
  'approve.ps1'      = 'fc7361d682132b14aa95e0143af988e1f526e017c3429f216204e6a8e754e8ab'
  'common.ps1'       = 'ac7ad1737db43321604655cea933fbce52825eff8d4cfc029956f5a6c24d0e30'
  'install.ps1'      = 'cb65574fcecbc208be4b25438227900ce3e5b7d8f16c461930386961a7a51114'
  'request.ps1'      = '64d9f3caea947d95b02f8217bae0d05d19237feb1cd782ec96b6ce6026af7071'
  'runner.ps1'       = '7686f08366cd9d88e054da8fc3ddf75132f41b92e8958211644f7d68b1c76f07'
  'status.ps1'       = '14a5712a66bf3ee98c43bb61be6ee7ecb34098c0f30e6d568928259694d18192'
  'tests.ps1'        = '091e35ae0c20e288f7c6ed1648a3f9f9c306760a49628aec6ddb319784a37804'
  'test-vector.json' = 'd387b28cd545ba1448788e9ca75912845d0766e6e2ff658a74719ee372025149'
}

$pr = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  # ask for elevation once, re-running this same file
  $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"")
  if ($Off) { $a += '-Off' }
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $a
  'A UAC prompt opened: click Yes. The rest runs in the new (administrator) window.'
  return
}

$dir = Join-Path $env:ProgramData ('AgentAdmin-setup\' + $Commit.Substring(0, 7))
# a fresh folder only administrators can write, so nothing can swap a file between its hash check and its use
if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
[void][IO.Directory]::CreateDirectory($dir)
& icacls $dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed on $dir" }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
foreach ($f in $Files.Keys) {
  $out = Join-Path $dir $f
  Invoke-WebRequest -Uri "$Base/$f" -OutFile $out -UseBasicParsing
  $h = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash.ToLower()
  if ($h -ne $Files[$f]) { throw "sha256 mismatch for $f ($h): nothing was installed" }
  "ok     $f"
}
if ($Off) { & (Join-Path $dir 'install.ps1') } else { & (Join-Path $dir 'install.ps1') -SelfApprove }
''
if ($Off) { 'DONE: self-approve is OFF on this PC. Agents need an owner approval again.' }
else {
  'DONE: admin-runner installed, self-approve ON (temporary). Your agents can now run admin commands themselves;'
  'every run is listed in C:\ProgramData\AgentAdmin\audit.log. To turn it off: run setup.ps1 -Off.'
  'For your agents: this was the owner at the PC; proof is C:\ProgramData\AgentAdmin\policy.json (admin-write only).'
}
