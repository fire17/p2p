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
$Commit = '725767736cec2e50a3aa81518b52560c21c367aa'
$Base = "https://raw.githubusercontent.com/fire17/p2p/$Commit/agent-kit/windows/admin-runner"
$Files = [ordered]@{
  'README.md'        = 'dcff1630e7171ce08151988b3e04830a60c689b47058faf0d6bf0652760ca02c'
  'approve.ps1'      = '74cb47d187503bb694f9df747ce6396ca4a107b02addf281f4faa8b5b2a46df7'
  'common.ps1'       = '3ea506d47b5e731fcc0b3a713e6b85d09b0ae9ce1ecb0f25862442744f9ddd5a'
  'install.ps1'      = '972c339090d0d2bc48e14f14d7c57cc02caa1c9f4942984da2fce84ec30823ab'
  'request.ps1'      = '090f5a41d46898c1ae84070191bd724f74f5f363b4f226338345b8ece4c773d3'
  'runner.ps1'       = '7af5104072766592baab692599d6834add3764661ac56c7410d9630588832411'
  'status.ps1'       = 'a5d8b747417007b1cc80259ed0892113befffeb8447226b9cdd410ffca370b0e'
  'tests.ps1'        = 'a3ec91dcdc28cc3cb117f3a441095266028acf55182da7e873945066bd1ba1be'
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
