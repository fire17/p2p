# Exercise the exact generated CMD launcher with no runtime downloads.
$ErrorActionPreference = 'Stop'
$root = Join-Path ([IO.Path]::GetTempPath()) ('p2p cmd exit ' + [guid]::NewGuid().ToString('N'))
$savedHome = $env:P2P_HOME
try {
    New-Item -ItemType Directory -Path $root | Out-Null
    $env:P2P_HOME = $root
    [IO.File]::WriteAllText((Join-Path $root 'runtime.kind'), 'bun')
    [IO.File]::WriteAllText((Join-Path $root 'runtime.path'), (Join-Path $root 'missing.exe'))
    $source = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'init.ps1') -Raw -Encoding UTF8
    $body = [regex]::Match($source, '(?s)\$cmdBody = @''\r?\n(.*?)\r?\n''@').Groups[1].Value
    if (-not $body) { throw 'CMD template not found' }
    $shim = Join-Path $root 'p2p.cmd'
    [IO.File]::WriteAllText($shim, ($body -replace "`r?`n", "`r`n") + "`r`n", [Text.Encoding]::ASCII)
    $ErrorActionPreference = 'Continue'
    $directOutput = & $shim probe 2>&1 | Out-String
    $directCode = $global:LASTEXITCODE
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $env:ComSpec
    $info.Arguments = '/d /s /c ""' + $shim + '" probe"'
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($info)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $receipt = [pscustomobject]@{directCode=$directCode; directOutput=$directOutput; processCode=$process.ExitCode; stdout=$stdout; stderr=$stderr}
    Write-Output ($receipt | ConvertTo-Json -Compress)
    if ($process.ExitCode -eq 0 -or $directCode -eq 0) { throw 'Missing runtime must return a nonzero native exit code.' }
} finally {
    $env:P2P_HOME = $savedHome
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
$global:LASTEXITCODE = 0
