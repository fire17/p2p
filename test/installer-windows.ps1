# Run only on a disposable Windows CI runner. Install from this checkout into a
# fresh path containing spaces, execute BOTH generated launchers, then restore PATH.
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
    Write-Output 'SKIP: real Windows is required for the generated cmd launcher'
    exit 0
}
$repoPath = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('p2p windows smoke ' + [guid]::NewGuid().ToString('N'))
$savedUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$savedProcessPath = $env:Path
$savedConfig = @{}
foreach ($key in @('P2P_HOME', 'P2P_BIN_DIR', 'P2P_SRC')) {
    $savedConfig[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}
try {
    $env:P2P_HOME = Join-Path $testRoot 'state'
    $env:P2P_BIN_DIR = Join-Path $testRoot 'bin'
    $env:P2P_SRC = $repoPath
    & pwsh -NoProfile -NonInteractive -File (Join-Path $repoPath 'init.ps1')
    if ($LASTEXITCODE -ne 0) { throw "First install exited $LASTEXITCODE" }
    $sourcePackage = Get-Content -Raw (Join-Path $repoPath 'package.json') | ConvertFrom-Json
    $installedPackage = Get-Content -Raw (Join-Path $env:P2P_HOME 'app/package.json') | ConvertFrom-Json
    if ($sourcePackage.version -ne $installedPackage.version) { throw 'Installed version differs from source' }
    foreach ($shim in @('p2p.ps1', 'p2p.cmd')) {
        $shimPath = Join-Path $env:P2P_BIN_DIR $shim
        if ($shim -eq 'p2p.ps1') {
            $helpText = & pwsh -NoProfile -NonInteractive -File $shimPath tunnel --help 2>&1 | Out-String
        } else {
            $helpText = & $shimPath tunnel --help 2>&1 | Out-String
        }
        if ($LASTEXITCODE -ne 0 -or $helpText -notmatch 'tunnel') { throw "$shim cannot invoke installed tunnel: $helpText" }
        Write-Output "PASS: installed $shim invokes tunnel from a path containing spaces"
    }
    Write-Output "PASS: Windows first install $($installedPackage.version)"
} finally {
    [Environment]::SetEnvironmentVariable('Path', $savedUserPath, 'User')
    $env:Path = $savedProcessPath
    foreach ($key in $savedConfig.Keys) {
        [Environment]::SetEnvironmentVariable($key, $savedConfig[$key], 'Process')
    }
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
