# Run only on a disposable Windows CI runner. Install from this checkout into a
# fresh path containing spaces, execute BOTH generated launchers, then restore PATH.
param(
    [ValidateSet('pwsh', 'powershell.exe')]
    [string]$PowerShellCommand = 'pwsh'
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
    Write-Output 'SKIP: real Windows is required for the generated cmd launcher'
    exit 0
}
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This PATH-mutating installer test requires a disposable GitHub Actions Windows runner'
}
$expectedEdition = if ($PowerShellCommand -eq 'powershell.exe') { 'Desktop' } else { 'Core' }
if ($PSVersionTable.PSEdition -ne $expectedEdition) {
    throw "Run this test under $PowerShellCommand so the cmd launcher uses the same native argument parser"
}
$shellExe = (Get-Command $PowerShellCommand -CommandType Application -ErrorAction Stop).Source
Write-Output "Testing installer and launchers with $PowerShellCommand ($($PSVersionTable.PSVersion))"
$repoPath = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('p2p windows smoke ' + [guid]::NewGuid().ToString('N'))
$savedUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$savedProcessPath = $env:Path
$savedConfig = @{}
foreach ($key in @('P2P_HOME', 'P2P_BIN_DIR', 'P2P_SRC', 'P2P_NODE_DIST', 'P2P_FORCE_NODE_BOOTSTRAP', 'P2P_INSTALLER_TEST_SOURCE')) {
    $savedConfig[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}
try {
    $env:P2P_HOME = Join-Path $testRoot 'state'
    $env:P2P_BIN_DIR = Join-Path $testRoot 'bin'
    $env:P2P_SRC = $repoPath
    # setup-node provides Node 22. A discovery/quoting regression must fail without
    # falling back to a public download; Invoke-WebRequest does not support file URLs.
    $env:P2P_NODE_DIST = 'file:///p2p-installer-smoke-network-disabled'
    $env:P2P_FORCE_NODE_BOOTSTRAP = '0'
    $env:P2P_INSTALLER_TEST_SOURCE = Join-Path $repoPath 'init.ps1'
    # Match the documented irm | iex entry point with locally decoded UTF-8 text.
    # Direct -File would let Windows PowerShell reinterpret BOM-less UTF-8 as ANSI.
    & $shellExe -NoProfile -NonInteractive -Command 'Get-Content -LiteralPath $env:P2P_INSTALLER_TEST_SOURCE -Raw -Encoding UTF8 | Invoke-Expression'
    if ($LASTEXITCODE -ne 0) { throw "First install exited $LASTEXITCODE" }
    $sourcePackage = Get-Content -Raw (Join-Path $repoPath 'package.json') | ConvertFrom-Json
    $installedPackage = Get-Content -Raw (Join-Path $env:P2P_HOME 'app/package.json') | ConvertFrom-Json
    if ($sourcePackage.version -ne $installedPackage.version) { throw 'Installed version differs from source' }
    foreach ($shim in @('p2p.ps1', 'p2p.cmd')) {
        $shimPath = Join-Path $env:P2P_BIN_DIR $shim
        if ($shim -eq 'p2p.ps1') {
            $helpText = & $shellExe -NoProfile -NonInteractive -File $shimPath tunnel --help 2>&1 | Out-String
        } else {
            $helpText = & $shimPath tunnel --help 2>&1 | Out-String
        }
        if ($LASTEXITCODE -ne 0 -or $helpText -notmatch 'tunnel') { throw "$shim cannot invoke installed tunnel: $helpText" }
        Write-Output "PASS: $PowerShellCommand installed $shim invokes tunnel from a path containing spaces"
    }
    Write-Output "PASS: Windows first install $($installedPackage.version) under $PowerShellCommand"
} finally {
    [Environment]::SetEnvironmentVariable('Path', $savedUserPath, 'User')
    $env:Path = $savedProcessPath
    foreach ($key in $savedConfig.Keys) {
        [Environment]::SetEnvironmentVariable($key, $savedConfig[$key], 'Process')
    }
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
