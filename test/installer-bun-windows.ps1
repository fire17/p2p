# Real, pinned Bun runtime plus actual generated Windows launchers. This test
# mutates user PATH only on a disposable CI runner and restores it in finally.
param(
    [ValidateSet('pwsh', 'powershell.exe')][string]$PowerShellCommand = 'pwsh',
    [string]$BunArchive = ''
)
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This installer integration test requires a disposable GitHub Actions Windows runner.'
}
$expectedEdition = if ($PowerShellCommand -eq 'powershell.exe') { 'Desktop' } else { 'Core' }
if ($PSVersionTable.PSEdition -ne $expectedEdition) { throw "Run this test under $PowerShellCommand." }
$shellExe = (Get-Command $PowerShellCommand -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$nodeExe = (Get-Command node -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$repoPath = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('p2p bun windows ' + [guid]::NewGuid().ToString('N'))
$savedUserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$savedProcessPath = $env:Path
$savedProgress = $ProgressPreference
$savedConfig = @{}
foreach ($key in @('P2P_HOME', 'P2P_BIN_DIR', 'P2P_SRC', 'P2P_SRC_SUMS', 'P2P_RUNTIME', 'P2P_NODE_DIST', 'P2P_BUN_DIST', 'P2P_FORCE_BUN_BOOTSTRAP', 'P2P_INSTALLER_TEST_SOURCE')) {
    $savedConfig[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}
$server = $null
function Run-Shim([string]$shim, [string[]]$arguments) {
    $priorPreference = $ErrorActionPreference
    try {
        # Capture expected error exits as data under both native shell adapters.
        $ErrorActionPreference = 'Continue'
        if ($shim.EndsWith('.ps1')) { $output = & $shellExe -NoProfile -NonInteractive -File $shim @arguments 2>&1 | Out-String }
        else { $output = & $shim @arguments 2>&1 | Out-String }
        $code = $LASTEXITCODE
        return [PSCustomObject]@{ Code = $code; Output = $output }
    } finally { $ErrorActionPreference = $priorPreference }
}
function Verify-Shims {
    $kind = (Get-Content -LiteralPath (Join-Path $env:P2P_HOME 'runtime.kind') -Raw).Trim()
    if ($kind -ne 'bun') { throw 'Installer failed to persist selected Bun runtime.' }
    $runtimePath = Join-Path $env:P2P_HOME 'runtime.path'
    $selectedRuntime = (Get-Content -LiteralPath $runtimePath -Raw -Encoding UTF8).Trim()
    if (-not (Test-Path -LiteralPath $selectedRuntime)) { throw 'Pinned runtime is absent.' }
    $shims = @((Join-Path $env:P2P_BIN_DIR 'p2p.cmd'), (Join-Path $env:P2P_BIN_DIR 'p2p.ps1'))
    foreach ($shim in $shims) {
        $helpResult = Run-Shim $shim @('tunnel', '--help')
        if ($helpResult.Code -ne 0 -or $helpResult.Output -notmatch 'tunnel') { throw "Actual p2p help failed through $shim : $($helpResult.Output)" }
    }
    # Keep a real stale Node executable at the old preferred location. The
    # instrumented entry identifies the executable actually chosen by each shim.
    $legacy = Join-Path $env:P2P_HOME 'runtime'
    New-Item -ItemType Directory -Path $legacy -Force | Out-Null
    Copy-Item -LiteralPath $nodeExe -Destination (Join-Path $legacy 'node.exe')
    [IO.File]::WriteAllText((Join-Path $env:P2P_HOME 'node.path'), $nodeExe)
    $entry = Join-Path $env:P2P_HOME 'app/bin/p2p.js'
    [IO.File]::WriteAllText($entry, 'console.log(JSON.stringify({bun:process.versions.bun||null,args:process.argv.slice(2)}))')
    $expectedArguments = @('text with spaces', 'C:\folder with spaces\file.txt', '--literal')
    foreach ($shim in $shims) {
        $result = Run-Shim $shim $expectedArguments
        if ($result.Code -ne 0) { throw "Runtime probe failed through $shim : $($result.Output)" }
        $observed = $result.Output | ConvertFrom-Json
        if (-not $observed.bun -or [version]$observed.bun -lt [version]'1.4.2') { throw "Generated $shim executed Node or old Bun." }
        if (($observed.args | ConvertTo-Json -Compress) -cne ($expectedArguments | ConvertTo-Json -Compress)) { throw "Generated $shim changed argument boundaries." }
    }
    [IO.File]::WriteAllText($runtimePath, (Join-Path $testRoot 'missing selected runtime.exe'))
    foreach ($shim in $shims) {
        $missing = Run-Shim $shim @('probe')
        if ($missing.Code -eq 0 -or $missing.Output -notmatch 'selected runtime is missing') { throw "Missing runtime refusal failed through $shim : $($missing | ConvertTo-Json -Compress)" }
    }
    Remove-Item -LiteralPath $runtimePath
    foreach ($shim in $shims) {
        $missing = Run-Shim $shim @('probe')
        if ($missing.Code -eq 0 -or $missing.Output -notmatch 'selected runtime path is missing') { throw "Missing metadata refusal failed through $shim : $($missing | ConvertTo-Json -Compress)" }
    }
    Write-Output 'PASS: actual Bun cmd/ps1 launchers preserve spaces, override stale Node, and refuse missing runtime or metadata.'
}
try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
        $targetName = 'bun-windows-aarch64'
        $officialHash = 'a7a16b876a305fd1029c66dbd27007b4f6112ae896532f675878731a21e50cfd'
    } else {
        $targetName = 'bun-windows-x64-baseline'
        $officialHash = '78c221c2376f79731ccf4e4af0b3bb46d81fefa3296c5abee09ad8a1b21e68c6'
    }
    $archiveName = "$targetName.zip"
    $archive = Join-Path $testRoot $archiveName
    if ($BunArchive) { Copy-Item -LiteralPath $BunArchive -Destination $archive }
    else {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/$archiveName" -OutFile $archive -UseBasicParsing
    }
    $actualHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -cne $officialHash) { throw 'Official Bun 1.4.2 fixture archive checksum differs from its frozen release hash.' }
    [IO.File]::WriteAllText((Join-Path $testRoot 'SHASUMS256.txt'), "$actualHash  $archiveName`n")
    [IO.File]::WriteAllText((Join-Path $testRoot 'bad-sums.txt'), (('0' * 64) + "  $archiveName`n"))
    $expanded = Join-Path $testRoot 'existing runtime'
    Expand-Archive -LiteralPath $archive -DestinationPath $expanded
    $existingBunDir = Join-Path $expanded $targetName
    $source = Join-Path $testRoot 'source'
    New-Item -ItemType Directory -Path $source | Out-Null
    foreach ($name in @('bin', 'src', 'package.json')) { Copy-Item -LiteralPath (Join-Path $repoPath $name) -Destination $source -Recurse }

    $ready = Join-Path $testRoot 'ready.json'
    $serverInfo = New-Object Diagnostics.ProcessStartInfo
    $serverInfo.FileName = $nodeExe
    $serverInfo.Arguments = '"' + (Join-Path $PSScriptRoot 'fixtures/bun-installer-http.cjs') + '"'
    $serverInfo.UseShellExecute = $false
    $serverInfo.CreateNoWindow = $true
    $serverInfo.EnvironmentVariables['P2P_BUN_HTTP_ROOT'] = $testRoot
    $serverInfo.EnvironmentVariables['P2P_BUN_HTTP_READY'] = $ready
    $serverInfo.EnvironmentVariables['P2P_BUN_HTTP_ARCHIVE'] = $archiveName
    $server = [Diagnostics.Process]::Start($serverInfo)
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $ready)) {
        if ($server.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'Bun HTTP fixture failed to start.' }
        Start-Sleep -Milliseconds 50
    }
    $baseUrl = (Get-Content -LiteralPath $ready -Raw | ConvertFrom-Json).url
    $env:P2P_RUNTIME = 'bun'
    $env:P2P_SRC = $source
    $env:P2P_NODE_DIST = 'file:///node-must-not-be-downloaded'
    $env:P2P_INSTALLER_TEST_SOURCE = Join-Path $repoPath 'init.ps1'
    foreach ($case in @('existing', 'bootstrap', 'bad')) {
        $env:P2P_RUNTIME = 'bun'
        $env:Path = $existingBunDir + ';' + $savedProcessPath
        $env:P2P_HOME = Join-Path $testRoot "$case state with spaces"
        $env:P2P_BIN_DIR = Join-Path $testRoot "$case bin with spaces"
        $env:P2P_FORCE_BUN_BOOTSTRAP = if ($case -eq 'existing') { '0' } else { '1' }
        $env:P2P_BUN_DIST = if ($case -eq 'bad') { "$baseUrl/bad" } elseif ($case -eq 'existing') { 'file:///bun-bootstrap-must-not-run' } else { "$baseUrl/good" }
        $outputFile = Join-Path $testRoot "$case.out"
        & $shellExe -NoProfile -NonInteractive -Command 'Get-Content -LiteralPath $env:P2P_INSTALLER_TEST_SOURCE -Raw -Encoding UTF8 | Invoke-Expression' *> $outputFile
        $installCode = $LASTEXITCODE
        $output = Get-Content -LiteralPath $outputFile -Raw
        if ($case -eq 'bad') {
            if ($installCode -eq 0 -or $output -notmatch 'Bun checksum MISMATCH') { throw "Bad Bun checksum was not refused: $output" }
            foreach ($path in @('app', 'bun-runtime', 'runtime.kind', 'runtime.path')) {
                if (Test-Path -LiteralPath (Join-Path $env:P2P_HOME $path)) { throw "Bad archive installed $path." }
            }
            if (Test-Path -LiteralPath $env:P2P_BIN_DIR) { throw 'Bad archive installed launchers.' }
            Write-Output 'PASS: binary HTTP manifest mismatch refused before Bun execution, app installation, or launcher writes.'
            continue
        }
        if ($installCode -ne 0) { throw "$case Bun install failed: $output" }
        $hasPrivate = Test-Path -LiteralPath (Join-Path $env:P2P_HOME 'bun-runtime/bun.exe')
        if (($case -eq 'bootstrap') -ne $hasPrivate) { throw 'Existing/forced Bun discovery did not follow the requested path.' }
        $env:P2P_RUNTIME = ''
        $env:P2P_FORCE_BUN_BOOTSTRAP = '0'
        $env:P2P_BUN_DIST = 'file:///update-must-reuse-selected-bun'
        & $shellExe -NoProfile -NonInteractive -Command 'Get-Content -LiteralPath $env:P2P_INSTALLER_TEST_SOURCE -Raw -Encoding UTF8 | Invoke-Expression' *> $outputFile
        if ($LASTEXITCODE -ne 0) { throw "Plain update failed: $(Get-Content -LiteralPath $outputFile -Raw)" }
        Verify-Shims
        Write-Output "PASS: $case actual Bun 1.4.2 install under $PowerShellCommand."
    }
} finally {
    if ($server -and -not $server.HasExited) { $server.Kill(); $server.WaitForExit() }
    [Environment]::SetEnvironmentVariable('Path', $savedUserPath, 'User')
    $env:Path = $savedProcessPath
    $ProgressPreference = $savedProgress
    foreach ($key in $savedConfig.Keys) { [Environment]::SetEnvironmentVariable($key, $savedConfig[$key], 'Process') }
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
# Expected refusal cases deliberately run native commands that exit nonzero.
# Reach this only after every assertion and cleanup has succeeded.
$global:LASTEXITCODE = 0
