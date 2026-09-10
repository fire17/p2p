# Real HTTP Content marshalling and remote ZIP integrity, using loopback assets only.
# -ContractOnly is safe on developer machines: no install and no user PATH writes.
param(
    [ValidateSet('pwsh', 'powershell.exe')]
    [string]$PowerShellCommand = 'pwsh',
    [switch]$ContractOnly
)

$ErrorActionPreference = 'Stop'
if (-not $ContractOnly) {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
        throw 'Full installer checks require a disposable GitHub Actions Windows runner; use -ContractOnly locally'
    }
    $expectedEdition = if ($PowerShellCommand -eq 'powershell.exe') { 'Desktop' } else { 'Core' }
    if ($PSVersionTable.PSEdition -ne $expectedEdition) { throw "Run this test under $PowerShellCommand" }
}
$repoPath = Split-Path -Parent $PSScriptRoot
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('p2p http smoke ' + [guid]::NewGuid().ToString('N'))
$server = $null
$savedUserPath = if (-not $ContractOnly) { [Environment]::GetEnvironmentVariable('Path', 'User') } else { $null }
$savedProcessPath = $env:Path
$savedConfig = @{}
foreach ($key in @('P2P_HOME', 'P2P_BIN_DIR', 'P2P_SRC', 'P2P_SRC_SUMS', 'P2P_NODE_DIST', 'P2P_FORCE_NODE_BOOTSTRAP', 'P2P_INSTALLER_TEST_SOURCE')) {
    $savedConfig[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}
try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $manifest = ('a' * 64) + "  asset.zip`n"
    [IO.File]::WriteAllText((Join-Path $testRoot 'SHASUMS256.txt'), $manifest, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $testRoot 'text-sums.txt'), $manifest, [Text.UTF8Encoding]::new($false))

    $readyPath = Join-Path $testRoot 'ready.json'
    $serverInfo = New-Object Diagnostics.ProcessStartInfo
    $serverInfo.FileName = (Get-Command node -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $serverInfo.Arguments = '"' + (Join-Path $PSScriptRoot 'fixtures/installer-http.cjs') + '"'
    $serverInfo.UseShellExecute = $false
    $serverInfo.CreateNoWindow = $true
    $serverInfo.EnvironmentVariables['P2P_INSTALLER_HTTP_ROOT'] = $testRoot
    $serverInfo.EnvironmentVariables['P2P_INSTALLER_HTTP_READY'] = $readyPath
    $server = [Diagnostics.Process]::Start($serverInfo)
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $readyPath)) {
        if ($server.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'Loopback fixture server failed to start' }
        Start-Sleep -Milliseconds 50
    }
    $baseUrl = (Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json).url

    # Load the actual installer function, without executing the installer. Log is
    # the only stub; Invoke-WebRequest and its .Content object are real.
    $installerText = Get-Content -LiteralPath (Join-Path $repoPath 'init.ps1') -Raw -Encoding UTF8
    $parseTokens = $null; $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($installerText, [ref]$parseTokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw 'Installer source did not parse' }
    $functionAst = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'DownloadText' }, $true)
    if ($functionAst.Count -ne 1) { throw 'Expected exactly one actual DownloadText function' }
    function Log([string]$message) {}
    . ([scriptblock]::Create($functionAst[0].Extent.Text))
    foreach ($suffix in @('/SHASUMS256.txt', '/assets/text-sums.txt')) {
        $rawContent = (Invoke-WebRequest -Uri ($baseUrl + $suffix) -UseBasicParsing).Content
        Write-Output "Content type under $($PSVersionTable.PSVersion): $($rawContent.GetType().FullName) ($suffix)"
        $downloadedText = DownloadText ($baseUrl + $suffix)
        if ($downloadedText -isnot [string] -or $downloadedText -cne $manifest) {
            throw "DownloadText changed HTTP manifest bytes/type: $($downloadedText.GetType().FullName)"
        }
        Write-Output "PASS: actual DownloadText returns exact manifest string ($suffix)"
    }

    if (-not $ContractOnly) {
        $shellExe = (Get-Command $PowerShellCommand -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
        $archiveRoot = Join-Path $testRoot 'p2p-fixture'
        New-Item -ItemType Directory -Path $archiveRoot | Out-Null
        foreach ($entry in @('bin', 'src', 'package.json')) {
            Copy-Item -LiteralPath (Join-Path $repoPath $entry) -Destination $archiveRoot -Recurse
        }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zipPath = Join-Path $testRoot 'asset.zip'
        [IO.Compression.ZipFile]::CreateFromDirectory($archiveRoot, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $true)
        $digest = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLower()
        [IO.File]::WriteAllText((Join-Path $testRoot 'SHASUMS256.txt'), "$digest  asset.zip`n", [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $testRoot 'bad-sums.txt'), (('0' * 64) + "  asset.zip`n"), [Text.UTF8Encoding]::new($false))

        $env:P2P_SRC = "$baseUrl/assets/asset.zip"
        $env:P2P_NODE_DIST = 'file:///p2p-installer-smoke-network-disabled'
        $env:P2P_FORCE_NODE_BOOTSTRAP = '0'
        $env:P2P_INSTALLER_TEST_SOURCE = Join-Path $repoPath 'init.ps1'
        foreach ($case in @('good', 'bad')) {
            $env:P2P_HOME = Join-Path $testRoot "$case state"
            $env:P2P_BIN_DIR = Join-Path $testRoot "$case bin"
            $env:P2P_SRC_SUMS = if ($case -eq 'good') { "$baseUrl/SHASUMS256.txt" } else { "$baseUrl/assets/bad-sums.txt" }
            $outputFile = Join-Path $testRoot "$case.out"
            & $shellExe -NoProfile -NonInteractive -Command 'Get-Content -LiteralPath $env:P2P_INSTALLER_TEST_SOURCE -Raw -Encoding UTF8 | Invoke-Expression' *> $outputFile
            $installCode = $LASTEXITCODE
            $output = Get-Content -LiteralPath $outputFile -Raw
            $appPackage = Join-Path $env:P2P_HOME 'app/package.json'
            if ($case -eq 'bad') {
                if ($installCode -eq 0 -or (Test-Path -LiteralPath $appPackage) -or $output -notmatch 'checksum MISMATCH') {
                    throw "Bad checksum was not refused for the right reason (exit $installCode): $output"
                }
                if (Test-Path -LiteralPath (Join-Path $env:P2P_BIN_DIR 'p2p.cmd')) { throw 'Rejected archive installed a launcher' }
                Write-Output 'PASS: remote bad checksum refused before app or launcher installation'
                continue
            }
            if ($installCode -ne 0 -or -not (Test-Path -LiteralPath $appPackage) -or $output -notmatch 'source sha256 verified') {
                throw "Remote ZIP install failed (exit $installCode): $output"
            }
            $sourceVersion = (Get-Content -LiteralPath (Join-Path $repoPath 'package.json') -Raw | ConvertFrom-Json).version
            $installedVersion = (Get-Content -LiteralPath $appPackage -Raw | ConvertFrom-Json).version
            if ($installedVersion -ne $sourceVersion) { throw 'Remote ZIP installed the wrong version' }
            foreach ($shim in @('p2p.ps1', 'p2p.cmd')) {
                $shimPath = Join-Path $env:P2P_BIN_DIR $shim
                if ($shim -eq 'p2p.ps1') {
                    $helpText = & $shellExe -NoProfile -NonInteractive -File $shimPath tunnel --help 2>&1 | Out-String
                } else { $helpText = & $shimPath tunnel --help 2>&1 | Out-String }
                if ($LASTEXITCODE -ne 0 -or $helpText -notmatch 'tunnel') { throw "Remote-installed $shim failed: $helpText" }
                Write-Output "PASS: remote ZIP-installed $shim invokes tunnel under $PowerShellCommand"
            }
            Write-Output "PASS: remote octet-stream manifest verified and installed $installedVersion"
        }
    }
} finally {
    if ($server -and -not $server.HasExited) { $server.Kill(); $server.WaitForExit() }
    if (-not $ContractOnly) { [Environment]::SetEnvironmentVariable('Path', $savedUserPath, 'User') }
    $env:Path = $savedProcessPath
    foreach ($key in $savedConfig.Keys) { [Environment]::SetEnvironmentVariable($key, $savedConfig[$key], 'Process') }
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
