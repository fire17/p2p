<#
  p2p installer — Windows.  (Linux/macOS: the POSIX `init` script)

    irm p2p.akeyo.io/init.ps1 | iex                        install, then print next steps
    & ([scriptblock]::Create((irm p2p.akeyo.io/init.ps1))) KEY     install, then chat with KEY
    .\init.ps1 KEY            install, then chat with KEY's owner
    .\init.ps1 -Force         reinstall even if already up to date

  What it does, without admin rights and without a package manager:
    1. finds a node >= 22 (PATH, or %USERPROFILE%\.p2p\runtime); if none, downloads a
       PORTABLE node zip and verifies it against nodejs.org's SHASUMS256.txt
    2. fetches the p2p source into %USERPROFILE%\.p2p\app  (skips if already up to date)
    3. drops p2p.cmd + p2p.ps1 in %USERPROFILE%\.local\bin and adds that dir to the
       *user* PATH (setx-equivalent, no admin)
    4. logs every step to %USERPROFILE%\.p2p\install.log — on ANY failure it prints that path

  Your identity/friends (~\.p2p\*.json) are NEVER touched by an update.
  PowerShell 5.1+ compatible.
#>

[CmdletBinding()]
param(
  [Parameter(Position = 0)][string]$Key = '',
  [Alias('Reinstall')][switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ── config (override via env) ───────────────────────────────────────────────────
# PRODUCTION DEFAULT: a PINNED release of the p2p repo (an immutable tag — NEVER the
# floating `main` branch). The source archive is fetched as a release asset and
# SHA256-verified against its SHASUMS256.txt manifest BEFORE extraction (fail CLOSED),
# exactly the way the node runtime is already verified. See docs/RELEASE-SIGNING.md.
#   - Why not `main`: a moving branch means a compromised push or a MITM of the archive
#     would be executed with zero verification.
#   - Why still "latest": the /init.ps1 served from the site is regenerated to the newest
#     release tag on every release, so `irm … | iex` still installs the latest version.
# Overrides (local testing / private forks):
#   P2P_REF       release tag to install                 (default: the newest release)
#   P2P_SRC       a local DIRECTORY (trusted, unverified), OR a .zip/.tar.gz URL
#                 (checksum-verified against P2P_SRC_SUMS).
#   P2P_SRC_SUMS  URL/path of the SHASUMS256.txt covering the P2P_SRC archive.
#   P2P_RUNTIME   node (default) or bun. Bun is installed privately when absent.
#   P2P_BUN_DIST  mirror of the pinned Bun release (must include SHASUMS256.txt).
$Ref        = if ($env:P2P_REF) { $env:P2P_REF } else { 'v0.3.6' }
$SrcDefault = "https://github.com/fire17/p2p/releases/download/$Ref/p2p-$Ref.zip"
$Src        = if ($env:P2P_SRC) { $env:P2P_SRC } else { $SrcDefault }
$Sums       = if ($env:P2P_SRC_SUMS) { $env:P2P_SRC_SUMS } else { "https://github.com/fire17/p2p/releases/download/$Ref/SHASUMS256.txt" }
$NodeDist   = if ($env:P2P_NODE_DIST) { $env:P2P_NODE_DIST } else { 'https://nodejs.org/dist/latest-v22.x' }
$NodeMin    = 22
$RuntimeKind = if ($env:P2P_RUNTIME) { $env:P2P_RUNTIME.ToLower() } else { '' }
$BunDist = if ($env:P2P_BUN_DIST) { $env:P2P_BUN_DIST } else { 'https://github.com/oven-sh/bun/releases/download/bun-v1.4.2' }
$UserHome   = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$P2pHome    = if ($env:P2P_HOME) { $env:P2P_HOME } else { Join-Path $UserHome '.p2p' }
$BinDir     = if ($env:P2P_BIN_DIR) { $env:P2P_BIN_DIR } else { Join-Path $UserHome '.local\bin' }
$AppDir     = Join-Path $P2pHome 'app'
$RuntimeDir = Join-Path $P2pHome 'runtime'
$LogFile    = Join-Path $P2pHome 'install.log'
if (-not $RuntimeKind) {
  $savedKind = Join-Path $P2pHome 'runtime.kind'
  $RuntimeKind = if (Test-Path -LiteralPath $savedKind) { (Get-Content -LiteralPath $savedKind -Raw).Trim() } else { 'node' }
}

# a bare positional key may arrive with a leading flag-ish token from `iex` forms
if ($Key -match '^-') { $Key = '' }

# ── logging + failure reporting ─────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $P2pHome | Out-Null
$script:Step = 'startup'
function Stamp { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Log([string]$m) { try { Add-Content -Path $LogFile -Value ("[{0}] {1}" -f (Stamp), $m) -Encoding UTF8 } catch {} }
function Step([string]$s) { $script:Step = $s; Log "STEP $s" }
function Say([string]$m, [string]$color = 'Gray') { Write-Host ("  " + $m) -ForegroundColor $color }

function Fail([string]$msg) {
  Log "FAILED during step '$script:Step'"
  Log "--- error ---"; Log $msg; Log "--- end ---"
  Write-Host ""
  Write-Host "  x p2p install FAILED (step: $script:Step)" -ForegroundColor Red
  foreach ($line in ($msg -split "`n")) { Write-Host ("    " + $line) -ForegroundColor Red }
  Write-Host ""
  Write-Host "  full log:  $LogFile" -ForegroundColor Yellow
  Write-Host "  please send this file to us for debugging." -ForegroundColor Yellow
  Write-Host ""
  if ($script:Tmp -and (Test-Path $script:Tmp)) { Remove-Item -Recurse -Force $script:Tmp -ErrorAction SilentlyContinue }
  exit 1
}

$script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("p2p-install-" + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $script:Tmp | Out-Null

try {
  if ($RuntimeKind -notin @('node', 'bun')) { Fail 'P2P_RUNTIME must be node or bun' }
  # TLS 1.2 — PS 5.1 on older Windows still defaults to SSL3/TLS1.0 and nodejs.org refuses it
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol } catch {}

  # ── platform ──────────────────────────────────────────────────────────────────
  Step 'detect-platform'
  $archRaw = $env:PROCESSOR_ARCHITECTURE
  if (-not $archRaw) { $archRaw = 'AMD64' }
  switch -Regex ($archRaw) {
    'ARM64'        { $NArch = 'arm64'; break }
    'AMD64|x86_64' { $NArch = 'x64';   break }
    'x86'          { $NArch = 'x86';   break }
    default        { Fail "unsupported CPU arch '$archRaw' — no portable node build exists for it" }
  }
  $NodePlat = "win-$NArch"

  Log "=============================================================="
  Log "p2p install start — OS=Windows ARCH=$archRaw node-target=$NodePlat"
  Log "HOME=$UserHome P2P_HOME=$P2pHome src=$Src force=$($Force.IsPresent) key=$(if($Key){$Key}else{'<none>'})"
  Write-Host ""
  Say "p2p installer  ·  Windows/$archRaw" 'Cyan'

  function Download([string]$url, [string]$out) {
    Log "GET $url -> $out"
    try {
      $pp = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
      Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
      $ProgressPreference = $pp
    } catch { throw "download failed: $url`n  $($_.Exception.Message)" }
  }
  function DownloadText([string]$url) {
    Log "GET $url"
    try {
      $content = (Invoke-WebRequest -Uri $url -UseBasicParsing).Content
      # GitHub release assets use application/octet-stream: PowerShell 7 returns
      # byte[] here. Decode before returning, or the pipeline enumerates the bytes
      # and the caller receives Object[] instead of checksum-manifest text.
      if ($content -is [byte[]]) { return [Text.Encoding]::UTF8.GetString($content) }
      if ($content -is [string]) { return $content }
      throw 'unexpected response content type for text download'
    } catch { throw "download failed: $url`n  $($_.Exception.Message)" }
  }
  # read a manifest from either a local path (tests/private forks) or an http(s) URL
  function ReadOrDownload([string]$src) {
    if (Test-Path -LiteralPath $src) { return (Get-Content -Raw -LiteralPath $src) }
    return (DownloadText $src)
  }
  # verify a downloaded SOURCE archive against its SHASUMS256.txt manifest. FAIL CLOSED —
  # Fail() (never warn-and-proceed) on: no/empty manifest, no matching entry, or a hash
  # mismatch. Get-FileHash ships with PowerShell 5.1+, so (unlike the POSIX path) there is
  # no "no hash tool" case on Windows. Mirrors the node path; see docs/RELEASE-SIGNING.md.
  # NOTE: a same-repo checksum stops a tampered DOWNLOAD (MITM/bad mirror), not an attacker
  # who can rewrite the repo itself (they rewrite the manifest too) — for that verify the
  # manifest's signature (RELEASE-SIGNING.md).
  function VerifySourceArchive([string]$archive) {
    Step 'verify-source-checksum'
    $got = (Get-FileHash -Path $archive -Algorithm SHA256).Hash.ToLower()
    if (-not $Sums) { Fail "no source checksum manifest (P2P_SRC_SUMS is empty) — refusing to install an unverified source archive.`n  set P2P_SRC_SUMS to its SHASUMS256.txt, or point P2P_SRC at a trusted local directory." }
    Say "v verifying source integrity..."
    $sumsText = ReadOrDownload $Sums
    $name = Split-Path -Leaf $Src
    $line = ($sumsText -split "`n") | Where-Object { $_ -match ("\s+" + [Regex]::Escape($name) + "\s*$") } | Select-Object -First 1
    if (-not $line) { Fail "the source manifest ($Sums) has no SHA256 entry for '$name' — is it the right manifest for this archive?" }
    $want = (($line.Trim() -split '\s+')[0]).ToLower()
    if ($got -ne $want) { Fail "source checksum MISMATCH for $name`n  expected $want`n  got      $got`n  the downloaded p2p source does not match its manifest — refusing to install." }
    Say "  + source sha256 verified  ·  $name" 'Green'
    Log "source sha256 OK: $name = $got"
  }

  # ── 1. selected runtime ──────────────────────────────────────────────────────
  $Node = $null  # historical name; this is the selected executable, Node or Bun
  if ($RuntimeKind -eq 'bun') {
    Step 'find-bun'
    function BunOk([string]$exe) {
      if (-not $exe) { return $false }
      try {
        $v = & $exe -e 'process.stdout.write(String(process.versions.bun||0))' 2>$null
        return ($LASTEXITCODE -eq 0 -and [version]($v -split '-')[0] -ge [version]'1.4.2')
      } catch { return $false }
    }
    $bunRuntime = Join-Path $P2pHome 'bun-runtime'
    $bunCandidates = @((Join-Path $bunRuntime 'bun.exe'), (Join-Path $UserHome '.bun\bin\bun.exe'))
    $pathBun = Get-Command bun -ErrorAction SilentlyContinue
    if ($pathBun) { $bunCandidates += $pathBun.Source }
    if ($env:P2P_FORCE_BUN_BOOTSTRAP -ne '1') {
      foreach ($candidate in $bunCandidates) {
        if ((Test-Path -LiteralPath $candidate) -and (BunOk $candidate)) { $Node = $candidate; break }
      }
    }
    if (-not $Node) {
      switch ($NArch) {
        'x64' { $bunTarget = 'bun-windows-x64-baseline' }
        'arm64' { $bunTarget = 'bun-windows-aarch64' }
        default { Fail "Bun has no portable Windows build for $NArch; use P2P_RUNTIME=node" }
      }
      $bunZipName = "$bunTarget.zip"
      Step 'bun-shasums'
      $bunSums = DownloadText "$BunDist/SHASUMS256.txt"
      $bunLine = ($bunSums -split "`n") | Where-Object { $_ -match ("\s+" + [Regex]::Escape($bunZipName) + "\s*$") } | Select-Object -First 1
      if (-not $bunLine) { Fail "Bun manifest has no SHA256 entry for $bunZipName" }
      $bunWant = ($bunLine.Trim() -split '\s+')[0].ToLower()
      Step 'bun-download'
      Say 'v downloading private Bun 1.4.2 (no global runtime changes)...' 'Yellow'
      $bunZip = Join-Path $script:Tmp $bunZipName
      Download "$BunDist/$bunZipName" $bunZip
      Step 'bun-verify-checksum'
      $bunGot = (Get-FileHash -LiteralPath $bunZip -Algorithm SHA256).Hash.ToLower()
      if ($bunWant -ne $bunGot) { Fail "Bun checksum MISMATCH for $bunZipName" }
      Step 'bun-extract'
      $bunExtract = Join-Path $script:Tmp 'bunx'
      Expand-Archive -LiteralPath $bunZip -DestinationPath $bunExtract -Force
      $bunCandidate = Join-Path (Join-Path $bunExtract $bunTarget) 'bun.exe'
      if (-not (Test-Path -LiteralPath $bunCandidate) -or -not (BunOk $bunCandidate)) { Fail 'The verified Bun archive does not contain a working Bun >=1.4.2' }
      New-Item -ItemType Directory -Force -Path $bunRuntime | Out-Null
      Copy-Item -LiteralPath $bunCandidate -Destination (Join-Path $bunRuntime 'bun.exe') -Force
      $Node = Join-Path $bunRuntime 'bun.exe'
    }
    Say ("+ bun " + (& $Node --version) + " (>=1.4.2)  ·  $Node") 'Green'
    Log "using Bun: $Node"
  } else {
  # Node remains the default and retains the existing verified bootstrap.
  Step 'find-node'
  function NodeMajor([string]$exe) {
    try { $v = & $exe -e 'process.stdout.write(String(parseInt(process.versions.node)))' 2>$null; return [int]$v } catch { return 0 }
  }
  function NodeOk([string]$exe) {
    if (-not $exe) { return $false }
    try { return (NodeMajor $exe) -ge $NodeMin } catch { return $false }
  }

  $Node = $null
  $runtimeNode = Join-Path $RuntimeDir 'node.exe'
  if ($env:P2P_FORCE_NODE_BOOTSTRAP -eq '1') {
    Log 'P2P_FORCE_NODE_BOOTSTRAP=1 — skipping node discovery'
  } elseif ((Test-Path $runtimeNode) -and (NodeOk $runtimeNode)) {
    $Node = $runtimeNode
    Log "using bootstrapped node: $Node"
  } else {
    $onPath = (Get-Command node -ErrorAction SilentlyContinue)
    if ($onPath -and (NodeOk $onPath.Source)) { $Node = $onPath.Source; Log "using PATH node: $Node" }
    elseif ($onPath) { Log "PATH node too old: $($onPath.Source)" }
  }

  if ($Node) {
    Say ("+ node " + (& $Node --version) + " (>= v$NodeMin)  ·  $Node") 'Green'
  } else {
    Say "v no node >= v$NodeMin found - downloading a portable one (no admin, no package manager)..." 'Yellow'

    Step 'node-shasums'
    $sums = DownloadText "$NodeDist/SHASUMS256.txt"
    $line = ($sums -split "`n") | Where-Object { $_ -match "\s+node-v[\d.]+-$NodePlat\.zip\s*$" } | Select-Object -First 1
    if (-not $line) { Fail "nodejs.org has no $NodePlat build in $NodeDist" }
    $parts   = ($line.Trim() -split '\s+')
    $wantSha = $parts[0]
    $zipName = $parts[1]
    Log "node zip=$zipName sha256=$wantSha"

    Step 'node-download'
    Say "  v $zipName"
    $zipPath = Join-Path $script:Tmp $zipName
    Download "$NodeDist/$zipName" $zipPath

    Step 'node-verify-checksum'
    $gotSha = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
    if ($gotSha -ne $wantSha.ToLower()) {
      Fail "checksum MISMATCH for $zipName`n  expected $wantSha`n  got      $gotSha"
    }
    Say "  + sha256 verified" 'Green'

    Step 'node-extract'
    $exTmp = Join-Path $script:Tmp 'nodex'
    New-Item -ItemType Directory -Force -Path $exTmp | Out-Null
    try {
      Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
      [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $exTmp)
    } catch { Expand-Archive -Path $zipPath -DestinationPath $exTmp -Force }
    # the zip has a single top-level dir (node-vX-win-x64) — flatten it
    $inner = Get-ChildItem -Path $exTmp -Directory | Select-Object -First 1
    if (-not $inner) { Fail "the extracted node archive has no top-level directory" }
    $newRt = "$RuntimeDir.new"
    if (Test-Path $newRt) { Remove-Item -Recurse -Force $newRt }
    Move-Item -Path $inner.FullName -Destination $newRt
    $cand = Join-Path $newRt 'node.exe'
    if (-not (Test-Path $cand)) { Fail "the extracted node archive has no node.exe" }

    Step 'node-verify-runs'
    if (-not (NodeOk $cand)) { Fail "the downloaded node does not run, or reports < v$NodeMin" }
    if (Test-Path $RuntimeDir) { Remove-Item -Recurse -Force $RuntimeDir }
    Move-Item -Path $newRt -Destination $RuntimeDir
    $Node = Join-Path $RuntimeDir 'node.exe'
    Say ("+ node " + (& $Node --version) + " installed to $RuntimeDir") 'Green'
    Log "bootstrapped node at $Node"
  }

  }

  # remember WHICH node worked, so legacy shims keep working after Node installs
  # later. Not a *.json file — user data (identity/friends) is untouched.
  if ($RuntimeKind -eq 'node') { try { Set-Content -LiteralPath (Join-Path $P2pHome 'node.path') -Value $Node -Encoding ASCII } catch {} }

  # ── 2. fetch the p2p source ───────────────────────────────────────────────────
  Step 'fetch-source'
  $stage = Join-Path $script:Tmp 'stage'
  New-Item -ItemType Directory -Force -Path $stage | Out-Null

  if (Test-Path -LiteralPath $Src -PathType Container) {
    # A local directory is an EXPLICIT operator choice (dev/test/private fork) — trusted,
    # so no checksum is applied here. Only remote ARCHIVES are verified (below).
    Log "P2P_SRC is a local directory — trusted, no checksum verification"
    Say "v copying p2p source from $Src"
    Get-ChildItem -LiteralPath $Src -Force |
      Where-Object { $_.Name -notin @('.git', 'node_modules', 'scratch') } |
      ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $stage -Recurse -Force }
  } elseif ($Src -match '\.zip$') {
    Say "v downloading p2p source..."
    $srcZip = Join-Path $script:Tmp 'src.zip'
    Download $Src $srcZip
    VerifySourceArchive $srcZip
    $exSrc = Join-Path $script:Tmp 'srcx'
    New-Item -ItemType Directory -Force -Path $exSrc | Out-Null
    try {
      Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
      [System.IO.Compression.ZipFile]::ExtractToDirectory($srcZip, $exSrc)
    } catch { Expand-Archive -Path $srcZip -DestinationPath $exSrc -Force }
    $top = Get-ChildItem -Path $exSrc -Directory | Select-Object -First 1   # github zips nest one dir
    if (-not $top) { Fail "the downloaded source zip is empty or malformed" }
    Get-ChildItem -LiteralPath $top.FullName -Force | ForEach-Object { Move-Item -LiteralPath $_.FullName -Destination $stage -Force }
  } elseif ($Src -match '\.tar\.gz$|\.tgz$') {
    Say "v downloading p2p source..."
    $srcTgz = Join-Path $script:Tmp 'src.tar.gz'
    Download $Src $srcTgz
    VerifySourceArchive $srcTgz
    # bsdtar ships with Windows 10 1803+ as tar.exe
    if (-not (Get-Command tar -ErrorAction SilentlyContinue)) { Fail "P2P_SRC is a .tar.gz but this Windows has no tar.exe — use the .zip URL instead" }
    & tar -xzf $srcTgz -C $stage --strip-components 1
    if ($LASTEXITCODE -ne 0) { Fail "tar could not extract the source archive" }
  } else {
    Fail "unsupported P2P_SRC '$Src' — use a local directory, a .zip URL, or a .tar.gz URL"
  }

  if (-not (Test-Path (Join-Path $stage 'package.json')) -or -not (Test-Path (Join-Path $stage 'bin\p2p.js'))) {
    Fail "the fetched source is missing package.json or bin\p2p.js — wrong URL?"
  }

  function PkgVersion([string]$pkgPath) {
    try { return (Get-Content -Raw -LiteralPath $pkgPath | ConvertFrom-Json).version } catch { return '' }
  }
  # semver-ish compare, prerelease tags ignored: -1 / 0 / 1 for $a vs $b
  function VerCmp([string]$a, [string]$b) {
    $pa = ($a -split '-')[0] -split '\.'; $pb = ($b -split '-')[0] -split '\.'
    for ($i = 0; $i -lt 3; $i++) {
      $x = 0; $y = 0
      if ($i -lt $pa.Count) { [void][int]::TryParse($pa[$i], [ref]$x) }
      if ($i -lt $pb.Count) { [void][int]::TryParse($pb[$i], [ref]$y) }
      if ($x -gt $y) { return 1 }
      if ($x -lt $y) { return -1 }
    }
    return 0
  }

  $newVer = PkgVersion (Join-Path $stage 'package.json')
  if (-not $newVer) { Fail "could not read a version out of the fetched package.json" }
  Log "fetched p2p version: $newVer"

  # ── 3. install / skip / update ────────────────────────────────────────────────
  Step 'version-check'
  $oldVer = ''
  $oldPkg = Join-Path $AppDir 'package.json'
  if (Test-Path $oldPkg) { $oldVer = PkgVersion $oldPkg }

  $action = 'install'
  if ($oldVer) {
    $cmp = VerCmp $oldVer $newVer
    Log "installed=$oldVer available=$newVer cmp=$cmp force=$($Force.IsPresent)"
    if ($Force.IsPresent) { $action = 'reinstall' }
    elseif ($cmp -lt 0)   { $action = 'update' }
    else                  { $action = 'skip' }
  }

  if ($action -eq 'skip') {
    Say "+ p2p $oldVer already installed and up to date (latest: $newVer) - skipping" 'Green'
    Say "  (re-run with -Force to reinstall)" 'DarkGray'
  } else {
    Step 'install-app'
    if ($action -eq 'update')    { Say "^ updating p2p $oldVer -> $newVer  (your identity + friends are preserved)" 'Cyan' }
    if ($action -eq 'reinstall') { Say "~ reinstalling p2p $newVer (-Force)" 'Cyan' }
    if ($action -eq 'install')   { Say "v installing p2p $newVer" 'Cyan' }
    # only .p2p\app is replaced. .p2p\*.json (identity, friends) and .p2p\runtime are
    # OUTSIDE app and are never touched.
    $appNew = "$AppDir.new"; $appOld = "$AppDir.old"
    foreach ($d in @($appNew, $appOld)) { if (Test-Path $d) { Remove-Item -Recurse -Force $d } }
    Move-Item -LiteralPath $stage -Destination $appNew
    if (Test-Path $AppDir) { Move-Item -LiteralPath $AppDir -Destination $appOld }
    try { Move-Item -LiteralPath $appNew -Destination $AppDir }
    catch {
      if (Test-Path $appOld) { Move-Item -LiteralPath $appOld -Destination $AppDir }
      Fail "could not move the new app into place (the old app was restored)`n  $($_.Exception.Message)"
    }
    if (Test-Path $appOld) { Remove-Item -Recurse -Force $appOld }
    Say "+ p2p $newVer installed to $AppDir" 'Green'
    Log "app installed: $action -> $newVer"
  }

  # ── 4. the `p2p` launcher on PATH ─────────────────────────────────────────────
  Step 'launcher'
  # Persist only after source verification/install succeeded.
  [IO.File]::WriteAllText((Join-Path $P2pHome 'runtime.path'), ($Node + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
  Set-Content -LiteralPath (Join-Path $P2pHome 'runtime.kind') -Value $RuntimeKind -Encoding ASCII
  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

  $cmdShim = Join-Path $BinDir 'p2p.cmd'
  $cmdBody = @'
@echo off
setlocal
if "%P2P_HOME%"=="" set "P2P_HOME=%USERPROFILE%\.p2p"
set "P2P_APP=%P2P_HOME%\app"
set "P2P_NODE="
if exist "%P2P_HOME%\runtime.kind" if not exist "%P2P_HOME%\runtime.path" goto runtime_path_missing
if not exist "%P2P_HOME%\runtime.path" goto legacy_runtime
for /f "usebackq delims=" %%N in ("%P2P_HOME%\runtime.path") do if exist "%%~N" set "P2P_NODE=%%~N"
if not defined P2P_NODE goto runtime_missing
goto runtime_ready
:legacy_runtime
if exist "%P2P_HOME%\runtime\node.exe" (
  set "P2P_NODE=%P2P_HOME%\runtime\node.exe"
) else (
  if exist "%P2P_HOME%\node.path" (
    for /f "usebackq delims=" %%N in ("%P2P_HOME%\node.path") do if exist "%%~N" set "P2P_NODE=%%~N"
  )
)
if "%P2P_NODE%"=="" set "P2P_NODE=node"
:runtime_ready
if not exist "%P2P_APP%\bin\p2p.js" (
  echo p2p: %P2P_APP% is missing. Re-run:  irm p2p.akeyo.io/init.ps1 ^| iex 1>&2
  exit /b 1
)
"%P2P_NODE%" "%P2P_APP%\bin\p2p.js" %*
exit /b %errorlevel%
:runtime_missing
echo p2p: selected runtime is missing. Re-run the installer. 1>&2
exit /b 1
:runtime_path_missing
echo p2p: selected runtime path is missing. Re-run the installer. 1>&2
exit /b 1
'@
  [IO.File]::WriteAllText($cmdShim, ($cmdBody -replace "`r?`n", "`r`n") + "`r`n", [Text.Encoding]::ASCII)

  $ps1Shim = Join-Path $BinDir 'p2p.ps1'
  $ps1Body = @'
#!/usr/bin/env pwsh
# p2p launcher (generated by the p2p installer — safe to delete along with ~\.p2p)
$p2pHome = if ($env:P2P_HOME) { $env:P2P_HOME } else { Join-Path $env:USERPROFILE '.p2p' }
$app     = Join-Path $p2pHome 'app'
$rtNode  = Join-Path $p2pHome 'runtime\node.exe'
$pinFile = Join-Path $p2pHome 'node.path'
$pinned  = if (Test-Path $pinFile) { (Get-Content -Raw $pinFile).Trim() } else { '' }
$runtimeFile = Join-Path $p2pHome 'runtime.path'
if ((Test-Path (Join-Path $p2pHome 'runtime.kind')) -and -not (Test-Path $runtimeFile)) { Write-Error 'p2p: selected runtime path is missing. Re-run the installer.'; exit 1 }
if (Test-Path $runtimeFile) {
  $node = (Get-Content -Raw -Encoding UTF8 $runtimeFile).Trim()
  if (-not (Test-Path -LiteralPath $node)) { Write-Error 'p2p: selected runtime is missing. Re-run the installer.'; exit 1 }
}
elseif (Test-Path $rtNode) { $node = $rtNode }
elseif ($pinned -and (Test-Path $pinned)) { $node = $pinned }
elseif (Get-Command node -ErrorAction SilentlyContinue) { $node = 'node' }
else { Write-Error 'p2p: no node >= 22 found. Re-run:  irm p2p.akeyo.io/init.ps1 | iex'; exit 1 }
$entry = Join-Path $app 'bin\p2p.js'
if (-not (Test-Path $entry)) { Write-Error "p2p: $app is missing. Re-run:  irm p2p.akeyo.io/init.ps1 | iex"; exit 1 }
& $node $entry @args
exit $LASTEXITCODE
'@
  Set-Content -LiteralPath $ps1Shim -Value $ps1Body -Encoding UTF8
  Say "+ launcher: $cmdShim" 'Green'
  Log "shims written: $cmdShim, $ps1Shim"

  # ── 5. PATH (user-scoped, no admin) ───────────────────────────────────────────
  Step 'path'
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not $userPath) { $userPath = '' }
  $already = ($userPath -split ';') | Where-Object { $_ -and ($_.TrimEnd('\') -ieq $BinDir.TrimEnd('\')) }
  $pathAdded = $false
  if (-not $already) {
    $newPath = if ($userPath.TrimEnd(';')) { $userPath.TrimEnd(';') + ';' + $BinDir } else { $BinDir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')   # persists, no admin needed
    $env:Path = "$env:Path;$BinDir"                                    # and for THIS process
    $pathAdded = $true
    Log "added $BinDir to the user PATH"
    Say "+ added $BinDir to your PATH" 'Green'
  } else {
    if (($env:Path -split ';') -notcontains $BinDir) { $env:Path = "$env:Path;$BinDir" }
    Log "$BinDir already on the user PATH"
  }

  Step 'done'
  Log "SUCCESS — p2p $newVer ($action), $RuntimeKind $(& $Node --version), shim $cmdShim"
  Remove-Item -Recurse -Force $script:Tmp -ErrorAction SilentlyContinue

  # ── 6. next step / auto-launch ────────────────────────────────────────────────
  Write-Host ""
  Say "+ p2p is ready." 'Green'
  if ($pathAdded) { Say "  PATH updated - open a NEW terminal for `p2p` to resolve." 'Yellow' }
  Write-Host ""

  # `irm … | iex` has no interactive host for a full-screen TUI — only auto-launch when
  # there is a real console.
  $haveTty = $false
  try { $haveTty = -not [Console]::IsOutputRedirected -and $Host.Name -ne 'Default Host' } catch { $haveTty = $false }

  if ($Key) {
    if ($haveTty) {
      Say "-> connecting to $Key ..." 'Cyan'
      Write-Host ""
      & $cmdShim $Key
      exit $LASTEXITCODE
    } else {
      Say "no console detected - run this yourself to chat with that key:" 'Yellow'
      Say "    $cmdShim $Key"
    }
  } else {
    Say "next:"
    Say "    p2p          launch the chat TUI (and print your key)"
    Say "    p2p key      just print your 26-char key - share it with a friend"
    Say "    p2p KEY      connect to a friend's key"
    Say "    p2p doctor   check that rendezvous is reachable"
    if ($pathAdded) {
      Write-Host ""
      Say "  (in THIS terminal, use the full path: $cmdShim)" 'DarkGray'
    }
  }
  Write-Host ""
}
catch {
  Fail ("$($_.Exception.Message)`n" + ($_.ScriptStackTrace | Out-String))
}
