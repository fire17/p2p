# Encoding gate for every PowerShell script in this repository.
# Windows PowerShell 5.1 reads a BOM-less `-File` script in the ANSI code page
# (cp1252, cp1255, ...), so UTF-8 punctuation such as U+2014 (bytes E2 80 94)
# decodes to a smart quote that ends a string and breaks the parse. The join
# line runs the hash-pinned init.ps1 exactly that way.
# Rules: every tracked *.ps1 / *.ps1.in is pure ASCII (no BOM needed), and it
# parses with zero errors as UTF-8, cp1252 and cp1255. Under Windows PowerShell
# 5.1 it is also loaded through the real `-File` loader (Get-Command .ScriptBlock).
# Safe anywhere: read-only, runs with pwsh on macOS/Linux and both Windows shells.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$repoPath = Split-Path -Parent $PSScriptRoot
try { [Text.Encoding]::RegisterProvider([Text.CodePagesEncodingProvider]::Instance) } catch {}
$decoders = @(
    @{ Name = 'utf-8'; Encoding = (New-Object Text.UTF8Encoding($false)) },
    @{ Name = 'cp1252'; Encoding = [Text.Encoding]::GetEncoding(1252) },
    @{ Name = 'cp1255'; Encoding = [Text.Encoding]::GetEncoding(1255) }
)
function Get-ParseErrors([string]$text) {
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
    return $errors
}

# Canary: the check must reject what broke Windows PowerShell 5.1.
$canary = [Text.Encoding]::UTF8.GetBytes("Write-Host `"a " + [char]0x2014 + " b`"`n")
if (@(Get-ParseErrors ([Text.Encoding]::GetEncoding(1252).GetString($canary))).Count -eq 0) {
    throw 'Canary failed: a UTF-8 em dash inside a double-quoted string must not parse as cp1252'
}

# Filter by name: Windows PowerShell 5.1 ignores -Include together with -LiteralPath.
$files = @(Get-ChildItem -LiteralPath $repoPath -Recurse -File |
    Where-Object { $_.Name -match '\.ps1(\.in)?$' -and $_.FullName -notmatch '[\\/](\.git|node_modules)[\\/]' } | Sort-Object FullName)
if ($files.Count -lt 3) { throw "Expected the repository PowerShell scripts, found $($files.Count)" }
$failures = New-Object Collections.Generic.List[string]
$desktop = $PSVersionTable.PSEdition -eq 'Desktop'
foreach ($file in $files) {
    $rel = $file.FullName.Substring($repoPath.Length).TrimStart('\', '/')
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    $offender = -1
    for ($i = 0; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -gt 127) { $offender = $i; break } }
    if ($offender -ge 0) {
        $line = 1; for ($i = 0; $i -lt $offender; $i++) { if ($bytes[$i] -eq 10) { $line++ } }
        $failures.Add("$rel`: non-ASCII byte 0x$('{0:X2}' -f $bytes[$offender]) on line $line (Windows PowerShell 5.1 -File reads BOM-less scripts as ANSI)")
    }
    foreach ($decoder in $decoders) {
        $errors = @(Get-ParseErrors $decoder.Encoding.GetString($bytes))
        if ($errors.Count) { $failures.Add("$rel`: $($errors.Count) parse error(s) as $($decoder.Name); first: line $($errors[0].Extent.StartLineNumber): $($errors[0].Message)") }
    }
    if ($desktop -and $file.Extension -eq '.ps1') {
        try { [void](Get-Command -Name $file.FullName -ErrorAction Stop).ScriptBlock }
        catch { $failures.Add("$rel`: Windows PowerShell $($PSVersionTable.PSVersion) -File loader: $($_.Exception.Message)") }
    }
}
if ($failures.Count) {
    $failures | ForEach-Object { Write-Output "FAIL: $_" }
    throw "$($failures.Count) PowerShell encoding failure(s)"
}
$loader = if ($desktop) { ' + Windows PowerShell -File loader' } else { '' }
Write-Output "PASS: $($files.Count) PowerShell scripts are ASCII and parse as utf-8, cp1252, cp1255$loader (PowerShell $($PSVersionTable.PSVersion))"
