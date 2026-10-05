<#
.SYNOPSIS
  Publishes querypact.exe for Windows x64 (MVP-A packaging profile 1).

.DESCRIPTION
  Authoritative publish for Chosen package pgsqlparser 1.0.0 / packaging profile 1
  (self-contained single-file + IncludeNativeLibrariesForSelfExtract).
  Does not enable Native AOT.
  Compatible with Windows PowerShell 5.1+ and PowerShell 7+.

.PARAMETER Output
  Publish output directory (default: artifacts/win-x64 under repo root).
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $Output = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
if ([string]::IsNullOrWhiteSpace($Output)) {
    $Output = Join-Path $repoRoot "artifacts\win-x64"
}

$hostCsproj = Join-Path $repoRoot "src\Sav.Host\Sav.Host.csproj"
if (-not (Test-Path -LiteralPath $hostCsproj)) {
    throw "Host project not found: $hostCsproj"
}

if (-not [System.IO.Path]::IsPathRooted($Output)) {
    $Output = Join-Path $repoRoot $Output
}
$Output = [System.IO.Path]::GetFullPath($Output)
$legalTool = Join-Path $PSScriptRoot "release_licenses.py"
& python $legalTool prepare --output $Output
if ($LASTEXITCODE -ne 0) { throw "Publish output must be empty; previous/partial output cannot be reused." }
# Keep local cache paths outside the distributable; unique for every invocation.
$evidenceDir = Join-Path (Split-Path -Parent $Output) (".release-evidence-" + [Guid]::NewGuid().ToString("N"))
$evidenceTargets = Join-Path $repoRoot "build\ReleaseEvidence.targets"

Write-Host "Publishing profile 1 (win-x64 self-contained single-file) -> $Output"

# Keep generated XML API documentation in build output. Exclude both the host's
# documentation and project references' documentation from the distributable.
dotnet publish $hostCsproj `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:PublishDocumentationFile=false `
    -p:PublishReferencesDocumentationFiles=false `
    -p:GenerateSBOM=false `
    "-p:CustomAfterMicrosoftCommonTargets=$evidenceTargets" `
    "-p:SavReleaseEvidenceDir=$evidenceDir" `
    -o $Output

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit $LASTEXITCODE"
}

$exe = Join-Path $Output "querypact.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "Expected published binary missing: $exe"
}

# Exact restored packages and current bundle inputs select runtime notices.
& python $legalTool stage --repo $repoRoot --output $Output --evidence $evidenceDir
if ($LASTEXITCODE -ne 0) { throw "Redistribution notice staging failed; publish is incomplete." }

$forbidden = Get-ChildItem -LiteralPath $Output -Recurse -File | Where-Object {
    $_.Extension -in @(".pdb", ".mdmp", ".dmp") -or
    $_.Name -match "(?i)(appsettings\.Development|\.env|credentials|secrets)"
}
if ($forbidden) {
    $names = ($forbidden | ForEach-Object { $_.FullName }) -join ", "
    throw "Forbidden files in publish output: $names"
}

Write-Host "OK: $exe"
& $exe --version
if ($LASTEXITCODE -ne 0) {
    throw "querypact.exe --version failed with exit $LASTEXITCODE"
}

& $exe --help | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "querypact.exe --help failed with exit $LASTEXITCODE"
}

Write-Host "Publish smoke (--version/--help) passed."
& python $legalTool complete --output $Output
if ($LASTEXITCODE -ne 0) { throw "Could not mark publish evidence complete." }
