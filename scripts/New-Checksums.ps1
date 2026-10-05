<#
.SYNOPSIS
  Reconcile SPDX and write verified SHA-256 checksums for a fresh win-x64 publish.

.PARAMETER PublishDir
  Directory containing querypact.exe (default: artifacts/win-x64).

.PARAMETER GenerateSbom
  When set, runs Microsoft.Sbom.DotNetTool against the publish drop.
  Otherwise, requires an existing SPDX manifest valid for this exact candidate.

.PARAMETER PackageRoot
  Optional NuGet package cache root for exact archive verification. May be repeated.
  When omitted, release_sbom.py uses its existing default roots.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $PublishDir = "",

    [Parameter()]
    [switch] $GenerateSbom,

    [Parameter()]
    [string[]] $PackageRoot = @()
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "ReleaseSbomArguments.ps1")

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
if ([string]::IsNullOrWhiteSpace($PublishDir)) {
    $PublishDir = Join-Path $repoRoot "artifacts\win-x64"
}
else {
    if (-not [System.IO.Path]::IsPathRooted($PublishDir)) {
        $PublishDir = Join-Path $repoRoot $PublishDir
    }
    $PublishDir = [System.IO.Path]::GetFullPath($PublishDir)
}

$exe = Join-Path $PublishDir "querypact.exe"
if (-not (Test-Path -LiteralPath $exe)) {
    throw "querypact.exe not found in publish dir: $PublishDir"
}

$spdxPath = Join-Path $PublishDir "_manifest/spdx_2.2/manifest.spdx.json"
if (-not $GenerateSbom -and -not (Test-Path -LiteralPath $spdxPath -PathType Leaf)) {
    throw "Without -GenerateSbom, an existing valid SPDX manifest is required at $spdxPath. Run with -GenerateSbom on a fresh publish directory."
}

$legalTool = Join-Path $PSScriptRoot "release_licenses.py"
& python $legalTool validate --output $PublishDir
if ($LASTEXITCODE -ne 0) { throw "Incomplete publish or invalid required notices; checksums aborted." }
if (Test-Path -LiteralPath (Join-Path $PublishDir "SHA256SUMS.txt")) {
    throw "Old checksums refused; use a fresh publish directory."
}

if ($GenerateSbom) {
    $hostProj = Join-Path $repoRoot "src\Sav.Host"
    $manifestDir = Join-Path $PublishDir "_manifest"
    if (Test-Path -LiteralPath $manifestDir) {
        throw "Old SBOM output refused; use a fresh publish directory."
    }
    $toolManifest = Join-Path $repoRoot ".config\dotnet-tools.json"

    if (-not (Test-Path -LiteralPath $toolManifest)) {
        throw "Local .NET tool manifest not found: $toolManifest"
    }

    $version = & $exe --version
    if ($LASTEXITCODE -ne 0) {
        throw "querypact.exe --version failed"
    }
    $version = ($version | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "Published executable returned an empty version; SBOM version cannot be invented."
    }

    Write-Host "Restoring local SBOM tool manifest ..."
    Push-Location -LiteralPath $repoRoot
    try {
        dotnet tool restore --tool-manifest $toolManifest | Out-Null
    }
    finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restore the local Microsoft.Sbom.DotNetTool manifest"
    }

    Write-Host "Generating SPDX SBOM via local Microsoft.Sbom.DotNetTool ..."
    # Default manifest path is <buildDrop>/_manifest (do not pass -m nested under that).
    $toolArgs = @(
        "generate",
        "-b", $PublishDir,
        "-bc", $hostProj,
        "-pn", "QueryPact",
        "-pv", $version,
        "-ps", "QueryPact",
        "-nsb", "https://github.com/DOKOS-TAYOS/querypact"
    )

    Push-Location -LiteralPath $repoRoot
    try {
        & dotnet tool run sbom-tool @toolArgs
    }
    finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0) {
        throw "SBOM generation failed with exit $LASTEXITCODE"
    }

    $spdx = Get-ChildItem -LiteralPath $manifestDir -Recurse -Filter "*.spdx.json" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $spdx) {
        throw "SBOM generate completed but no *.spdx.json under $manifestDir"
    }

    Write-Host "SBOM: $($spdx.FullName)"
}

# Enrichment preserves the original generator output and verifies exact inputs.
if ($GenerateSbom) {
    if ($PackageRoot.Count -eq 0) {
        $enrichArgs = Get-ReleaseSbomEnrichArguments -PublishDir $PublishDir
    }
    else {
        $enrichArgs = Get-ReleaseSbomEnrichArguments -PublishDir $PublishDir -PackageRoot $PackageRoot
    }
    & python (Join-Path $PSScriptRoot "release_sbom.py") @enrichArgs
    if ($LASTEXITCODE -ne 0) { throw "Verified SPDX enrichment failed." }
}

# Reconciliation verifies enrichment provenance; public release remains blocked.
& python $legalTool reconcile --output $PublishDir
if ($LASTEXITCODE -ne 0) {
    if (-not $GenerateSbom) {
        throw "Without -GenerateSbom, an existing SPDX manifest valid for this exact candidate is required; license reconciliation failed."
    }
    throw "License reconciliation failed."
}
& python $legalTool checksums --output $PublishDir
if ($LASTEXITCODE -ne 0) { throw "Redistribution checksum validation failed." }
Write-Host "Checksums complete. Public release gate: BLOCKED (see license-reconciliation.json)."
