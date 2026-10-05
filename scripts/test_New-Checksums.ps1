param(
    [Parameter(Mandatory = $true)]
    [string] $SyntheticOutput
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "ReleaseSbomArguments.ps1")

function Assert-Arguments([string[]] $Actual, [string[]] $Expected, [string] $Case) {
    if ($Actual.Count -ne $Expected.Count) { throw "$Case argument count mismatch: $($Actual -join '|')" }
    for ($i = 0; $i -lt $Expected.Count; $i++) {
        if ($Actual[$i] -cne $Expected[$i]) { throw "$Case argument mismatch at $i" }
    }
}

$outputPath = Join-Path $env:TEMP "synthetic publish with spaces"
Assert-Arguments (Get-ReleaseSbomEnrichArguments -PublishDir $outputPath) @("enrich", "--output", $outputPath) "defaults"
Assert-Arguments (Get-ReleaseSbomEnrichArguments -PublishDir $outputPath -PackageRoot "C:\cache with spaces") `
    @("enrich", "--output", $outputPath, "--package-root", "C:\cache with spaces") "one root"
Assert-Arguments (Get-ReleaseSbomEnrichArguments -PublishDir $outputPath -PackageRoot @("C:\first cache", "D:\second cache")) `
    @("enrich", "--output", $outputPath, "--package-root", "C:\first cache", "--package-root", "D:\second cache") "multiple roots"

# The synthetic Python fixture has valid SPDX/evidence but its exact archive is
# removed by the caller. Enrichment must fail closed and report the missing identity.
$emptyRoot = Join-Path $env:TEMP "empty package root with spaces"
New-Item -ItemType Directory -Path $emptyRoot -Force | Out-Null
$enrichArgs = Get-ReleaseSbomEnrichArguments -PublishDir $SyntheticOutput -PackageRoot $emptyRoot
$result = & python (Join-Path $PSScriptRoot "release_sbom.py") @enrichArgs 2>&1
if ($LASTEXITCODE -eq 0 -or ($result -join "`n") -notmatch "Exact source archive unavailable") {
    throw "Missing exact archive was not refused as expected: $($result -join ' ')"
}
Write-Output "PowerShell SBOM argument regressions passed."
