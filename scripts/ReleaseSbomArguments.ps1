function Get-ReleaseSbomEnrichArguments {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PublishDir,

        [Parameter()]
        [string[]] $PackageRoot = @()
    )

    $arguments = @("enrich", "--output", $PublishDir)
    foreach ($root in $PackageRoot) {
        $arguments += @("--package-root", $root)
    }
    return ,$arguments
}
