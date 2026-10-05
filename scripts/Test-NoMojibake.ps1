<#
.SYNOPSIS
  Reject double-encoded UTF-8 / Latin-1 mojibake in docs.

.DESCRIPTION
  Scans docs/**/*.md for classic mojibake markers of U+2192 (arrow), U+00F3 (o acute),
  and U+2014 (em dash) that appear when a UTF-8 file was mis-decoded as
  Latin-1/Windows-1252 and re-saved as UTF-8.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$docsRoot = Join-Path $repoRoot "docs"

# Build mojibake fingerprints from UTF-8 bytes of each literal, mis-decoded as
# Windows-1252. Avoid embedding those characters as string literals - PowerShell
# treats U+2018/U+2019/U+201C/U+201D as quote delimiters (ParserError on pwsh).
function Get-Cp1252Mojibake {
    param(
        [Parameter(Mandatory = $true)]
        [char] $Literal
    )

    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Literal)
    $cp1252 = [System.Text.Encoding]::GetEncoding(1252)
    return $cp1252.GetString($utf8Bytes)
}

$markers = @(
    [pscustomobject]@{ Codepoint = "U+2192"; Literal = [char]0x2192; Mojibake = (Get-Cp1252Mojibake -Literal ([char]0x2192)) },
    [pscustomobject]@{ Codepoint = "U+00F3"; Literal = [char]0x00F3; Mojibake = (Get-Cp1252Mojibake -Literal ([char]0x00F3)) },
    [pscustomobject]@{ Codepoint = "U+2014"; Literal = [char]0x2014; Mojibake = (Get-Cp1252Mojibake -Literal ([char]0x2014)) }
)

$files = @(Get-ChildItem -LiteralPath $docsRoot -Recurse -Filter "*.md" -File)

$failures = New-Object System.Collections.Generic.List[string]

foreach ($file in ($files | Sort-Object -Property FullName -Unique)) {
    $text = [System.IO.File]::ReadAllText($file.FullName)
    foreach ($m in $markers) {
        if ($text.Contains($m.Mojibake)) {
            $rel = $file.FullName.Substring($repoRoot.Path.Length).TrimStart("\", "/")
            $failures.Add("$rel contains mojibake for $($m.Codepoint): '$($m.Mojibake)' (literal $($m.Literal) is OK)")
        }
    }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    throw "Mojibake check failed ($($failures.Count) hit(s))."
}

Write-Host "OK: no mojibake markers in $($files.Count) markdown file(s)."
