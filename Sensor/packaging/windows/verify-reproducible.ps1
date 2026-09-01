[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$SourceDateEpoch
)
$ErrorActionPreference = 'Stop'

if (-not $SourceDateEpoch) {
    $sensorRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
    $SourceDateEpoch = (& git -C $sensorRoot log -1 --format=%ct).Trim()
}
if ($SourceDateEpoch -notmatch '^\d+$') { throw 'A numeric SourceDateEpoch is required' }

$verificationRoot = Join-Path ([IO.Path]::GetTempPath()) "umai-adr-msi-$([Guid]::NewGuid().ToString('N'))"
$firstOutput = Join-Path $verificationRoot 'first'
$secondOutput = Join-Path $verificationRoot 'second'
$buildScript = Join-Path $PSScriptRoot 'build.ps1'
$fileName = "umai-adr-collector-$Version-x64.msi"

& $buildScript -Version $Version -SourceDateEpoch $SourceDateEpoch -OutputDirectory $firstOutput
& $buildScript -Version $Version -SourceDateEpoch $SourceDateEpoch -OutputDirectory $secondOutput

$firstHash = (Get-FileHash -LiteralPath (Join-Path $firstOutput $fileName) -Algorithm SHA256).Hash
$secondHash = (Get-FileHash -LiteralPath (Join-Path $secondOutput $fileName) -Algorithm SHA256).Hash
if ($firstHash -ne $secondHash) {
    throw "MSI reproducibility check failed: $firstHash != $secondHash"
}

$dist = Join-Path $PSScriptRoot 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null
Copy-Item -LiteralPath (Join-Path $secondOutput $fileName) -Destination (Join-Path $dist $fileName) -Force
$evidence = [ordered]@{
    version = $Version
    source_date_epoch = [long]$SourceDateEpoch
    sha256 = $secondHash
} | ConvertTo-Json
# WriteAllText with an explicit BOM-less encoding: Windows PowerShell 5.1's
# `-Encoding utf8` emits a BOM that strict JSON parsers reject, and `utf8NoBOM`
# does not exist there.
[IO.File]::WriteAllText(
    (Join-Path $dist 'reproducibility.json'),
    "$evidence`n",
    (New-Object Text.UTF8Encoding $false))

Write-Host "Reproducible MSI verified: $secondHash"
