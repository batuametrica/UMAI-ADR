[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist'),
    [string]$SourceDateEpoch
)
$ErrorActionPreference = 'Stop'

function Get-DeterministicGuid([string]$Seed) {
    $seedBytes = [Text.Encoding]::UTF8.GetBytes($Seed)
    # ComputeHash rather than the .NET 5+ static HashData, so the installer still
    # builds under Windows PowerShell 5.1 as well as pwsh.
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try { $digest = $sha256.ComputeHash($seedBytes) } finally { $sha256.Dispose() }
    $guidBytes = $digest[0..15]
    $guidBytes[7] = ($guidBytes[7] -band 0x0f) -bor 0x50
    $guidBytes[8] = ($guidBytes[8] -band 0x3f) -bor 0x80
    return ([Guid]::new([byte[]]$guidBytes)).ToString('B').ToUpperInvariant()
}

function Set-MsiCompoundTimestamp([string]$Path, [long]$Epoch) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $signature = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
    $validSignature = $bytes.Length -ge 512
    for ($index = 0; $validSignature -and $index -lt $signature.Length; $index++) {
        $validSignature = $bytes[$index] -eq $signature[$index]
    }
    if (-not $validSignature) {
        throw "Not a Compound File Binary MSI: $Path"
    }
    $sectorShift = [BitConverter]::ToUInt16($bytes, 30)
    if ($sectorShift -notin 9, 12) { throw "Unsupported MSI sector shift: $sectorShift" }
    $firstDirectorySector = [BitConverter]::ToUInt32($bytes, 48)
    $rootOffset = ([long]$firstDirectorySector + 1) * (1L -shl $sectorShift)
    if ($rootOffset + 116 -gt $bytes.Length) { throw 'Invalid MSI root directory offset' }
    $fileTime = ($Epoch + 11644473600L) * 10000000L
    [BitConverter]::GetBytes($fileTime).CopyTo($bytes, $rootOffset + 108)
    [IO.File]::WriteAllBytes($Path, $bytes)
}

$sensorRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$stage = Join-Path $PSScriptRoot 'build\payload'
$toolchain = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'toolchain.lock.json') -Raw | ConvertFrom-Json

$pythonVersion = (& python -c "import platform; print(platform.python_version())").Trim()
if ($LASTEXITCODE -ne 0 -or $pythonVersion -ne $toolchain.python) {
    throw "Python $($toolchain.python) is required; found $pythonVersion"
}
$pyInstallerVersion = (& python -m PyInstaller --version).Trim()
if ($LASTEXITCODE -ne 0 -or $pyInstallerVersion -ne $toolchain.pyinstaller) {
    throw "PyInstaller $($toolchain.pyinstaller) is required; found $pyInstallerVersion"
}

$wix = Join-Path $env:USERPROFILE '.dotnet\tools\wix.exe'
if (-not (Test-Path -LiteralPath $wix)) { $wix = 'wix' }
$wixVersion = (& $wix --version).Trim()
if ($LASTEXITCODE -ne 0 -or -not $wixVersion.StartsWith("$($toolchain.wix)+")) {
    throw "WiX $($toolchain.wix) is required; found $wixVersion"
}

if (-not $SourceDateEpoch) {
    $SourceDateEpoch = (& git -C $sensorRoot log -1 --format=%ct).Trim()
    if ($LASTEXITCODE -ne 0 -or $SourceDateEpoch -notmatch '^\d+$') {
        throw 'SourceDateEpoch is required outside a git checkout'
    }
}
$env:SOURCE_DATE_EPOCH = $SourceDateEpoch
$env:PYTHONHASHSEED = '0'

New-Item -ItemType Directory -Force -Path $stage, $OutputDirectory | Out-Null

python -m PyInstaller --clean --noconfirm --noupx --onefile --name umai-adr-collector `
    --distpath $stage --workpath (Join-Path $PSScriptRoot 'build\pyinstaller') `
    --specpath (Join-Path $PSScriptRoot 'build') --paths $sensorRoot `
    (Join-Path $PSScriptRoot 'collector_entry.py')
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed' }

$productCode = Get-DeterministicGuid "umai-adr-product|$Version"
$payloadPath = Join-Path $stage 'umai-adr-collector.exe'
$buildDate = [DateTimeOffset]::FromUnixTimeSeconds([long]$SourceDateEpoch).UtcDateTime
(Get-Item -LiteralPath $payloadPath).LastWriteTimeUtc = $buildDate
$payloadHash = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash
$packageCode = Get-DeterministicGuid "umai-adr-package|$Version|$payloadHash"
$msiPath = Join-Path $OutputDirectory "umai-adr-collector-$Version-x64.msi"
& $wix build (Join-Path $PSScriptRoot 'Product.wxs') -arch x64 `
    -d "Version=$Version" -d "ProductCode=$productCode" -d "PayloadDir=$stage" -d "SourceDir=$PSScriptRoot" `
    -intermediatefolder (Join-Path $PSScriptRoot 'build\wix') `
    -out $msiPath
if ($LASTEXITCODE -ne 0) { throw 'WiX MSI build failed' }

# WiX 5 does not expose its random PackageCode or SummaryInformation timestamps.
# Normalize the three fields after linking so identical inputs produce identical bytes.
$installer = New-Object -ComObject WindowsInstaller.Installer
$summary = $installer.SummaryInformation((Resolve-Path $msiPath).Path, 3)
$summary.Property(9) = $packageCode
$summary.Property(12) = $buildDate
$summary.Property(13) = $buildDate
$summary.Persist()
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary) | Out-Null
[Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
# Windows Installer writes the CFB root-storage modified time during Persist().
# Normalize that final metadata field to make the unsigned MSI byte-reproducible.
Set-MsiCompoundTimestamp -Path (Resolve-Path $msiPath).Path -Epoch ([long]$SourceDateEpoch)

Write-Host "Built $msiPath"
