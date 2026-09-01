[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'dist')
)
$ErrorActionPreference = 'Stop'
$sensorRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$stage = Join-Path $PSScriptRoot 'build\payload'
New-Item -ItemType Directory -Force -Path $stage, $OutputDirectory | Out-Null

python -m PyInstaller --clean --noconfirm --onefile --name umai-adr-collector `
    --distpath $stage --workpath (Join-Path $PSScriptRoot 'build\pyinstaller') `
    --specpath (Join-Path $PSScriptRoot 'build') --paths $sensorRoot `
    (Join-Path $PSScriptRoot 'collector_entry.py')
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed' }

$wix = Join-Path $env:USERPROFILE '.dotnet\tools\wix.exe'
if (-not (Test-Path -LiteralPath $wix)) { $wix = 'wix' }
& $wix build (Join-Path $PSScriptRoot 'Product.wxs') -arch x64 `
    -d "Version=$Version" -d "PayloadDir=$stage" -d "SourceDir=$PSScriptRoot" `
    -intermediatefolder (Join-Path $PSScriptRoot 'build\wix') `
    -out (Join-Path $OutputDirectory "umai-adr-collector-$Version-x64.msi")
if ($LASTEXITCODE -ne 0) { throw 'WiX MSI build failed' }
Write-Host "Built $(Join-Path $OutputDirectory "umai-adr-collector-$Version-x64.msi")"
