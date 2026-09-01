[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$OutputPath)
$collector = Join-Path $PSScriptRoot 'umai-adr-collector.exe'
$env:UMAI_ADR_DATA_DIR = Join-Path $env:ProgramData 'UMAI\ADR Collector'
& $collector --support-bundle $OutputPath
exit $LASTEXITCODE
