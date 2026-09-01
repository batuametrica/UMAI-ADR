$ErrorActionPreference = 'Stop'
$dataRoot = Join-Path $env:ProgramData 'UMAI\ADR Collector'
$configPath = Join-Path $dataRoot 'config\collector.json'
$logPath = Join-Path $dataRoot 'logs\collector.log'
$collector = Join-Path $PSScriptRoot 'umai-adr-collector.exe'

New-Item -ItemType Directory -Force -Path (Split-Path $logPath) | Out-Null
if (-not (Test-Path -LiteralPath $configPath)) {
    "$(Get-Date -Format o) configuration missing: $configPath" | Add-Content -LiteralPath $logPath
    exit 2
}

$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$env:UMAI_INGEST_ENDPOINT = [string]$config.endpoint
$env:UMAI_TENANT_ID = [string]$config.tenant_id
if ($config.proxy_url) { $env:UMAI_HTTPS_PROXY = [string]$config.proxy_url }
if ($config.ca_bundle_path) { $env:UMAI_CA_BUNDLE = [string]$config.ca_bundle_path }
$env:UMAI_ADR_STATE_DIR = Join-Path $dataRoot 'state'
$env:UMAI_ADR_DATA_DIR = $dataRoot

"$(Get-Date -Format o) collector run started" | Add-Content -LiteralPath $logPath
& $collector --send --no-save --source everything *>> $logPath
$exitCode = $LASTEXITCODE
"$(Get-Date -Format o) collector run finished exit_code=$exitCode" | Add-Content -LiteralPath $logPath
exit $exitCode
