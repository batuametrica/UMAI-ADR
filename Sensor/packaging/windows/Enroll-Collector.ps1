[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^https://')][string]$Endpoint,
    [Parameter(Mandatory = $true)][guid]$TenantId,
    [Parameter(Mandatory = $true)][Security.SecureString]$BootstrapToken,
    [string]$ProxyUrl,
    [string]$CaBundlePath
)
$ErrorActionPreference = 'Stop'
$dataRoot = Join-Path $env:ProgramData 'UMAI\ADR Collector'
$configDir = Join-Path $dataRoot 'config'
$stateDir = Join-Path $dataRoot 'state'
$collector = Join-Path $PSScriptRoot 'umai-adr-collector.exe'
New-Item -ItemType Directory -Force -Path $configDir, $stateDir, (Join-Path $dataRoot 'logs') | Out-Null

$config = [ordered]@{
    version = 1
    endpoint = $Endpoint.TrimEnd('/')
    tenant_id = $TenantId.ToString()
    proxy_url = $ProxyUrl
    ca_bundle_path = $CaBundlePath
}
$config | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $configDir 'collector.json') -Encoding UTF8

$token = [System.Net.NetworkCredential]::new('', $BootstrapToken).Password
try {
    $env:UMAI_INGEST_ENDPOINT = $config.endpoint
    $env:UMAI_TENANT_ID = $config.tenant_id
    $env:UMAI_BOOTSTRAP_TOKEN = $token
    $env:UMAI_ADR_STATE_DIR = $stateDir
    if ($ProxyUrl) { $env:UMAI_HTTPS_PROXY = $ProxyUrl }
    if ($CaBundlePath) { $env:UMAI_CA_BUNDLE = $CaBundlePath }
    & $collector --send --no-save --source everything
    if ($LASTEXITCODE -ne 0) { throw "Enrollment run failed with exit code $LASTEXITCODE" }
}
finally {
    Remove-Item Env:UMAI_BOOTSTRAP_TOKEN -ErrorAction SilentlyContinue
    $token = $null
}
Write-Host 'Collector enrolled. The device token is stored with Windows DPAPI.'
