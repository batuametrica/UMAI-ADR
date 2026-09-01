<#
.SYNOPSIS
    Sign the collector MSI with Authenticode, and record what happened either way.

.DESCRIPTION
    Signing rewrites the file, so this script records *two* digests:

      unsigned_sha256    the byte-reproducible digest the double-build gate proved
      signed_sha256      the digest of the file a customer actually downloads

    Conflating them is the failure mode. Verifying a download against the unsigned
    digest fails for a perfectly good signed installer; verifying reproducibility
    against the signed digest fails every time.

    When no certificate is available the script does not fail. It records an unsigned
    result and lets scripts/enforce_signing_policy.py decide whether that may ship —
    that decision belongs in a committed policy, not in a build script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$MsiPath,
    [string]$Component = 'adr-collector',
    [string]$OutputPath,
    # A PFX, base64-encoded so it can live in a repository secret.
    [string]$CertificateBase64 = $env:UMAI_SIGNING_CERTIFICATE_BASE64,
    [string]$CertificatePassword = $env:UMAI_SIGNING_CERTIFICATE_PASSWORD,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)
$ErrorActionPreference = 'Stop'

function Get-Sha256([string]$Path) {
    return 'sha256:' + (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$msi = (Resolve-Path -LiteralPath $MsiPath).Path
if (-not $OutputPath) {
    $OutputPath = Join-Path (Split-Path -Parent $msi) 'signature.json'
}

$unsignedDigest = Get-Sha256 $msi
$result = [ordered]@{
    schema_version  = 1
    component       = $Component
    artifact        = [IO.Path]::GetFileName($msi)
    signed          = $false
    mechanism       = 'none'
    unsigned_sha256 = $unsignedDigest
    signed_sha256   = $null
    signer          = $null
    thumbprint      = $null
    timestamped     = $false
}

if (-not $CertificateBase64) {
    Write-Host "No signing certificate supplied; recording an unsigned result for $($result.artifact)."
} else {
    $signtool = Get-ChildItem -Path 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse `
        -Filter 'signtool.exe' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw 'signtool.exe was not found; install the Windows SDK.' }

    # The PFX lands in a temporary file and is removed in the finally block. Writing it
    # under the build output would risk it being picked up as a release artifact.
    $pfx = Join-Path ([IO.Path]::GetTempPath()) ("umai-signing-$([Guid]::NewGuid().ToString('N')).pfx")
    try {
        [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($CertificateBase64))

        $arguments = @('sign', '/fd', 'SHA256', '/f', $pfx, '/tr', $TimestampUrl, '/td', 'SHA256')
        if ($CertificatePassword) { $arguments += @('/p', $CertificatePassword) }
        $arguments += $msi

        & $signtool.FullName @arguments
        if ($LASTEXITCODE -ne 0) { throw "signtool sign failed with exit code $LASTEXITCODE" }

        # Verify with the same tool a customer's OS uses. /pa selects the Authenticode
        # policy rather than the driver policy, which would pass for the wrong reasons.
        & $signtool.FullName 'verify' '/pa' '/all' $msi
        if ($LASTEXITCODE -ne 0) { throw "signtool verify failed with exit code $LASTEXITCODE" }

        $signature = Get-AuthenticodeSignature -LiteralPath $msi
        if ($signature.Status -ne 'Valid') {
            throw "Authenticode status is $($signature.Status), expected Valid"
        }

        $result.signed = $true
        $result.mechanism = 'authenticode'
        $result.signed_sha256 = Get-Sha256 $msi
        $result.signer = $signature.SignerCertificate.Subject
        $result.thumbprint = $signature.SignerCertificate.Thumbprint
        $result.timestamped = $null -ne $signature.TimeStamperCertificate

        Write-Host "Signed $($result.artifact) as $($result.signer)"
    } finally {
        if (Test-Path -LiteralPath $pfx) {
            Remove-Item -LiteralPath $pfx -Force
        }
    }
}

[IO.File]::WriteAllText(
    $OutputPath,
    ((($result | ConvertTo-Json -Depth 4)) + "`n"),
    (New-Object Text.UTF8Encoding $false))
Write-Host "Signature evidence written to $OutputPath"
