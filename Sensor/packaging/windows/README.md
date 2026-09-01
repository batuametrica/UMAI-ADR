# UMAI ADR Collector for Windows

The GA v1 collector is a 64-bit, per-machine MSI. It installs the collector under
`%ProgramFiles%\UMAI ADR Collector`, creates a 15-minute Task Scheduler job running as
`NT AUTHORITY\SYSTEM`, and keeps mutable data under `%ProgramData%\UMAI\ADR Collector`.

## Build

Install the development extras plus PyInstaller, then run:

```powershell
python -m pip install -e ".[dev]" pyinstaller
.\packaging\windows\build.ps1 -Version 1.0.0
```

## Silent install and enrollment

```powershell
msiexec /i .\umai-adr-collector-1.0.0-x64.msi /qn /norestart /l*v install.log
$token = Read-Host 'One-time bootstrap token' -AsSecureString
& "$env:ProgramFiles\UMAI ADR Collector\Enroll-Collector.ps1" `
  -Endpoint https://umai.example.com -TenantId 11111111-1111-1111-1111-111111111111 `
  -BootstrapToken $token
```

`Enroll-Collector.ps1` keeps the one-time bootstrap token only in process memory. The
returned device token is written as a Windows DPAPI LocalMachine blob; it never appears
in `device.json`, installer logs, or support bundles. Add `-ProxyUrl` and
`-CaBundlePath` for an enterprise proxy or a PEM private-CA bundle.

## Upgrade, rollback, and uninstall

An in-place MSI major upgrade replaces binaries and scripts while preserving the
`state` directory and DPAPI credential. Test rollback by reinstalling the previously
approved MSI; WiX blocks a downgrade by default, so first uninstall the newer MSI while
retaining ProgramData, then install the prior MSI and trigger the task.

```powershell
msiexec /x {PRODUCT-CODE-FROM-INVENTORY} /qn /norestart /l*v uninstall.log
msiexec /i .\umai-adr-collector-PREVIOUS-x64.msi /qn /norestart /l*v rollback.log
Start-ScheduledTask -TaskName 'UMAI ADR Collector'
```

Uninstall removes the scheduled task and program files but deliberately retains device
state for repair/rollback. A full decommission must first revoke the device in UMAI,
then delete the exact `%ProgramData%\UMAI\ADR Collector` directory.

## Logs and support bundle

Runtime logs are `%ProgramData%\UMAI\ADR Collector\logs\collector.log`; MSI logs are at
the path supplied to `/l*v`. Create a bundle with:

```powershell
& "$env:ProgramFiles\UMAI ADR Collector\New-SupportBundle.ps1" -OutputPath C:\Temp\umai-adr.zip
```

The archive includes version/OS/device metadata, redacted configuration, and the last
2 MB of each log. Transcript state and `*.dpapi` credential blobs are never included.
