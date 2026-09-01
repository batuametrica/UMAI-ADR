[CmdletBinding()]
param([switch]$DryRun)
$ErrorActionPreference = 'Stop'
$taskName = 'UMAI ADR Collector'
$runner = Join-Path $PSScriptRoot 'Run-Collector.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runner`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 15)
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
if ($DryRun) {
    [pscustomobject]@{ TaskName = $taskName; Principal = $principal.UserId; Runner = $runner; IntervalMinutes = 15 }
    exit 0
}
Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
