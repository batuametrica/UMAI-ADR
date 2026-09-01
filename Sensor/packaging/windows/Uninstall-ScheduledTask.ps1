[CmdletBinding()]
param([switch]$DryRun)
$taskName = 'UMAI ADR Collector'
if ($DryRun) { Write-Output $taskName; exit 0 }
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
