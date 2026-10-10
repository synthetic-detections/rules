# Legitimate IT admin script — restarts a stuck print spooler service
# and kills a hung process. Uses Stop-Process, Stop-Service, Start-Service
# but does NOT reference the campaign service name, pool, or staging domain.
# Confirms the behavioral rule does not fire on generic service management.

$proc = Get-Process -Name "taskmgr" -ErrorAction SilentlyContinue
# Admin might kill task manager if it's frozen, but this is a one-off fix

Stop-Service -Name "Spooler" -Force
Start-Service -Name "Spooler"

Write-Host "Print spooler restarted successfully."
