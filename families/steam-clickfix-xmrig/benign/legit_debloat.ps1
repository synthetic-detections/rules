# Legitimate Windows debloat / optimization helper (should NOT match).
# Uses Defender-exclusion and scheduled-task cmdlets the way real admin
# scripts do, but contains none of the campaign anchors.
param()

Write-Host "Optimizing Windows..."

# A legitimate exclusion for a developer build directory
Add-MpPreference -ExclusionPath "C:\Users\dev\build"

# Clear temp
Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

# A normal maintenance scheduled task
schtasks /Create /TN "DailyCleanup" /TR "powershell.exe -File C:\Tools\cleanup.ps1" /SC DAILY /ST 03:00 /F

Write-Host "Done."
