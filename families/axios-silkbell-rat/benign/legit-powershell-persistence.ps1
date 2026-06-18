# Legitimate Windows startup script — should NOT trigger
# Uses Run key but with standard app name, no RAT indicators

$AppName = "MyBackupApp"
$AppPath = "C:\Program Files\MyBackup\backup.exe"

# Register startup
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $AppName -Value $AppPath -PropertyType String -Force

# Run backup
& $AppPath --schedule daily --time 02:00
