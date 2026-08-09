# Routine GPO maintenance
Backup-GPO -Name "Default Domain Policy" -Path \\server\backups
Register-ScheduledTask -TaskName "Nightly Maintenance" -User "SYSTEM"
Set-ItemProperty $gpt -Name MachineVersionNumber -Value 131074
