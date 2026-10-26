# Legitimate file-integrity checker that uses Add-Type C# embedding
# Should NOT trigger LazyWiper rules: uses FileAccess.Read (not Write),
# no Random/Seek overwrite pattern, no Defender disable

$CSharpCode = @"
using System;
using System.IO;
using System.Security.Cryptography;
public class FileHasher
{
    public string ComputeHash(string filePath)
    {
        using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(fileStream);
            return BitConverter.ToString(hash).Replace("-", "");
        }
    }
}
"@

Add-Type -TypeDefinition $CSharpCode;
$hasher = New-Object FileHasher;
$exts = @(".doc",".docx",".pdf",".xlsx",".pptx",".bak")
Get-ChildItem -Path "D:\Backups" -Recurse -File |
    Where-Object { $exts -contains $_.Extension } |
    ForEach-Object {
        $hash = $hasher.ComputeHash($_.FullName)
        Write-Output "$hash  $($_.FullName)"
    }
