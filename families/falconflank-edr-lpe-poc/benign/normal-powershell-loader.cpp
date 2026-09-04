// benign: a legitimate tool that loads bcrypt and lists scheduled tasks
LoadLibrary(L"bcrypt.dll");
system("schtasks /query /tn \\Microsoft\\Windows\\Application Experience\\MareBackup");
printf("PowerShell v1.0 present\n");
