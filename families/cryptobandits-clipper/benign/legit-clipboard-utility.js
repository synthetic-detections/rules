// Legitimate clipboard utility — should NOT trigger any rule
// Contains some overlapping strings in isolation

var wsh = new ActiveXObject("WScript.Shell");

// Clipboard operations
function copyToClipboard(text) {
    var clip = wsh.Exec("clip.exe");
    clip.StdIn.Write(text);
    clip.StdIn.Close();
}

// Task scheduler for maintenance
var schtasks_cmd = "schtasks";

// URL shortcut creation
var sc = wsh.CreateShortcut("myapp.lnk");
sc.TargetPath = "C:\\Program Files\\MyApp\\myapp.exe";
sc.Save();
