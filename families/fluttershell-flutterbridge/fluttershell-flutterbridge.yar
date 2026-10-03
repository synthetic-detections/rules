/*
   FlutterShell — Operation FlutterBridge macOS backdoor (disclosed 2026-06-06)
   ----------------------------------------------------------------------------
   Palo Alto Networks Unit 42 disclosed a malvertising campaign delivering a
   new macOS backdoor codenamed FlutterShell via hundreds of Google-verified
   Google Ads. The operator paid the Google Ads vetting tax through shell
   companies, so the ads themselves look entirely legitimate; the delivered
   apps carry valid Apple Developer IDs and pass notarisation at submission.

   Three variants shipped as Flutter framework apps:
     - PodcastsLounge   (bundle: com.app.podcastsLounge, dev: Yasar Sever)
     - PDF-Brain        (bundle: com.app.pdfBrain,        dev: Batuhan Dabag)
     - PDF-Ninja        (bundle: com.pdfninja.app,        dev: Yusuf Bal)

   The backdoor uses a WebView with a JavaScript-to-native bridge named
   `flutterInvoke`. Malicious logic lives on attacker-hosted JS at the C2,
   not in the binary — so the operator can rotate payload behaviour in
   real time without recompiling. Commands: exec_sync, pdf_sync,
   renderPDF, read_file, write_file, read_dir, exists, get_home_dir,
   get_env. PDF-Ninja additionally uses Flutter --obfuscate and renames
   commands (read_pdf instead of read_file) to slip static analyzers.

   AI-summarisation exfil — some variants proxy host documents through
   /summarize-text on the attacker's C2 before forwarding to the
   legitimate AI summariser, giving an exfil channel that looks like
   legitimate AI usage.

   Three rules:
     1. MachOBundle      — Mach-O specimen + verbatim bundle IDs and
                           Apple Developer IDs published by Unit 42.
     2. WebViewJSBridge  — the flutterInvoke message channel + command
                           name set + C2 path-shape, file-agnostic
                           (catches the Flutter Dart AOT blob too).
     3. IOC              — campaign markers, 9 SHA256 hashes, 4 C2
                           hostnames, observed reconnaissance commands.

   Source:
     https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/
     https://thehackernews.com/2026/06/fluttershell-backdoor-spreads-to-macos.html
*/

rule FlutterShell_MachOBundle {
    meta:
        description = "FlutterShell macOS Mach-O — verbatim bundle IDs + Apple Developer IDs from the three FlutterBridge variants"
        author = "synthetic-detections"
        date = "2026-06-07"
        severity = "critical"
        family = "fluttershell-flutterbridge"
        reference = "https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/"
    strings:
        $mh_fat_be = { CA FE BA BE }
        $mh_fat_le = { BE BA FE CA }
        $mh_64_be = { FE ED FA CF }
        $mh_64_le = { CF FA ED FE }
        $b_podcasts = "com.app.podcastsLounge"
        $b_pdfbrain = "com.app.pdfBrain"
        $b_pdfninja = "com.pdfninja.app"
        $dev_sever = "Yasar Sever (UBZDAAV97Y)"
        $dev_dabag = "Batuhan Dabag (FW9NHQ8922)"
        $dev_bal = "Yusuf Bal (B73CHZ24Y8)"
        $tid_sever = "UBZDAAV97Y" fullword
        $tid_dabag = "FW9NHQ8922" fullword
        $tid_bal = "B73CHZ24Y8" fullword
    condition:
        ($mh_fat_be at 0 or $mh_fat_le at 0 or $mh_64_be at 0 or $mh_64_le at 0) and (any of ($b_podcasts, $b_pdfbrain, $b_pdfninja) or any of ($dev_sever, $dev_dabag, $dev_bal) or any of ($tid_sever, $tid_dabag, $tid_bal)) and filesize < 200MB
}

rule FlutterShell_WebViewJSBridge {
    meta:
        description = "FlutterShell WebView JS-to-native bridge — flutterInvoke channel + command name set + C2 path-shape"
        author = "synthetic-detections"
        date = "2026-06-07"
        severity = "critical"
        family = "fluttershell-flutterbridge"
        reference = "https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/"
    strings:
        $bridge = "flutterInvoke"
        $cmd_exec = "exec_sync"
        $cmd_pdf = "pdf_sync"
        $cmd_render = "renderPDF"
        $cmd_read_f = "read_file"
        $cmd_write_f = "write_file"
        $cmd_read_d = "read_dir"
        $cmd_exists = "exists" fullword
        $cmd_home = "get_home_dir"
        $cmd_env = "get_env" fullword
        $cmd_read_p = "read_pdf"
        $p_update_thanks = "/update-thanks.html"
        $p_update_delay = "/api/update-delay"
        $p_getconfig = "/getConfig"
        $p_getupdate = "/getUpdateThanksConfig"
        $p_summarize = "/summarize-text"
        $recon_ioreg = "ioreg -rd1 -c IOPlatformExpertDevice"
        $chrome_pref = "default_search_provider_data"
    condition:
        ($bridge and 3 of ($cmd_*) or any of ($p_update_thanks, $p_update_delay, $p_getupdate, $p_summarize) or $p_getconfig and $bridge or $recon_ioreg and $chrome_pref) and filesize < 200MB
}

rule FlutterShell_IOC {
    meta:
        description = "FlutterShell static IOC sweep — campaign markers, 9 SHA-256, 4 C2 hostnames, the three signing Team IDs"
        author = "synthetic-detections"
        date = "2026-06-07"
        severity = "high"
        family = "fluttershell-flutterbridge"
        reference = "https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/"
    strings:
        $m_op_name = "FlutterBridge" nocase
        $m_mal_name = "FlutterShell" nocase
        $c2_podcasts = "atsheisdomestic.org" nocase
        $c2_pdfbrain = "etoftheappyrince.org" nocase
        $c2_pdfninja = "healightejustb.org" nocase
        $c2_track = "sinterfumesco.com" nocase
        $h1 = "021666417de8b9972c179783fe60d4c4ad2d93224e3a0f16137065c960b1b845" nocase
        $h2 = "363923500ce942bf1a953e8a4e943fbf1fb1b5ed6e5d247964c345b3ad5bfc34" nocase
        $h3 = "8421c902364980e3d762ec6dbbe6b0f40577c27bd79b48c57d098328b2533109" nocase
        $h4 = "644fc49fa1006a2a2acace694e5fb83753164e2617051ece6d9dc9ea32329e70" nocase
        $h5 = "9053e8ddaecca1f960c041c944ca8799fc71dc86a4b50d2639ee4e0d2cb82f47" nocase
        $h6 = "b60074d1ea2008a581f432f2dee5f84f78668d9dd8e66f75d03c42dabd89bdea" nocase
        $h7 = "9425e8e39fa8a7212cdd07f0917cb3dfde38a90b87297de2c82a5850aff1e4de" nocase
        $h8 = "30448686ec900d5213d74f08f0d2b7924c5336a29445b2a434aba8d8b19d7530" nocase
        $h9 = "48047c34bfd57fe1e24bc538bc2ce9e0ac4c4eb48d3b0c195b414f0379dc0745" nocase
    condition:
        any of them and filesize < 50MB
}
