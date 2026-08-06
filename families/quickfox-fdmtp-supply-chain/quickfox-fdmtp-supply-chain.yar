/*
   QuickFox VPN supply-chain compromise -> FDMTP implant
   (disclosed 2026-08-04; Fortinet FortiGuard Labs -- tactical overlap with
    Mustang Panda / "Twill Typhoon", not confidently attributed)
   -----------------------------------------------------------------------
   A long-running supply-chain attack on QuickFox, a VPN / network-accelerator
   aimed at overseas Chinese users. Trojanized Windows builds (first affected
   v3.51.0, seen 2025-08-13; components removed in v3.59.6) shipped malicious
   JavaScript injected into the Electron renderer HTML.

   Kill chain (Fortinet):
     - Injected JS loads two attacker files from the update CDN disguised as
       Firebase SDKs (firebase-app-compat.js / firebase-analytics-compat.js).
     - An obfuscated JS loader (wrapper r1muVuL, ten parallel base91 layers)
       fingerprints the host: it ABORTS if steam.exe is present, and only
       continues if at least one target process is running -- SSH/RDP clients
       (xshell/finalshell/MobaXterm/Tabby), DB tools (navicat/dbeaver),
       dev tools (git/idea64/Code/notepad++/sublime_text), crypto wallets
       (Exodus/Binance/Ledger/Trezor), messengers (telegram), and a set of
       Chinese translation apps (Hello-GPT.exe and several localized ones).
     - It downloads update.zip, drops a malicious Microsoft.ServiceHosting.
       Tools.dll into %APPDATA%\Local\Temp\quickfox\updated\ and side-loads it
       via the legitimate Azure emulator binary csmonitor.exe (DLL sideload).
     - The DLL AES-128-ECB-decrypts update.bin (key "POt_L[Bsh0=+@0a.") to
       load the FDMTP implant, which stores compressed plugins under
       HKCU\SOFTWARE\Microsoft\IME\{HWID} and beacons to the GetCluster,
       GetEndpoints, GetNodes endpoints (protocol tag Dotnet-TcpDmtp)
       on ports 20800-20816.

   NOTE: Microsoft.ServiceHosting.Tools.dll and csmonitor.exe are LEGITIMATE
   filenames (Azure SDK); the AES key, the base91 loader wrapper, the DMTP
   protocol tag, and the quickfox\updated staging path are the campaign-
   specific anchors. Rules deliberately require co-occurrence so a normal
   Azure emulator install or a benign Electron app does not match.

   Rule 1 -- Behavioral: FDMTP loader/sideload chain + AES key + DMTP beacon.
   Rule 2 -- LoaderShape: the fingerprinting JavaScript stage (guardrails).
   Rule 3 -- IOC: C2 domains/IPs and file hashes (Fortinet appendix).

   Sources:
     https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant
     https://thehackernews.com/2026/08/quickfox-supply-chain-attack-delivers.html
*/

rule QuickFox_FDMTP_LoaderChain
{
    meta:
        description = "QuickFox->FDMTP sideload chain — malicious Microsoft.ServiceHosting.Tools.dll under quickfox\\updated side-loaded via csmonitor, AES-128-ECB key POt_L[Bsh0=+@0a., DMTP GetCluster/GetEndpoints beacon on 20800-range"
        author      = "synthetic-detections"
        date        = "2026-08-06"
        severity    = "critical"
        family      = "quickfox-fdmtp-supply-chain"
        reference   = "https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant"

    strings:
        // Campaign-unique AES-128-ECB key for update.bin
        $aes_key   = "POt_L[Bsh0=+@0a." ascii wide

        // Staging path + sideload artifacts (legit filenames, campaign path)
        $path      = "quickfox\\updated" ascii wide nocase
        $sideload  = "Microsoft.ServiceHosting.Tools.dll" ascii wide
        $csmon     = "csmonitor.exe" ascii wide nocase
        $payload   = "update.bin" ascii wide nocase

        // FDMTP / TouchSocket DMTP C2 protocol artifacts
        $dmtp      = "Dotnet-TcpDmtp" ascii wide
        $ep1       = "GetCluster" ascii wide
        $ep2       = "GetEndpoints" ascii wide
        $ep3       = "GetNodes" ascii wide

        // FDMTP plugin persistence hive
        $reg       = "SOFTWARE\\Microsoft\\IME\\" ascii wide

    condition:
        filesize < 50MB
        and (
            $aes_key
            or ( $path and ($sideload or $csmon or $payload) )
            or ( $dmtp and 1 of ($ep1, $ep2, $ep3) )
            or ( 2 of ($ep1, $ep2, $ep3) and ($reg or $sideload) )
        )
}

rule QuickFox_FDMTP_LoaderShape
{
    meta:
        description = "QuickFox injected-JS fingerprinting loader — r1muVuL base91 wrapper, steam.exe abort guardrail, target-process allowlist (finalshell/MobaXterm/navicat/dbeaver/Exodus/Binance/Ledger), fake Firebase SDK filenames"
        author      = "synthetic-detections"
        date        = "2026-08-06"
        severity    = "high"
        family      = "quickfox-fdmtp-supply-chain"
        reference   = "https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant"

    strings:
        // Obfuscation wrapper unique to the loader
        $wrap      = "r1muVuL" ascii wide

        // Fake Firebase SDK stage filenames (attacker-hosted)
        $fb1       = "firebase-app-compat.js" ascii nocase
        $fb2       = "firebase-analytics-compat.js" ascii nocase

        // Guardrail: blocking process
        $block     = "steam.exe" ascii wide nocase

        // Target-process allowlist tokens (must co-occur to be meaningful)
        $p1        = "finalshell" ascii wide nocase
        $p2        = "MobaXterm" ascii wide nocase
        $p3        = "navicat" ascii wide nocase
        $p4        = "dbeaver" ascii wide nocase
        $p5        = "Exodus.exe" ascii wide nocase
        $p6        = "Binance.exe" ascii wide nocase
        $p7        = "Hello-GPT.exe" ascii wide nocase
        $p8        = "idea64.exe" ascii wide nocase

    condition:
        filesize < 20MB
        and (
            $wrap
            or ( $block and 4 of ($p*) )
            or ( all of ($fb*) and 2 of ($p*) )
        )
}

rule QuickFox_FDMTP_IOC
{
    meta:
        description = "Static IOC sweep — QuickFox/FDMTP C2 domains, cluster IPs, and file hashes (Fortinet appendix, 2026-08-04)"
        author      = "synthetic-detections"
        date        = "2026-08-06"
        severity    = "high"
        family      = "quickfox-fdmtp-supply-chain"
        reference   = "https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant"

    strings:
        // Loader / C2 domains
        $d1  = "cdns3.51quickfox.cn" ascii wide nocase
        $d2  = "icloud-cdn.net" ascii wide nocase
        $d3  = "google-apis.net" ascii wide nocase
        $d4  = "yahoo-cdn.it.com" ascii wide nocase
        $d5  = "techcheck1.com" ascii wide nocase
        $d6  = "wangmeng.xyz" ascii wide nocase
        $d7  = "wangmengsb.com" ascii wide nocase
        $d8  = "wangmeng66.top" ascii wide nocase

        // FDMTP cluster IPs
        $ip1 = "47.238.64.56" ascii wide
        $ip2 = "47.239.93.49" ascii wide
        $ip3 = "47.239.4.179" ascii wide
        $ip4 = "47.88.21.252" ascii wide
        $ip5 = "38.60.142.56" ascii wide
        $ip6 = "154.223.75.206" ascii wide
        $ip7 = "154.223.58.64" ascii wide
        $ip8 = "154.223.58.142" ascii wide
        $ip9 = "45.158.180.250" ascii wide
        $ip10 = "47.238.240.219" ascii wide

        // File hashes (SHA-256)
        $h1 = "2b6cdafdfe427a3de1a94a8a2ca1f09fc4c8f90e4f59089fd9b35b73185ed01c" ascii nocase
        $h2 = "795594ad5e6f2868cc4d8ed12dabf4f3999a1477c6b250527c5ede9a98528fb9" ascii nocase
        $h3 = "6634339b813e6105b5138de6ab67b016b8dfbf49233c29de9bab3207e8b50d24" ascii nocase
        $h4 = "dc666e9c148bbca5e21d8c9a97143575c075f53360f135e0191aed9e8278d396" ascii nocase
        $h5 = "5cbb64375636e83b5f17d6083633cecc02e2a5f4168cd7cca5cdee36ccca9b38" ascii nocase
        $h6 = "a53d756f28457b1c4a239c91cdec8ed7b7da67a93e332e6df9621cbef8417474" ascii nocase
        $h7 = "d9db5cbc193ddaf4c0a265804fdef70c32451daaf2974fa9adf52ce1defac5f7" ascii nocase
        $h8 = "7462ce2595119c928cf516ec33148dc2a39dd9f71636a5c849c7ed93b7c5ca06" ascii nocase
        $h9 = "3bd3b300f3278520819a06d0cb1f0eadbf946dbbc11352538246ff075eb427f1" ascii nocase
        $h10 = "6932a20ac61fd3f93d7cfee414f6f46834068ac7c9ca011b054a6a10dc56b3d1" ascii nocase

    condition:
        filesize < 50MB
        and (
            any of ($d*)
            or 2 of ($ip*)
            or any of ($h*)
        )
}
