/*
   TerminalFix reverse-tunnel campaign
   (first catalogued 2026-08-28, Microsoft Threat Intelligence)
   -------------------------------------------------------------
   Multi-stage intrusion chain: fake Cloudflare CAPTCHA → clipboard-
   hijacked PowerShell command → DLL sideloading via legitimate
   LockScreenContentServer.exe + malicious dui70.dll → PNG
   steganography payload extraction → Active Directory recon →
   WebSocket reverse-tunnel implant (client.py over pythonw.exe).

   Used by Rhysida affiliates in the 2026 Berlin state network breach.

   Three rules:
     1. Behavioural — matches the DLL sideloading stage (dui70.dll
        with DirectUI masquerade + sideloading artifacts).
     2. IOC — known hashes, C2 domains, file paths, persistence
        names. Goes stale on infrastructure rotation.
     3. Lure page — matches the HTML/JS clipboard-hijack lure that
        initiates the chain (fake CAPTCHA + clipboard copy + terminal
        instruction pattern).

   References:
     - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
     - https://www.heise.de/en/news/BSI-explains-first-attack-vector-on-Berlin-authorities-11444212.html
     - https://www.malwarebytes.com/blog/news/2026/09/terminalfix-looks-like-clickfix-but-delivers-a-very-different-payload
     - https://thehackernews.com/2026/08/terminalfix-uses-fake-cloudflare.html
*/

import "pe"


rule TerminalFix_DLL_Sideload
{
    meta:
        description = "Detects dui70.dll malicious sideload payload used by TerminalFix campaign"
        author = "synthetic-detections"
        date = "2026-09-12"
        severity = "critical"
        family = "terminalfix"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
        hash = "ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07"
        hash = "026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab"
        hash = "032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22"
        hash = "df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf"

    strings:
        // dui70.dll masquerades as Windows DirectUI Engine
        $name_dui70 = "dui70.dll" ascii wide nocase
        $desc_directui = "Windows DirectUI Engine" ascii wide

        // LockScreenContentServer is the sideloading host
        $sideload_host = "LockScreenContentServer" ascii wide

        // Steganography extraction function
        $steg_func = "Extract-RawFileFromImage" ascii wide

        // Persistence artifacts
        $persist_bat = "1.bat" ascii wide
        $persist_lockscreen = "LockScreenContentServer_" ascii wide

        // Reverse tunnel implant indicators
        $tunnel_client = "client.py" ascii wide
        $tunnel_server = "--server" ascii wide
        $tunnel_uuid = "--uuid" ascii wide
        $tunnel_cert = "cert.pem" ascii wide

        // Reverse tunnel WebSocket endpoint
        $ws_tunnel = "/tunnel" ascii wide

        // AD recon commands
        $recon_trusts = "nltest /domain_trusts" ascii wide nocase
        $recon_admins = "domain admins" ascii wide nocase
        $recon_adsi = "ADSISearcher" ascii wide

        // Payload staging path
        $staging_path = "\\ProgramData\\f47f2a8c21c9df4e" ascii wide

    condition:
        filesize < 10MB
        and (
            // DLL sideload: dui70 name + DirectUI description + sideload host
            (2 of ($name_dui70, $desc_directui, $sideload_host))
            or
            // Steganography + persistence combo
            ($steg_func and any of ($persist_*))
            or
            // Reverse tunnel implant
            (3 of ($tunnel_*) and $ws_tunnel)
            or
            // AD recon + any staging/persistence indicator
            (2 of ($recon_*) and any of ($persist_*, $staging_path))
        )
}


rule TerminalFix_IOC
{
    meta:
        description = "Known TerminalFix campaign IOCs — C2 domains, file hashes, persistence names"
        author = "synthetic-detections"
        date = "2026-09-12"
        severity = "high"
        family = "terminalfix"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"

    strings:
        // C2 and payload-hosting domains
        $c2_gitnow = "gitnow.dev" ascii wide nocase
        $c2_newspapper = "bestsocialmedianewspapper.com" ascii wide nocase
        $c2_updater = "offlineupdater.com" ascii wide nocase
        $c2_linkedlog = "linked-log.com" ascii wide nocase

        // ZIP archive name
        $file_zip = "verify_pkg.zip" ascii wide nocase

        // Known dui70.dll SHA-256 hashes as strings (for threat intel docs)
        $hash1 = "ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07" ascii nocase
        $hash2 = "026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab" ascii nocase
        $hash3 = "032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22" ascii nocase
        $hash4 = "df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf" ascii nocase
        $hash5 = "eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0" ascii nocase
        $hash6 = "5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8" ascii nocase
        $hash7 = "9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24" ascii nocase
        $hash8 = "342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e" ascii nocase
        $hash9 = "ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d" ascii nocase
        $hash_zip = "18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f" ascii nocase
        $hash_tunnel = "b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a" ascii nocase

        // Persistence task/registry name pattern
        $persist_name = "LockScreenContentServer_MuODG5yBM" ascii wide

        // Staging directory
        $stage_dir = "f47f2a8c21c9df4e" ascii wide

    condition:
        filesize < 50MB
        and any of them
}


rule TerminalFix_Lure_Page
{
    meta:
        description = "Detects TerminalFix/ClickFix HTML lure pages with clipboard hijack and fake CAPTCHA"
        author = "synthetic-detections"
        date = "2026-09-12"
        severity = "critical"
        family = "terminalfix"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"

    strings:
        // Clipboard API used to plant malicious command
        $clip_write = "navigator.clipboard.writeText" ascii
        $clip_copy = "document.execCommand" ascii
        $clip_api = "clipboard.write" ascii

        // Fake CAPTCHA / verification text patterns
        $captcha_verify = "Verify you are human" ascii nocase
        $captcha_turnstile = "Turnstile" ascii nocase
        $captcha_cloudflare = "Cloudflare" ascii nocase
        $captcha_check = "Security check" ascii nocase

        // Terminal instruction patterns
        $instr_winr = /press\s+(Windows|Win)\s*\+\s*(R|X)/i
        $instr_terminal = "Windows Terminal" ascii nocase
        $instr_powershell = "PowerShell" ascii nocase
        $instr_paste = /Ctrl\s*\+\s*V/i
        $instr_enter = /press\s+Enter/i

    condition:
        filesize < 1MB
        and (
            // Clipboard write + fake CAPTCHA branding + terminal instruction
            any of ($clip_*) and any of ($captcha_*) and any of ($instr_*)
        )
}
