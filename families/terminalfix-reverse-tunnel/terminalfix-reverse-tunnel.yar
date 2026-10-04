/*
   TerminalFix reverse-tunnel campaign (STAC4924)
   (first catalogued 2026-08-28, Microsoft Threat Intelligence)
   (STAC4924 expansion 2026-10, Sophos)
   -------------------------------------------------------------
   Multi-stage intrusion chain: fake Cloudflare CAPTCHA → clipboard-
   hijacked PowerShell command → DLL sideloading via legitimate
   Windows binaries + malicious DLL → Lorem Ipsum Loader (shellcode
   encoded as English words for entropy evasion) → Python WebSocket
   reverse-tunnel implant (client.py).

   Attributed to GOLD VICTOR / Vanilla Tempest / VICE SPIDER.
   Used by Rhysida affiliates in the 2026 Berlin state network breach.

   Three rules:
     1. Behavioural — matches DLL sideloading stage across known
        host/DLL pairs and the Lorem Ipsum word-to-shellcode loader.
     2. IOC — known hashes, C2 domains, staging domains, file paths,
        persistence names. Goes stale on infrastructure rotation.
     3. Lure page — matches the HTML/JS clipboard-hijack lure that
        initiates the chain (fake CAPTCHA + clipboard copy + terminal
        instruction pattern).

   References:
     - https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
     - https://www.sophos.com/en-us/blog/terminalfix-and-lorem-ipsum-loader-enable-covert-tunneling
     - https://www.heise.de/en/news/BSI-explains-first-attack-vector-on-Berlin-authorities-11444212.html
     - https://www.malwarebytes.com/blog/news/2026/09/terminalfix-looks-like-clickfix-but-delivers-a-very-different-payload
     - https://thehackernews.com/2026/08/terminalfix-uses-fake-cloudflare.html
*/

import "pe"

rule TerminalFix_DLL_Sideload
{
    meta:
        description = "Detects DLL sideloading payloads and Lorem Ipsum Loader used by TerminalFix/STAC4924"
        author      = "synthetic-detections"
        date        = "2026-10-04"
        severity    = "critical"
        family      = "terminalfix"
        reference   = "https://www.sophos.com/en-us/blog/terminalfix-and-lorem-ipsum-loader-enable-covert-tunneling"
        hash        = "ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07"
        hash        = "026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab"
        hash        = "032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22"
        hash        = "df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf"
    strings:
        // Phase 1 sideloading: LockScreenContentServer.exe → dui70.dll
        $name_dui70         = "dui70.dll" ascii wide nocase
        $desc_directui      = "Windows DirectUI Engine" ascii wide
        $sideload_host1     = "LockScreenContentServer" ascii wide
        // Phase 2 sideloading pairs (Sophos STAC4924)
        $sideload_host2     = "changepk.exe" ascii wide nocase
        $sideload_host3     = "embeddedapplauncher.exe" ascii wide nocase
        $sideload_dll2a     = "faultrep.dll" ascii wide nocase
        $sideload_dll2b     = "sppcext.dll" ascii wide nocase
        // Steganography extraction function
        $steg_func          = "Extract-RawFileFromImage" ascii wide
        // Persistence artifacts
        $persist_bat        = "1.bat" ascii wide fullword
        $persist_lockscreen = "LockScreenContentServer_" ascii wide
        // Reverse tunnel implant indicators
        $tunnel_client      = "client.py" ascii wide
        $tunnel_server      = "--server" ascii wide
        $tunnel_uuid        = "--uuid" ascii wide
        $tunnel_cert        = "cert.pem" ascii wide
        // Reverse tunnel WebSocket endpoint
        $ws_tunnel          = "/tunnel" ascii wide
        // Python staging path (Sophos)
        $staging_indigo     = "\\Users\\Public\\indigo" ascii wide
        // AD recon commands
        $recon_trusts       = "nltest /domain_trusts" ascii wide nocase
        $recon_admins       = "domain admins" ascii wide nocase
        $recon_adsi         = "ADSISearcher" ascii wide
        // Payload staging path
        $staging_path       = "\\ProgramData\\f47f2a8c21c9df4e" ascii wide
    condition:
        (
            ($sideload_host1 and ($name_dui70 or $desc_directui)) or
            ($sideload_host2 and ($sideload_dll2a or $sideload_dll2b)) or
            ($sideload_host3 and $tunnel_client) or
            ($steg_func and any of ($persist_*)) or
            (3 of ($tunnel_*) and $ws_tunnel) or
            (2 of ($recon_*) and any of ($persist_*, $staging_path, $staging_indigo))
        )
        and filesize < 10MB
}

rule TerminalFix_IOC
{
    meta:
        description = "Known TerminalFix/STAC4924 IOCs — C2 domains, staging infra, file hashes, persistence names"
        author      = "synthetic-detections"
        date        = "2026-10-04"
        severity    = "high"
        family      = "terminalfix"
        reference   = "https://www.sophos.com/en-us/blog/terminalfix-and-lorem-ipsum-loader-enable-covert-tunneling"
    strings:
        // C2 domains (Microsoft report)
        $c2_gitnow           = "gitnow.dev" ascii wide nocase
        $c2_linkedlog        = "linked-log.com" ascii wide nocase
        // C2 domains (Sophos STAC4924)
        $c2_newspapper       = "bestsocialmedianewspapper.com" ascii wide nocase
        $c2_updater          = "offlineupdater.com" ascii wide nocase
        $c2_fixdoc           = "fixdocumentview.com" ascii wide nocase
        $c2_opendocfree      = "openlockeddocuments.com" ascii wide nocase
        $c2_appdoc           = "yourappdoctor.com" ascii wide nocase
        $c2_prettypic        = "yourprettylittlepicture.com" ascii wide nocase
        $c2_biblegod         = "biblegodlike.com" ascii wide nocase
        $c2_peekphoto        = "peekyourphoto.com" ascii wide nocase
        $c2_catimage         = "freecatimages.com" ascii wide nocase
        $c2_kittyspace       = "kittyfreespace.com" ascii wide nocase
        $c2_oceansecret      = "oceansecretlife.com" ascii wide nocase
        $c2_semigoddess      = "semigoddess.com" ascii wide nocase
        $c2_webfeed          = "webfeedonline.com" ascii wide nocase
        $c2_fishplanet       = "fish-planet.online" ascii wide nocase
        $c2_forestpet        = "forest-pet.com" ascii wide nocase
        $c2_yellowtree       = "yellow-tree.online" ascii wide nocase
        $c2_cave             = "cave-discovery.online" ascii wide nocase
        // Staging domains (Sophos)
        $stg_ghostproc       = "ghostproc.com" ascii wide nocase
        $stg_assetsoftgo     = "assetsoftgo.com" ascii wide nocase
        $stg_autorelaylab    = "autorelaylab.com" ascii wide nocase
        $stg_adstatli        = "adstatli.com" ascii wide nocase
        $stg_metricgw        = "metricgw.com" ascii wide nocase
        $stg_platformhub     = "platformco-hub.com" ascii wide nocase
        $stg_swiftcurrento   = "swiftcurrento.net" ascii wide nocase
        $stg_cronverta       = "cronverta.net" ascii wide nocase
        // Dead-drop resolver
        $deadrop_letsdiskuss = "letsdiskuss.com/user/" ascii wide nocase
        // ZIP archive name
        $file_zip            = "verify_pkg.zip" ascii wide nocase
        // Known dui70.dll SHA-256 hashes as strings
        $hash1               = "ba77feed86bcda49308746421bdc684a432dd5d68c363975b2a3c6831bda3f07" nocase
        $hash2               = "026478003fe354134c03acf6890e7d3b153ba08a836eca42350db48f213872ab" nocase
        $hash3               = "032b529fac61e550f5dc9489686f519b82d64625fa05a8d9ecf8ba8be9b2ad22" nocase
        $hash4               = "df8221a933b38284ebdcb8bffc2df62123c9f5b5f421dd0b070e13e668b3eabf" nocase
        $hash5               = "eb1b4be34d05b394fb74efdeb95faecd1d1963be6ecc1b9db2b4757b491f01f0" nocase
        $hash6               = "5d43abf5c36ea203176d3300ff14af27b4be81810ad2679b3a62b255e3d6e1c8" nocase
        $hash7               = "9a7b4dcd51d9251c177d323d6aaecdfc86674f69bc1af048dc872926d22aaa24" nocase
        $hash8               = "342df92235c9dec81203b837addaa38bb85b64b4a48fe71b5303ca86d991991e" nocase
        $hash9               = "ededeacf30e493dd632d477fe770ba419aa2848f685ea049381a0a8d2cc3e84d" nocase
        $hash_zip            = "18c2090e8a0ae0568af9b87e59eaf8270f23d2909600ed9db91a9444fd8b278f" nocase
        $hash_tunnel         = "b8d107800403b9197e5b7609ceacd8e4cac1b0f9a1d156e6dacd6c3f7794b36a" nocase
        // Persistence task/registry name pattern
        $persist_name        = "LockScreenContentServer_MuODG5yBM" ascii wide
        // Staging directories
        $stage_dir           = "f47f2a8c21c9df4e" ascii wide
        $stage_indigo        = "\\Users\\Public\\indigo\\" ascii wide
    condition:
        any of them and filesize < 50MB
}

rule TerminalFix_Lure_Page
{
    meta:
        description = "Detects TerminalFix/ClickFix HTML lure pages with clipboard hijack and fake CAPTCHA"
        author      = "synthetic-detections"
        date        = "2026-09-12"
        severity    = "critical"
        family      = "terminalfix"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/"
    strings:
        // Clipboard API used to plant malicious command
        $clip_write         = "navigator.clipboard.writeText"
        $clip_copy          = "document.execCommand"
        $clip_api           = "clipboard.write"
        // Fake CAPTCHA / verification text patterns
        $captcha_verify     = "Verify you are human" nocase
        $captcha_turnstile  = "Turnstile" nocase
        $captcha_cloudflare = "Cloudflare" nocase
        $captcha_check      = "Security check" nocase
        // Terminal instruction patterns
        $instr_winr         = /press\s+(Windows|Win)\s*\+\s*(R|X)/i
        $instr_terminal     = "Windows Terminal" nocase
        $instr_powershell   = "PowerShell" nocase
        $instr_paste        = /Ctrl\s*\+\s*V/i
        $instr_enter        = /press\s+Enter/i
    condition:
        // Clipboard write + fake CAPTCHA branding + terminal instruction
        any of ($clip_*) and any of ($captcha_*) and any of ($instr_*) and filesize < 1MB
}
