/*
   Axios npm supply chain compromise — SILKBELL dropper + WAVESHAPER RAT
   (disclosed 2026-03-31, attributed to Sapphire Sleet / BlueNoroff / DPRK)
   -----------------------------------------------------------------------
   Compromised npm maintainer account (jasonsaayman) published backdoored
   axios@1.14.1 and axios@0.30.4 with a phantom dependency
   plain-crypto-js@4.2.1. The postinstall hook in setup.js uses XOR with
   key "OrDeR_7077" + constant 333, Base64 encoding, and string reversal
   to reconstruct C2 URLs. Dropper contacts sfrclak[.]com:8000/6202033
   (142.11.206.73, Hostwinds) and deploys OS-specific RATs:
     - Windows: VBScript stager → PowerShell RAT, persists as
       MicrosoftUpdate Run key, copies pwsh to wt.exe
     - macOS: AppleScript → Mach-O binary at com.apple.act.mond,
       internal project name "macWebT" (links to BlueNoroff RustBucket)
     - Linux: Python RAT at /tmp/ld.py
   RAT beacons every 60s with FirstInfo/BaseInfo/CmdResult JSON→Base64
   messages. Commands: kill, peinject, runscript, rundir.

   Microsoft: SILKBELL (dropper), WAVESHAPER.V2 (RAT)
   GTIG: UNC1069 / Sapphire Sleet / BlueNoroff / CryptoCore

   Companion family: easydayjs-mastra-rat (2026-06-17) shares the same
   User-Agent, Hostwinds hosting, postinstall dropper pattern, and
   crypto-stealer payload — attribution unconfirmed but tradecraft
   overlap is extensive.

   Rule 1 — Behavioral: SILKBELL dropper — obfuscated setup.js with
            XOR key, platform fingerprinting, self-delete.
   Rule 2 — Structural: WAVESHAPER RAT persistence artifacts across
            all three platforms + beacon protocol markers.
   Rule 3 — IOC: C2 infrastructure, hashes, accounts, package coords.

   Sources:
     https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/
     https://hunt.io/blog/axios-supply-chain-attack-ta444-bluenoroff
     https://www.bleepingcomputer.com/news/security/hackers-compromise-axios-npm-package-to-drop-cross-platform-malware/
     https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
     https://research.jfrog.com/post/easy-day-js/ (tradecraft comparison)
*/

rule Axios_SILKBELL_Dropper {
    meta:
        description = "SILKBELL dropper — obfuscated setup.js with OrDeR_7077 XOR key, platform fingerprinting POST bodies, and self-delete"
        author = "synthetic-detections"
        date = "2026-06-18"
        severity = "critical"
        family = "axios-silkbell-rat"
        reference = "https://hunt.io/blog/axios-supply-chain-attack-ta444-bluenoroff"
    strings:
        // XOR cipher key used in dropper obfuscation
        $xor_key = "OrDeR_7077"
        // Platform selection POST body markers — the dropper sends
        // these to the C2 to request OS-specific payloads
        $plat_mac = "packages.npm.org/product0"
        $plat_win = "packages.npm.org/product1"
        $plat_linux = "packages.npm.org/product2"
        // Campaign ID embedded in C2 URL path
        $campaign_id = "/6202033"
        // Dropper filename and postinstall hook
        $setup_js = "setup.js"
        $postinstall = "postinstall"
        // Phantom dependency injected into axios package.json
        $phantom_dep = "plain-crypto-js"
        // TLS disable (same pattern as easy-day-js successor)
        $tls_disable = "NODE_TLS_REJECT_UNAUTHORIZED"
        // Self-delete after execution
        $self_rm = "rmSync"
        // package.md → package.json rename trick
        $pkg_rename = "package.md"
    condition:
        // Path 1: setup.js dropper with XOR key
        // Path 2: platform fingerprinting POST bodies
        // Path 3: phantom dependency in package context
        // Path 4: dropper filename + package rename trick + TLS
        ($xor_key and ($self_rm or $tls_disable or $campaign_id) or 2 of ($plat_mac, $plat_win, $plat_linux) or $phantom_dep and $postinstall or $setup_js and $pkg_rename and $tls_disable) and filesize < 500KB
}

rule Axios_WAVESHAPER_RAT {
    meta:
        description = "WAVESHAPER.V2 cross-platform RAT — persistence artifacts (MicrosoftUpdate/com.apple.act.mond/ld.py), beacon protocol, command set"
        author = "synthetic-detections"
        date = "2026-06-18"
        severity = "critical"
        family = "axios-silkbell-rat"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/"
    strings:
        // Windows persistence
        $win_runkey = "MicrosoftUpdate"
        $win_wt = "wt.exe"
        $win_bat = "system.bat"
        $win_vbs = "6202033.vbs"
        // macOS persistence — masquerades as Apple daemon
        $mac_persist = "com.apple.act.mond"
        // Internal Xcode project name linking to BlueNoroff RustBucket
        $mac_webt = "macWebT"
        // macOS build path artifact
        $mac_build = "Jain_DEV"
        // Linux persistence
        $linux_rat = "ld.py"
        // Shared User-Agent across all platforms (IE8 on XP —
        // identical to easy-day-js successor campaign)
        $ua_beacon = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)" nocase
        // RAT beacon message types (JSON field values)
        $beacon_first = "FirstInfo"
        $beacon_base = "BaseInfo"
        $beacon_cmd = "CmdResult"
        // RAT command strings
        $cmd_kill = "\"kill\""
        $cmd_peinject = "peinject"
        $cmd_runscr = "runscript"
        $cmd_rundir = "rundir"
        // Status response strings
        $resp_wow = "\"Wow\""
        $resp_zzz = "\"Zzz\""
        // PowerShell execution flags (Windows RAT)
        $ps_flags = "-w hidden -ep bypass" nocase
    condition:
        // Path 1: macOS binary — project name or persistence path
        // Path 2: Windows RAT — Run key + batch/VBS artifacts
        // Path 3: beacon protocol — message types + command set
        // Path 4: shared BlueNoroff User-Agent + any RAT indicator
        // Path 5: Linux RAT path + beacon indicators
        // Path 6: response status codes + command set (RAT comms)
        ($mac_persist or $mac_webt and $mac_build or $win_runkey and any of ($win_bat, $win_vbs, $win_wt) or 2 of ($beacon_first, $beacon_base, $beacon_cmd) and any of ($cmd_kill, $cmd_peinject, $cmd_runscr, $cmd_rundir) or $ua_beacon and any of ($mac_persist, $win_runkey, $beacon_first, $cmd_peinject) or $linux_rat and ($ua_beacon or $beacon_first or $ps_flags) or any of ($resp_wow, $resp_zzz) and 2 of ($cmd_kill, $cmd_peinject, $cmd_runscr, $cmd_rundir)) and filesize < 10MB
}

rule Axios_SILKBELL_IOC {
    meta:
        description = "Static IOC sweep — C2 infrastructure, file hashes, hijacked accounts, package coordinates, Sapphire Sleet infrastructure overlaps"
        author = "synthetic-detections"
        date = "2026-06-18"
        severity = "high"
        family = "axios-silkbell-rat"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/"
    strings:
        // C2 domain and IP
        $c2_domain = "sfrclak.com"
        $c2_domain2 = "callnrwise.com"
        $c2_ip = "142.11.206.73"
        // Hostwinds reverse DNS
        $rdns = "hwsrv-1320779"
        // Related Sapphire Sleet infrastructure (hunt.io pivots)
        $infra1 = "23.254.167.216"
        $infra2 = "108.174.194.44"
        $infra3 = "108.174.194.196"
        // Campaign endpoint
        $campaign = "6202033"
        // Malicious package name
        $phantom = "plain-crypto-js"
        // XOR key (unique to this campaign)
        $xor_key = "OrDeR_7077"
        // Hijacked npm account
        $acct_hijack = "jasonsaayman"
        // Attacker accounts and emails
        $acct_atk = "nrwise"
        $email_atk1 = "ifstap@proton.me"
        $email_atk2 = "nrwise@proton.me"
        // File hashes (SHA-256) — dropper and RAT payloads
        $hash_setup = "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09" nocase
        $hash_mac = "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a" nocase
        $hash_mac2 = "506690fcbd10fbe6f2b85b49a1fffa9d984c376c25ef6b73f764f670e932cab4" nocase
        $hash_win_ps = "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101" nocase
        $hash_win_bt = "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd" nocase
        $hash_linux = "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf" nocase
        $hash_pkg = "58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668" nocase
        $hash_axios = "5bb67e88846096f1f8d42a0f0350c9c46260591567612ff9af46f98d1b7571cd" nocase
        // macOS build path artifact
        $build_path = "Jain_DEV"
        $project = "macWebT"
        // SSH key fingerprint linking infrastructure
        $ssh_key = "e1f6b7f621a391a9d26e9a196974f3e2cc1ce8b4d8f73a14b2e8cb0f2a40289f" nocase
        // Defender detection names
        $det_js = "AxioRAT"
        $det_mac = "Multiverze"
        $det_py = "TalonStrike"
    condition:
        // C2 infrastructure
        // Related Sapphire Sleet IPs
        // Attacker accounts (hijacked maintainer + attacker publisher)
        // File hashes
        // Campaign-specific strings: XOR key or phantom dep +
        // campaign ID
        // macOS attribution artifacts
        // Infrastructure SSH key
        // Defender detection classification names
        (any of ($c2_domain, $c2_domain2, $c2_ip, $rdns) or 2 of ($infra1, $infra2, $infra3) or any of ($acct_hijack, $acct_atk, $email_atk1, $email_atk2) or any of ($hash_setup, $hash_mac, $hash_mac2, $hash_win_ps, $hash_win_bt, $hash_linux, $hash_pkg, $hash_axios) or $xor_key and $campaign or $phantom and $campaign or $build_path and $project or $ssh_key or any of ($det_js, $det_mac, $det_py)) and filesize < 50MB
}
