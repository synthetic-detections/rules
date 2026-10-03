/*
   Star Blizzard RedFlick / CosmicPulse — FSB Centre 18 phishing & backdoor
   ========================================================================
   Disclosed 2026-09-29 by Microsoft Threat Intelligence. Star Blizzard
   (COLDRIVER / SEABORGIUM), attributed to Russian FSB Centre 18, uses the
   "RedFlick" delivery technique: LNK inside password-protected ZIP/RAR
   triggers conhost.exe -> cmd.exe -> SSH or curl download of an MSI
   installer. MSI drops scheduled tasks that load CPL DLL applets, which
   bootstrap a bundled Python 3.8 runtime running the CosmicPulse backdoor
   (also tracked as YESROBOT / BAITSWITCH). C2 over WebDAV UNC paths.
   AES key stored in HKCU\Software\Classes\.mollis registry key.

   Three rules:
     1. StarBlizzard_RedFlick_Behavior
        Behavioural — co-occurrence of .mollis registry key, scheduled task
        names, CPL + Python bundling indicators, and WebDAV UNC patterns
        found in the RedFlick delivery chain.

     2. StarBlizzard_RedFlick_IOCs
        IOC-based — C2 domains, IPs, and delivery artifact hashes. Uses
        co-occurrence guards to avoid matching generic network logs.

     3. StarBlizzard_RedFlick_Specimens
        Specimen pin — exact SHA-256 hash matches for known campaign
        artifacts (ZIP, RAR, VHDX).

   Author: synthetic-detections, 2026-10-01
   Sources:
     Microsoft: https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/
   Sample hashes:
     9707a8694e954e9ee13e839d6e5905ce626c0837c7c90da6d1025bfbe152866b (ZIP)
     1f2096ff906915fbf80778f0636446206197351f7e271af97936eeb6f32c179d (VHDX)
     699e92a9e0edf7835879d5697bc67138c0b137117f459caf1a44df357407cad9 (RAR)
     24b6e36a09eb2acfc2a95478ca685acb7593b1689be6a4a639fe0d222393cfa7 (RAR)
     dd98dbc1a55afe6fd0ed2ed53a79c76f6bde15081a0060422185b74eb1799ee4 (ZIP)
   [[sibling]] midnight-blizzard-gtg20006
*/

import "hash"

rule StarBlizzard_RedFlick_Behavior {
    meta:
        description = "RedFlick delivery chain artifacts: .mollis registry key, scheduled task names, CPL applet masquerading, CosmicPulse Python backdoor markers, WebDAV UNC patterns"
        author = "synthetic-detections"
        date = "2026-10-01"
        severity = "critical"
        family = "CosmicPulse"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/"
    strings:
        $reg_mollis1 = "Software\\Classes\\.mollis" ascii wide nocase
        $reg_mollis2 = ".mollis" ascii wide
        $task1 = "Internet Quality Test Connection" ascii wide nocase
        $task2 = "Network Configuration Manager" ascii wide nocase
        $task3 = "System Health Monitor" ascii wide nocase
        $chain_ssh = "conhost.exe" ascii wide
        $chain_cmd = "cmd.exe /c" ascii wide nocase
        $chain_msi = ".msi" ascii wide
        $cpl_entry = "CPlApplet" ascii wide
        $cpl_ext = ".cpl" ascii wide nocase
        $cp_marker1 = "CosmicPulse" ascii wide nocase
        $cp_marker2 = "YESROBOT" ascii wide nocase
        $cp_marker3 = "BAITSWITCH" ascii wide nocase
        $python38 = "python38.dll" ascii wide nocase
        $python38z = "python38.zip" ascii wide nocase
        $webdav1 = "\\\\@SSL\\" ascii wide
        $webdav2 = "\\\\@SSL@" ascii wide
        $webdav3 = "DavWWWRoot" ascii wide nocase
    condition:
        (any of ($reg_mollis*) and any of ($task*) or any of ($reg_mollis*) and any of ($cpl_*) or 2 of ($task*) or any of ($cp_marker*) and (any of ($reg_mollis*) or any of ($task*) or any of ($webdav*)) or any of ($cpl_*) and any of ($python38*) and any of ($webdav*) or $chain_ssh and $chain_cmd and $chain_msi and (any of ($reg_mollis*) or any of ($task*)) or 2 of ($cp_marker*)) and filesize < 50MB
}

rule StarBlizzard_RedFlick_IOCs {
    meta:
        description = "RedFlick/CosmicPulse IOCs — C2 domains, IPs, and delivery artifact indicators"
        author = "synthetic-detections"
        date = "2026-10-01"
        severity = "high"
        family = "CosmicPulse"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/"
    strings:
        $dom1 = "etia.ca" nocase
        $dom2 = "groy.cc" nocase
        $dom3 = "muvb.net" nocase
        $dom4 = "divekickspolic.org" nocase
        $dom5 = "secure-dns-hub.com" nocase
        $dom6 = "cyrna.top" nocase
        $ip1 = "103.245.231.248"
        $ip2 = "2.57.241.246"
        $ip3 = "89.125.209.168"
        $ip4 = "45.84.59.66"
        $reg_mollis = "Software\\Classes\\.mollis" ascii wide nocase
        $task1 = "Internet Quality Test Connection" ascii wide nocase
        $task2 = "Network Configuration Manager" ascii wide nocase
        $task3 = "System Health Monitor" ascii wide nocase
    condition:
        (2 of ($dom*, $ip*) or any of ($dom*, $ip*) and any of ($reg_mollis, $task*)) and filesize < 50MB
}

rule StarBlizzard_RedFlick_Specimens {
    meta:
        description = "Known Star Blizzard RedFlick campaign samples — exact SHA-256 hash matches"
        author = "synthetic-detections"
        date = "2026-10-01"
        severity = "critical"
        family = "CosmicPulse"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/"
        hash1 = "9707a8694e954e9ee13e839d6e5905ce626c0837c7c90da6d1025bfbe152866b"
        hash2 = "1f2096ff906915fbf80778f0636446206197351f7e271af97936eeb6f32c179d"
        hash3 = "699e92a9e0edf7835879d5697bc67138c0b137117f459caf1a44df357407cad9"
        hash4 = "24b6e36a09eb2acfc2a95478ca685acb7593b1689be6a4a639fe0d222393cfa7"
        hash5 = "dd98dbc1a55afe6fd0ed2ed53a79c76f6bde15081a0060422185b74eb1799ee4"
    condition:
        hash.sha256(0, filesize) == "9707a8694e954e9ee13e839d6e5905ce626c0837c7c90da6d1025bfbe152866b" or hash.sha256(0, filesize) == "1f2096ff906915fbf80778f0636446206197351f7e271af97936eeb6f32c179d" or hash.sha256(0, filesize) == "699e92a9e0edf7835879d5697bc67138c0b137117f459caf1a44df357407cad9" or hash.sha256(0, filesize) == "24b6e36a09eb2acfc2a95478ca685acb7593b1689be6a4a639fe0d222393cfa7" or hash.sha256(0, filesize) == "dd98dbc1a55afe6fd0ed2ed53a79c76f6bde15081a0060422185b74eb1799ee4"
}
