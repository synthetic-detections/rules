/*
   Midnight Blizzard GTG-20006 — AI-orchestrated espionage campaign, 2026-09
   --------------------------------------------------------------------------
   Campaign attributed to Midnight Blizzard (APT29/Cozy Bear) tracked as
   GTG-20006. Multi-platform intrusion set targeting government and diplomatic
   entities through Microsoft-service impersonation and autonomous malware
   rebuilding when detected.

   Malware families: PowerChrome (browser credential harvester), WUEngine
   (Windows Update impersonator), Shadow C2 (covert command-and-control),
   MiniPlasma (lightweight implant), CloudSyncSvc (cloud persistence agent).
   Mobile: GiftDrop (Android dropper), DarkSword (iOS implant).

   Infrastructure uses a distinctive Microsoft-impersonation domain pattern:
   ms365-live[.]com, m365-owa[.]com, owa-ms365[.]com, ms365-device[.]com,
   statistic-ms[.]live, static-ms[.]live, docs-viewer[.]org — with WhatsApp
   lures via wa-connect[.]eu and wa-meeting[.]com.

   Executables masquerade as Microsoft Edge and Windows Update components:
   msedgeupdate_v3.exe, msedgeupdate.exe, WUEngine.exe, DiagHost.exe,
   client_20260507093021_4286d211_x64.exe, fix_network.apk.

   Rule 1 — behavioural: Microsoft-impersonation C2 domain pattern plus
            executable naming consistent with the campaign's masquerading.
   Rule 2 — IOC sweep: C2 domains and IPs with co-occurrence guard (>=2).
   Rule 3 — specimen-pin: SHA-256 pins for known campaign samples.

   Sources:
     https://www.anthropic.com/research/september-2026-threat-intelligence-report
*/

import "hash"

rule MidnightBlizzard_GTG20006_Behavioural {
    meta:
        description = "Midnight Blizzard GTG-20006 behavioural — Microsoft-impersonation C2 domain patterns combined with campaign executable naming"
        author = "synthetic-detections"
        date = "2026-09-14"
        severity = "critical"
        family = "midnight-blizzard-gtg20006"
        reference = "https://www.anthropic.com/research/september-2026-threat-intelligence-report"
    strings:
        $c2_ms365 = /ms365-[a-z]{2,10}\.(com|live)/
        $c2_m365 = /m365-[a-z]{2,10}\.(com|live)/
        $c2_owa = /owa-ms365\.(com|live)/
        $c2_stat_ms = /stat(ic|istic)-ms\.live/
        $c2_docs = "docs-viewer.org" nocase
        $c2_wa = /wa-(connect|meeting)\.(eu|com)/
        $exe_edge1 = "msedgeupdate_v3.exe" nocase
        $exe_edge2 = "msedgeupdate.exe" nocase
        $exe_wu = "WUEngine.exe" nocase
        $exe_diag = "DiagHost.exe" nocase
        $exe_client = "client_20260507093021_4286d211_x64.exe" nocase
        $exe_apk = "fix_network.apk" nocase
        $fam_pc = "PowerChrome" nocase
        $fam_shadow = "Shadow C2"
        $fam_mini = "MiniPlasma"
        $fam_cloud = "CloudSyncSvc"
        $fam_gift = "GiftDrop"
        $fam_dark = "DarkSword"
    condition:
        (any of ($c2_*) and any of ($exe_*, $fam_*) or 2 of ($c2_*) or 2 of ($exe_*) or $exe_client) and filesize < 50MB
}

rule MidnightBlizzard_GTG20006_IOC {
    meta:
        description = "Midnight Blizzard GTG-20006 IOC sweep — C2 domains and IPs with co-occurrence guard (at least 2 indicators must match)"
        author = "synthetic-detections"
        date = "2026-09-14"
        severity = "high"
        family = "midnight-blizzard-gtg20006"
        reference = "https://www.anthropic.com/research/september-2026-threat-intelligence-report"
    strings:
        $d01 = "ms365-live.com" nocase
        $d02 = "teams.ms365-live.com" nocase
        $d03 = "m365-owa.com" nocase
        $d04 = "owa-ms365.com" nocase
        $d05 = "ms365-device.com" nocase
        $d06 = "statistic-ms.live" nocase
        $d07 = "static-ms.live" nocase
        $d08 = "docs-viewer.org" nocase
        $d09 = "wa-connect.eu" nocase
        $d10 = "wa-meeting.com" nocase
        $ip1 = "104.145.210.184"
        $ip2 = "31.57.243.154"
        $ip3 = "104.194.151.133"
        $ip4 = "104.194.159.55"
        $ip5 = "144.172.114.192"
        $ip6 = "213.145.86.112"
        $ip7 = "148.135.195.111"
    condition:
        2 of ($d*, $ip*) and filesize < 50MB
}

rule MidnightBlizzard_GTG20006_Specimen {
    meta:
        description = "Midnight Blizzard GTG-20006 specimen pin — SHA-256 hashes for known campaign samples"
        author = "synthetic-detections"
        date = "2026-09-14"
        severity = "critical"
        family = "midnight-blizzard-gtg20006"
        reference = "https://www.anthropic.com/research/september-2026-threat-intelligence-report"
    condition:
        hash.sha256(0, filesize) == "be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c" or hash.sha256(0, filesize) == "918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593"
}
