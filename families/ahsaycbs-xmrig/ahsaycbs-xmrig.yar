/*
   AhsayCBS exploitation -> XMRig cryptominer
   (disclosed 2026-10-08; Huntress)
   -----------------------------------------------------------------------
   Threat actors exploit CVE-2026-105133 and CVE-2026-105134 in AhsayCBS
   backup software to deploy XMRig-based cryptocurrency miners on
   compromised servers. The post-exploitation chain uses a modified NSSM
   binary (masquerading as msedge.exe) to install a persistent Windows
   service named "MicrosoftEdgeUpdateSvc" that launches XMRig (renamed to
   edge.exe), mining to the Kryptex pool at xmr.kryptex.network:8029.

   Kill chain:
     - Initial access via AhsayCBS RCE (CVE-2026-105133 / CVE-2026-105134).
     - Payloads staged on Alibaba Cloud OSS:
       imagefiles-backup.oss-ap-southeast-7.aliyuncs.com/javas/Office/win/
     - A modified NSSM (msedge.exe) registers a service
       "MicrosoftEdgeUpdateSvc" pointing to the miner binary (edge.exe).
     - XMRig config mines to xmr.kryptex.network:8029 under pool user
       krxYMRN97D/creativejs.
     - Taskgmr.ps1 — PowerShell watchdog that kills Task Manager to hide
       CPU usage and restarts the mining service if stopped.
     - WinRing0x64.sys driver loaded for MSR register access (XMRig perf).
     - Attacker IPs observed: 177.4.12.11, 38.60.252.110, 107.191.47.199,
       185.220.236.49, 104.234.26.10, 123.202.208.37.

   Rule 1 — Behavioral: campaign-specific string combinations.
   Rule 2 — IOC: globally unique tokens and co-occurring attacker IPs.
   Rule 3 — Specimen pin: SHA-256 hashes of 3 known samples.

   Sources:
     https://www.huntress.com/blog/threat-advisory-ahsaycbs-exploitation-xmrig
*/

import "hash"

rule AhsayCBS_XMRig_Behavioral : behavioral miner persistence
{
    meta:
        description = "AhsayCBS exploitation campaign — NSSM-based service persistence for XMRig miner, PowerShell watchdog killing Task Manager, Kryptex pool config, Alibaba Cloud OSS staging"
        author      = "synthetic-detections"
        date        = "2026-10-10"
        severity    = "critical"
        family      = "ahsaycbs-xmrig"
        reference   = "https://www.huntress.com/blog/threat-advisory-ahsaycbs-exploitation-xmrig"
    strings:
        // Service persistence via modified NSSM
        $svc_name       = "MicrosoftEdgeUpdateSvc" ascii wide nocase
        // Kryptex mining pool endpoint
        $pool           = "xmr.kryptex.network" ascii wide nocase
        $pool_port      = "8029" ascii wide
        // Pool user unique to this campaign
        $pool_user      = "krxYMRN97D" ascii wide
        $pool_user_full = "creativejs" ascii wide
        // Staging infrastructure on Alibaba Cloud OSS
        $staging_domain = "imagefiles-backup.oss-ap-southeast-7.aliyuncs.com" ascii wide nocase
        $staging_path   = "/javas/Office/win/" ascii wide nocase
        // Filenames used in the kill chain
        $fn_taskgmr     = "Taskgmr.ps1" ascii wide nocase
        $fn_msedge      = "msedge.exe" ascii wide nocase
        $fn_edge        = "edge.exe" ascii wide nocase
        $fn_winring     = "WinRing0x64.sys" ascii wide nocase
        // PowerShell watchdog behavior — kills Task Manager
        $ps_taskmgr     = "taskmgr" ascii wide nocase
        $ps_stop        = "Stop-Process" ascii wide nocase
        $ps_kill        = "Stop-Service" ascii wide nocase
        $ps_start       = "Start-Service" ascii wide nocase
        // XMRig indicator
        $xmrig          = "xmrig" ascii wide nocase
    condition:
        // Path 1: the fake service name + any mining indicator
        // Path 2: Kryptex pool + campaign pool user
        // Path 3: staging domain + payload path
        // Path 4: staging domain + any campaign artifact
        // Path 5: PowerShell watchdog — Task Manager killing + service
        // control for the mining service. Requires co-occurrence with
        // the campaign service name to avoid flagging legitimate admin
        // scripts that restart services or kill processes.
        // Path 6: Taskgmr.ps1 watchdog + any campaign anchor
        (
            ($svc_name and any of ($pool, $pool_port, $pool_user, $xmrig, $fn_edge)) or
            ($pool and ($pool_user or $pool_user_full)) or
            ($staging_domain and $staging_path) or
            ($staging_domain and any of ($svc_name, $fn_taskgmr, $fn_msedge, $fn_edge)) or
            ($ps_taskmgr and $ps_stop and any of ($ps_kill, $ps_start) and $svc_name) or
            ($fn_taskgmr and any of ($svc_name, $pool, $pool_user, $staging_domain, $fn_edge, $fn_winring))
        )
        and filesize < 20MB
}

rule AhsayCBS_XMRig_IOC : ioc miner
{
    meta:
        description = "Static IOC sweep — Kryptex pool user, Alibaba Cloud OSS staging domain, and attacker IPs observed in AhsayCBS exploitation campaign"
        author      = "synthetic-detections"
        date        = "2026-10-10"
        severity    = "high"
        family      = "ahsaycbs-xmrig"
        reference   = "https://www.huntress.com/blog/threat-advisory-ahsaycbs-exploitation-xmrig"
    strings:
        // Globally unique — fire standalone
        $unique_user    = "krxYMRN97D/creativejs" ascii wide
        $unique_stage   = "imagefiles-backup.oss-ap-southeast-7.aliyuncs.com" ascii wide nocase
        // Campaign anchor for IP co-occurrence
        $anchor_svc     = "MicrosoftEdgeUpdateSvc" ascii wide nocase
        $anchor_pool    = "xmr.kryptex.network" ascii wide nocase
        $anchor_stage   = "/javas/Office/win/" ascii wide nocase
        $anchor_taskgmr = "Taskgmr.ps1" ascii wide nocase
        // Attacker IPs — require co-occurrence (2+ together or with anchor)
        $ip1            = "177.4.12.11" ascii wide
        $ip2            = "38.60.252.110" ascii wide
        $ip3            = "107.191.47.199" ascii wide
        $ip4            = "185.220.236.49" ascii wide
        $ip5            = "104.234.26.10" ascii wide
        $ip6            = "123.202.208.37" ascii wide
    condition:
        // Globally unique tokens fire standalone
        // 2+ attacker IPs co-occurring
        // Single attacker IP + campaign anchor
        (
            $unique_user or
            $unique_stage or
            2 of ($ip*) or
            (any of ($ip*) and any of ($anchor_svc, $anchor_pool, $anchor_stage, $anchor_taskgmr))
        )
        and filesize < 50MB
}

rule AhsayCBS_XMRig_Specimen : miner specimen
{
    meta:
        description = "Specimen pin — exact SHA-256 hashes of 3 known samples from the AhsayCBS exploitation campaign (msedge.exe NSSM, edge.exe XMRig, Taskgmr.ps1 watchdog)"
        author      = "synthetic-detections"
        date        = "2026-10-10"
        severity    = "critical"
        family      = "ahsaycbs-xmrig"
        reference   = "https://www.huntress.com/blog/threat-advisory-ahsaycbs-exploitation-xmrig"
    condition:
        filesize < 50MB
        and (
            hash.sha256(0, filesize) == "05f69ae6b2b89c1c4dcf836bff032232f11bf0109f2b498e2345045d06139034" or
            hash.sha256(0, filesize) == "4dcb0202fe8b2d4d7b183764e38184cd6ed50132786cc7e7d1f7f4bce1dd6f3d" or
            hash.sha256(0, filesize) == "481728a7c9c4c02be07051d9c1958d902ea6397ebb8952ab83944818e3d25d21"
        )
}
