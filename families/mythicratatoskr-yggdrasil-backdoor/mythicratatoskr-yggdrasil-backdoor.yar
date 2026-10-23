/*
   MythicRatatoskr — Yggdrasil-enabled Mythic backdoor
   ====================================================
   Disclosed 2026-10-22 by ESET (LABScon 2026). Deployed against a
   Ukrainian grain logistics company. UAC-0099 provided initial access
   via spear-phishing; Sandworm then deployed MythicRatatoskr plus a
   SOCKS5 proxy tool and destructive wipers. Activity dated mid-2025;
   first public technical writeup October 2026.

   Go binary implementing a Mythic agent that tunnels C2 over the
   Yggdrasil decentralized IPv6 mesh network (200::/7). Uses AES-256-CFB
   for config encryption with a hardcoded PSK. Connects to C2 on port
   443/HTTPS over the Yggdrasil overlay. Companion SOCKS5 server tool
   (nbtresolver.exe / krbtman.exe) listens on 127.0.0.1:33690.

   Three rules:
     1. Sandworm_MythicRatatoskr_Agent
        Behavioural — Go Mythic agent function names, AES PSK, Yggdrasil
        bootstrap indicators, and backdoor command dispatch strings.

     2. Sandworm_MythicRatatoskr_IOCs
        IOC-based — C2 IPv6 addresses, config file paths, deployment
        filenames, related MATCHWOK infrastructure.

     3. Sandworm_MythicRatatoskr_SOCKS5
        Structural — companion SOCKS5 proxy tool with bindProxy function,
        Yggdrasil integration, and local listener on port 33690.

   Author: synthetic-detections, 2026-10-23
   Sources:
     ESET: https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration/
   Sample hashes (SHA-1, no SHA-256 published):
     D5F9288DAEBF87AE4579945F8DC6CF235B093CFD (Act64.exe)
     B69EF0E45B401440C0FDE22046775D0C57E87415 (ie.exe)
     4E3E6577866E4CE2ED73CA089700AE04230E768F (ieupdate.exe)
     028CA11F3F0D8396043AF7BF756231FC2F50F829 (windowsdefendersvc.exe)
     E29AF83A07FB32EB47C28733A9382E766D53F704 (OneDriveLiveUpdater.exe)
     D7E6A5A46C6ED3510997E91B11E51BE0250FD2A2 (updater.exe)
     131A371A1E4EE78EC3B2863607C99290EC3B58A6 (krbtman.exe, SOCKS5)
     09C816697C0C2AFF9B4FF58681558CA30D04C9CD (nbtresolver.exe, SOCKS5)
*/

import "pe"

rule Sandworm_MythicRatatoskr_Agent : apt malware
{
    meta:
        description = "MythicRatatoskr Yggdrasil-enabled Mythic agent — function names, AES PSK, and command dispatch"
        author      = "synthetic-detections"
        date        = "2026-10-23"
        severity    = "critical"
        family      = "MythicRatatoskr"
        reference   = "https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration/"
    strings:
        // Mythic agent Go function names (survive in Go binaries)
        $fn_checkin    = "CheckInAgent"
        $fn_save_cfg   = "saveConfig"
        $fn_agent_run  = "agent_run"
        $fn_init_agent = "init_agent"
        $fn_get_tasks  = "getTasks"
        $fn_do_task    = "doTask"
        $fn_socks      = "connectForSocks"
        $fn_run_svc    = "runService"
        // Hardcoded AES-256-CFB PSK (base64)
        $aes_psk       = "US3pM9KFxrZBSgc1pGl2wO4Kir1XjZP5Z9kBXBMYd2s="
        // Mythic check-in UUID
        $uuid_checkin  = "d71f1722-cf0b-4e27-9f8e-c95ec9b24a23"
        // Backdoor command strings (unique combination)
        $cmd_chtime    = "chtime"
        $cmd_expose    = "expose"
        $cmd_nodeinfo  = "nodeinfo"
        $cmd_churl     = "churl"
        // Debug/logging strings
        $dbg_accept    = "Accepting stream"
        $dbg_socks     = "Passing off to socks5"
        // Yggdrasil 200::/7 subnet reference
        $ygg_subnet    = "200::"
    condition:
        // Agent functions + PSK
        // Agent functions + check-in UUID
        // Agent function cluster (4+ is high-confidence Mythic agent)
        // Debug strings + Yggdrasil + any agent function
        // PSK + command dispatch (even without function names)
        (
            ($aes_psk and 2 of ($fn_*)) or
            ($uuid_checkin and 2 of ($fn_*)) or
            (4 of ($fn_*) and any of ($cmd_*)) or
            (any of ($dbg_*) and $ygg_subnet and any of ($fn_*)) or
            ($aes_psk and 3 of ($cmd_*))
        )
        and filesize < 30MB
}

rule Sandworm_MythicRatatoskr_IOCs : c2 ioc
{
    meta:
        description = "MythicRatatoskr IOCs — C2 addresses, config paths, deployment filenames, MATCHWOK infrastructure"
        author      = "synthetic-detections"
        date        = "2026-10-23"
        severity    = "high"
        family      = "MythicRatatoskr"
        reference   = "https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration/"
    strings:
        // Yggdrasil C2 IPv6 address (port 2838)
        $c2_ygg           = "201:b479:2771:8df4:b5eb:d007:63b0"
        // Config file paths (distinctive hidden-file convention)
        $cfg_updatecache1 = "\\Windows\\Temp\\.updatecache"
        $cfg_updatecache2 = "\\system32\\.updatecache"
        $cfg_crond        = "/Temp/.crond"
        // Unix test path left in binary
        $cfg_test         = "/tmp/.test_config"
        // Deployment filenames in system directories
        $fn_krbtman       = "krbtman.exe"
        $fn_updater       = "\\system32\\updater.exe"
        $fn_wdsvc         = "windowsdefendersvc.exe"
        $fn_odlive        = "OneDriveLiveUpdater.exe"
        $fn_apphost       = "applicationasphost.exe"
        // MATCHWOK infrastructure (related initial access)
        $matchwok_c2      = "uztickets.com"
        $matchwok_dl      = "egyptanimals.com"
        // Scheduled task name
        $schtask          = "pdfopentask"
    condition:
        any of them and filesize < 50MB
}

rule Sandworm_MythicRatatoskr_SOCKS5 : apt malware tool
{
    meta:
        description = "MythicRatatoskr companion SOCKS5 proxy — Yggdrasil-tunneled, binds 127.0.0.1:33690"
        author      = "synthetic-detections"
        date        = "2026-10-23"
        severity    = "critical"
        family      = "MythicRatatoskr"
        reference   = "https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration/"
    strings:
        // SOCKS5 tool internal name
        $fn_bind_proxy = "bindProxy"
        // Local SOCKS5 listener
        $listen_addr   = "127.0.0.1:33690"
        // Debug strings
        $dbg_accept    = "Accepting stream"
        $dbg_socks     = "Passing off to socks5"
        // Yggdrasil subnet
        $ygg           = "200::"
        // Go function names present in SOCKS5 variant
        $fn_run_svc    = "runService"
        $fn_socks      = "connectForSocks"
    condition:
        // bindProxy + SOCKS5 listener is definitive
        // bindProxy + Yggdrasil + debug
        // SOCKS5 listener + Yggdrasil + service runner
        (
            ($fn_bind_proxy and $listen_addr) or
            ($fn_bind_proxy and $ygg and any of ($dbg_*)) or
            ($listen_addr and $ygg and $fn_run_svc) or
            ($fn_socks and $fn_bind_proxy and $ygg)
        )
        and filesize < 30MB
}
