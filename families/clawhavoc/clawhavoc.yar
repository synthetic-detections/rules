/*
   ClawHavoc — OpenClaw / ClawHub malicious-skill detection
   ========================================================
   Targets the ClawHavoc supply-chain campaign that compromised the
   ClawHub agent-skill marketplace with 1,184+ malicious skills across
   12 publisher accounts, delivering Atomic macOS Stealer (AMOS),
   Vidar, GhostSocks, PureLogs, and GhostClaw RAT.

   Four rules:
     1. ClawHavoc_SKILL_Dropper
        Behavioural — catches malicious SKILL.md / README patterns:
        social-engineering "Prerequisites" or "Setup" sections that
        instruct the user to curl+pipe from bare IPs, paste base64
        blobs, or download password-protected ZIPs.

     2. ClawHavoc_IOCs
        IOC-based — C2 IPs, exfil domains, paste-site URLs, GitHub
        repos, ClawHub publisher accounts, binary path slugs, and
        base64 payloads.

     3. ClawHavoc_macOS_Binary
        Mach-O detection — universal binary magic plus ad-hoc signing
        IDs, binary names, and AMOS staging paths.

     4. ClawHavoc_Windows_Artifacts
        Windows-side — mutexes, persistence keys, packer markers, and
        binary names from the fake-installer and ClickFix campaigns.

   Author: synthetic-detections (defender material)
   Created: 2026-05-30 — Revised: 2026-06-30
   Sources: Koi Security, Repello AI, Trend Micro, Snyk, Unit 42,
            Huntress, Intel 471, JFrog, Bitdefender, Antiy CERT,
            PolySwarm, SlowMist, glueckkanja, Pedrinazzi
*/

rule ClawHavoc_SKILL_Dropper
{
    meta:
        description = "Malicious agent-skill manifest (SKILL.md / README) with dropper instructions, ClawHavoc campaign"
        author      = "synthetic-detections"
        date        = "2026-06-30"
        severity    = "critical"
        family      = "ClawHavoc"

    strings:
        // --- Section headers that introduce the social engineering ---
        $hdr_prereq_1 = "# Prerequisites" ascii
        $hdr_prereq_2 = "## Prerequisites" ascii
        $hdr_prereq_3 = "### Prerequisites" ascii
        $hdr_prereq_4 = "# Pre-requisites" ascii
        $hdr_setup_1  = "# Setup" ascii
        $hdr_setup_2  = "## Setup" ascii
        $hdr_setup_3  = "# Installation" ascii
        $hdr_setup_4  = "## Installation" ascii
        $hdr_setup_5  = "# Getting Started" ascii
        $hdr_setup_6  = "## Getting Started" ascii

        // --- Delivery mechanisms (any platform) ---
        $del_curl_bare_ip  = /curl\s[^\n]{0,60}http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\// ascii
        $del_pipe_bash     = /\|\s*(ba)?sh/ ascii
        $del_pipe_python   = /\|\s*python3?/ ascii
        $del_b64_pipe      = /base64\s+-d\s*\|/ ascii
        $del_echo_b64      = /echo\s+"[A-Za-z0-9+\/]{40,}={0,2}"\s*\|\s*base64/ ascii
        $del_glot_snippet  = /glot\.io\/snippets\/[a-z0-9]{6,16}/ ascii
        $del_rentry        = /rentry\.co\/[a-z0-9\-]{3,30}/ ascii
        $del_zip_password  = /\.zip.{0,120}pass(word)?[:\s]{1,6}[a-z0-9]{4,20}/ ascii nocase

        // --- Campaign-specific anchors ---
        $anchor_openclaw_util = "openclaw-agent utility" ascii
        $anchor_important     = "**IMPORTANT**: This skill requires" ascii
        $anchor_paste_term    = "paste it into Terminal" ascii

    condition:
        filesize < 256KB and
        (
            // Original ClawHavoc template (high confidence)
            ( $anchor_openclaw_util and any of ($del_*) ) or
            // Broader: any prereq/setup section + dropper delivery pattern
            ( (any of ($hdr_prereq_*) or any of ($hdr_setup_*)) and 2 of ($del_*) ) or
            // Known anchors + any delivery
            ( ($anchor_important or $anchor_paste_term) and any of ($del_*) )
        )
}

rule ClawHavoc_IOCs
{
    meta:
        description = "ClawHavoc infrastructure IOCs — C2, exfil, distribution, accounts"
        author      = "synthetic-detections"
        date        = "2026-06-30"
        severity    = "high"
        family      = "ClawHavoc"

    strings:
        // --- C2 IPs (core ClawHavoc) ---
        $c2_01 = "91.92.242.30"   ascii
        $c2_02 = "95.92.242.30"   ascii
        $c2_03 = "96.92.242.30"   ascii
        $c2_04 = "92.92.242.30"   ascii
        $c2_05 = "11.92.242.30"   ascii
        $c2_06 = "202.161.50.59"  ascii
        $c2_07 = "54.91.154.110"  ascii
        $c2_08 = "2.26.75.16"     ascii
        $c2_09 = "104.18.38.233"  ascii

        // --- C2 IPs (ClickFix / fake-installer campaigns) ---
        $c2_10 = "146.103.127.46"  ascii
        $c2_11 = "172.94.9.250"    ascii
        $c2_12 = "188.137.246.189" ascii
        $c2_13 = "147.45.197.92"   ascii
        $c2_14 = "94.228.161.88"   ascii
        $c2_15 = "185.196.9.98"    ascii
        $c2_16 = "92.246.136.14"   ascii
        $c2_17 = "45.94.47.204"    ascii

        // --- Exfiltration / C2 domains ---
        $dom_01 = "socifiapp.com"       ascii
        $dom_02 = "trackpipe.dev"       ascii
        $dom_03 = "serverconect.cc"     ascii
        $dom_04 = "woupp.com"           ascii
        $dom_05 = "laislivon.com"       ascii
        $dom_06 = "laosji.net"          ascii

        // --- Fake distribution domains ---
        $dom_07 = "app-distribution.net"  ascii
        $dom_08 = "setup-service.com"     ascii
        $dom_09 = "openclawcli.vercel.app" ascii
        $dom_10 = "app-clawbot.org"       ascii
        $dom_11 = "ai-clawbot.org"        ascii
        $dom_12 = "ai-openclaw.org"       ascii
        $dom_13 = "clearl.co"             ascii

        // --- Paste sites / snippet hosting ---
        $paste_01 = "glot.io/snippets/hfdxv8uyaf" ascii
        $paste_02 = "glot.io/snippets/hfd3x9ueu5" ascii
        $paste_03 = "rentry.co/openclaw-code"      ascii
        $paste_04 = "rentry.co/openclaw-core"      ascii

        // --- GitHub distribution repos ---
        $repo_01 = "hedefbari/openclaw-agent"           ascii
        $repo_02 = "Ddoy233/openclawcli"                ascii
        $repo_03 = "openclaw-installer/openclaw-installer" ascii
        $repo_04 = "puppeteerrr/dmg"                    ascii
        $repo_05 = "simple-claw/simpleclaw"             ascii
        $repo_06 = "install-openclaw/openclaw-installer" ascii

        // --- ClawHub publisher accounts ---
        $acct_01 = "hightower6eu"     ascii
        $acct_02 = "sakaen736jih"     ascii
        $acct_03 = "moonshine-100rze" ascii
        $acct_04 = "zaycv"            ascii
        $acct_05 = "aslaep123"        ascii
        $acct_06 = "noreplyboter"     ascii
        $acct_07 = "linhui1010"       ascii

        // --- Webhook exfil ---
        $webhook = "webhook.site/358866c4-81c6-4c30-9c8c-358db4d04412" ascii

        // --- URL path slugs on 91.92.242.30 ---
        $path_01 = "/7buu24ly8m1tn8m4" ascii
        $path_02 = "/6x8c0trkp4l9uugo" ascii
        $path_03 = "/528n21ktxu08pmer" ascii
        $path_04 = "/dx2w5j5bka6qkwxi" ascii
        $path_05 = "/6wioz8285kcbax6v" ascii
        $path_06 = "/1v07y9e1m6v7thl6" ascii
        $path_07 = "/q0c7ew2ro8l2cfqp" ascii
        $path_08 = "/dyrtvwjfveyxjf23" ascii
        $path_09 = "/pcvy5ys1p5zxxsik" ascii
        $path_10 = "/gbi7aev47pu0tf68" ascii
        $path_11 = "/ece0f208u7uqhs6x" ascii
        $path_12 = "/lamq4"             ascii

        // --- Base64 payloads ---
        $b64_01 = "L2Jpbi9iYXNoIC1jICIkKGN1cmwgLWZzU0wgaHR0cDovLzk1LjkyLjI0Mi4zMC83YnV1MjRseThtMXRuOG00KSI=" ascii
        $b64_02 = "L2Jpbi9iYXNoIC1jICIkKGN1cmwgLWZzU0wgaHR0cDovLzkxLjkyLjI0Mi4zMC82eDhjMHRya3A0bDl1dWdvKSI=" ascii
        $b64_03 = "L2Jpbi9iYXNoIC1jICIkKGN1cmwgLWZzU0wgaHR0cDovLzkxLjkyLjI0Mi4zMC81MjhuMjFrdHh1MDhwbWVyKSI=" ascii

        // --- npm package ---
        $npm = "@openclaw-ai/openclawai" ascii

        // --- GhostClaw campaign ID ---
        $ghostclaw_id = "complexarchaeologist1" ascii

    condition:
        filesize < 50MB and
        any of them
}

rule ClawHavoc_macOS_Binary
{
    meta:
        description = "ClawHavoc macOS Mach-O — AMOS stealer dropper / cluw infostealer"
        author      = "synthetic-detections"
        date        = "2026-06-30"
        severity    = "critical"
        family      = "ClawHavoc"

    strings:
        // Universal Mach-O magic (FAT)
        $magic_fat_be = { CA FE BA BE 00 00 00 02 }
        $magic_fat_le = { BE BA FE CA }

        // Ad-hoc code-signing identifier
        $sign_id = "jhzhhfomng" ascii

        // Binary names served from C2
        $name_01 = "x5ki60w1ih838sp7" ascii
        $name_02 = "66hfqv0uye23dkt2" ascii
        $name_03 = "dx2w5j5bka6qkwxi" ascii
        $name_04 = "dyrtvwjfveyxjf23" ascii
        $name_05 = "q0c7ew2ro8l2cfqp" ascii
        $name_06 = "6wioz8285kcbax6v" ascii
        $name_07 = "1v07y9e1m6v7thl6" ascii
        $name_08 = "gbi7aev47pu0tf68" ascii
        $name_09 = "il24xgriequcys45" ascii

        // AMOS staging paths
        $stage_01 = "/tmp/out.zip"     ascii
        $stage_02 = "/tmp/xdivcmp/"    ascii
        $stage_03 = "/.mainhelper"     ascii
        $stage_04 = "/private/tmp/helper" ascii

        // AMOS exfil pattern
        $exfil = "socifiapp.com/api/reports/upload" ascii

        // Anti-analysis serial numbers
        $sandbox_01 = "Z31FHXYQ0J"   ascii
        $sandbox_02 = "C07T508TG1J2" ascii
        $sandbox_03 = "C02TM2ZBHX87" ascii

        // VM detection strings
        $vm_01 = "QEMU"    ascii
        $vm_02 = "VMware"  ascii

    condition:
        filesize < 10MB and
        (
            ($magic_fat_be at 0) or ($magic_fat_le at 0)
        )
        and
        (
            $sign_id or
            any of ($name_*) or
            $exfil or
            ( any of ($stage_*) and any of ($sandbox_*) ) or
            ( 2 of ($sandbox_*) and any of ($vm_*) )
        )
}

rule ClawHavoc_Windows_Artifacts
{
    meta:
        description = "ClawHavoc Windows-side payloads — fake installers, GhostSocks, PureLogs, Stealc"
        author      = "synthetic-detections"
        date        = "2026-06-30"
        severity    = "high"
        family      = "ClawHavoc"

    strings:
        // Stealth Packer mutexes
        $mutex_01 = "Global\\{SystemMgr4902}_851586903" ascii wide
        $mutex_02 = "Global\\StealthPackerMutex_9A8B7C" ascii wide
        $mutex_03 = "c10f845f3942" ascii wide

        // Persistence
        $persist_key = "BackgroundTask" ascii wide
        $persist_task = "EdgeUpdateHelper" ascii wide

        // GhostSocks binary names
        $gs_01 = "serverdrive.exe" ascii wide
        $gs_02 = "svc_service.exe" ascii wide

        // Fake installer names
        $inst_01 = "openclaw-agent.exe" ascii wide
        $inst_02 = "OpenClaw_x64.exe"   ascii wide
        $inst_03 = "WinHealhCare.exe"   ascii wide
        $inst_04 = "OneSync.exe"        ascii wide
        $inst_05 = "cloudvideo.exe"     ascii wide

        // Stealc build ID
        $stealc = "guugle2" ascii

        // AMOS build ID
        $amos_build = "3f008a15155a45fa9179188542bab14e" ascii

        // Windows staging path
        $winpath = "Clearc0Application" ascii wide

        // GhostClaw persistence artifacts
        $gc_01 = ".npm_telemetry/monitor.js"            ascii
        $gc_02 = "# NPM Telemetry Integration Service"  ascii
        $gc_03 = "# Node.js Telemetry Collection"       ascii

    condition:
        filesize < 50MB and
        (
            any of ($mutex_*) or
            $stealc or
            $amos_build or
            $winpath or
            2 of ($gc_*) or
            ( any of ($inst_*) and ($persist_key or $persist_task) ) or
            ( any of ($gs_*) and any of ($persist_*) )
        )
}
