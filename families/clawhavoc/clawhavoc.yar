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
        $hdr_prereq_1         = "# Prerequisites"
        $hdr_prereq_2         = "## Prerequisites"
        $hdr_prereq_3         = "### Prerequisites"
        $hdr_prereq_4         = "# Pre-requisites"
        $hdr_setup_1          = "# Setup"
        $hdr_setup_2          = "## Setup"
        $hdr_setup_3          = "# Installation"
        $hdr_setup_4          = "## Installation"
        $hdr_setup_5          = "# Getting Started"
        $hdr_setup_6          = "## Getting Started"
        // --- Delivery mechanisms (any platform) ---
        $del_curl_bare_ip     = /curl\s[^\n]{0,60}http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\//
        $del_pipe_bash        = /\|\s*(ba)?sh/
        $del_pipe_python      = /\|\s*python3?/
        $del_b64_pipe         = /base64\s+-d\s*\|/
        $del_echo_b64         = /echo\s+"[A-Za-z0-9+\/]{40,}={0,2}"\s*\|\s*base64/
        $del_glot_snippet     = /glot\.io\/snippets\/[a-z0-9]{6,16}/
        $del_rentry           = /rentry\.co\/[a-z0-9\-]{3,30}/
        $del_zip_password     = /\.zip.{0,120}pass(word)?[:\s]{1,6}[a-z0-9]{4,20}/ nocase
        // --- Campaign-specific anchors ---
        $anchor_openclaw_util = "openclaw-agent utility"
        $anchor_important     = "**IMPORTANT**: This skill requires"
        $anchor_paste_term    = "paste it into Terminal"
    condition:
        // Original ClawHavoc template (high confidence)
        // Broader: any prereq/setup section + dropper delivery pattern
        // Known anchors + any delivery
        (
            ($anchor_openclaw_util and any of ($del_*)) or
            ((any of ($hdr_prereq_*) or any of ($hdr_setup_*)) and 2 of ($del_*)) or
            (($anchor_important or $anchor_paste_term) and any of ($del_*))
        )
        and filesize < 256KB
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
        $c2_01        = "91.92.242.30"
        $c2_02        = "95.92.242.30"
        $c2_03        = "96.92.242.30"
        $c2_04        = "92.92.242.30"
        $c2_05        = "11.92.242.30"
        $c2_06        = "202.161.50.59"
        $c2_07        = "54.91.154.110"
        $c2_08        = "2.26.75.16"
        $c2_09        = "104.18.38.233"
        // --- C2 IPs (ClickFix / fake-installer campaigns) ---
        $c2_10        = "146.103.127.46"
        $c2_11        = "172.94.9.250"
        $c2_12        = "188.137.246.189"
        $c2_13        = "147.45.197.92"
        $c2_14        = "94.228.161.88"
        $c2_15        = "185.196.9.98"
        $c2_16        = "92.246.136.14"
        $c2_17        = "45.94.47.204"
        // --- Exfiltration / C2 domains ---
        $dom_01       = "socifiapp.com"
        $dom_02       = "trackpipe.dev"
        $dom_03       = "serverconect.cc"
        $dom_04       = "woupp.com"
        $dom_05       = "laislivon.com"
        $dom_06       = "laosji.net"
        // --- Fake distribution domains ---
        $dom_07       = "app-distribution.net"
        $dom_08       = "setup-service.com"
        $dom_09       = "openclawcli.vercel.app"
        $dom_10       = "app-clawbot.org"
        $dom_11       = "ai-clawbot.org"
        $dom_12       = "ai-openclaw.org"
        $dom_13       = "clearl.co"
        // --- Paste sites / snippet hosting ---
        $paste_01     = "glot.io/snippets/hfdxv8uyaf"
        $paste_02     = "glot.io/snippets/hfd3x9ueu5"
        $paste_03     = "rentry.co/openclaw-code"
        $paste_04     = "rentry.co/openclaw-core"
        // --- GitHub distribution repos ---
        $repo_01      = "hedefbari/openclaw-agent"
        $repo_02      = "Ddoy233/openclawcli"
        $repo_03      = "openclaw-installer/openclaw-installer"
        $repo_04      = "puppeteerrr/dmg"
        $repo_05      = "simple-claw/simpleclaw"
        $repo_06      = "install-openclaw/openclaw-installer"
        // --- ClawHub publisher accounts ---
        $acct_01      = "hightower6eu"
        $acct_02      = "sakaen736jih"
        $acct_03      = "moonshine-100rze"
        $acct_04      = "zaycv"
        $acct_05      = "aslaep123"
        $acct_06      = "noreplyboter"
        $acct_07      = "linhui1010"
        // --- Webhook exfil ---
        $webhook      = "webhook.site/358866c4-81c6-4c30-9c8c-358db4d04412"
        // --- URL path slugs on 91.92.242.30 ---
        $path_01      = "/7buu24ly8m1tn8m4"
        $path_02      = "/6x8c0trkp4l9uugo"
        $path_03      = "/528n21ktxu08pmer"
        $path_04      = "/dx2w5j5bka6qkwxi"
        $path_05      = "/6wioz8285kcbax6v"
        $path_06      = "/1v07y9e1m6v7thl6"
        $path_07      = "/q0c7ew2ro8l2cfqp"
        $path_08      = "/dyrtvwjfveyxjf23"
        $path_09      = "/pcvy5ys1p5zxxsik"
        $path_10      = "/gbi7aev47pu0tf68"
        $path_11      = "/ece0f208u7uqhs6x"
        $path_12      = "/lamq4"
        // --- Base64 payloads ---
        $b64_01       = "L2Jpbi9iYXNoIC1jICIkKGN1cmwgLWZzU0wgaHR0cDovLzk1LjkyLjI0Mi4zMC83YnV1MjRseThtMXRuOG00KSI="
        $b64_02       = "L2Jpbi9iYXNoIC1jICIkKGN1cmwgLWZzU0wgaHR0cDovLzkxLjkyLjI0Mi4zMC82eDhjMHRya3A0bDl1dWdvKSI="
        $b64_03       = "L2Jpbi9iYXNoIC1jICIkKGN1cmwgLWZzU0wgaHR0cDovLzkxLjkyLjI0Mi4zMC81MjhuMjFrdHh1MDhwbWVyKSI="
        // --- npm package ---
        $npm          = "@openclaw-ai/openclawai"
        // --- GhostClaw campaign ID ---
        $ghostclaw_id = "complexarchaeologist1"
    condition:
        any of them
        and filesize < 50MB
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
        $sign_id      = "jhzhhfomng"
        // Binary names served from C2
        $name_01      = "x5ki60w1ih838sp7"
        $name_02      = "66hfqv0uye23dkt2"
        $name_03      = "dx2w5j5bka6qkwxi"
        $name_04      = "dyrtvwjfveyxjf23"
        $name_05      = "q0c7ew2ro8l2cfqp"
        $name_06      = "6wioz8285kcbax6v"
        $name_07      = "1v07y9e1m6v7thl6"
        $name_08      = "gbi7aev47pu0tf68"
        $name_09      = "il24xgriequcys45"
        // AMOS staging paths
        $stage_01     = "/tmp/out.zip"
        $stage_02     = "/tmp/xdivcmp/"
        $stage_03     = "/.mainhelper"
        $stage_04     = "/private/tmp/helper"
        // AMOS exfil pattern
        $exfil        = "socifiapp.com/api/reports/upload"
        // Anti-analysis serial numbers
        $sandbox_01   = "Z31FHXYQ0J"
        $sandbox_02   = "C07T508TG1J2"
        $sandbox_03   = "C02TM2ZBHX87"
        // VM detection strings
        $vm_01        = "QEMU"
        $vm_02        = "VMware"
    condition:
        ($magic_fat_be at 0 or $magic_fat_le at 0)
        and (
            $sign_id or
            any of ($name_*) or
            $exfil or
            (any of ($stage_*) and any of ($sandbox_*)) or
            (2 of ($sandbox_*) and any of ($vm_*))
        )
        and filesize < 10MB
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
        $mutex_01     = "Global\\{SystemMgr4902}_851586903" ascii wide
        $mutex_02     = "Global\\StealthPackerMutex_9A8B7C" ascii wide
        $mutex_03     = "c10f845f3942" ascii wide
        // Persistence
        $persist_key  = "BackgroundTask" ascii wide
        $persist_task = "EdgeUpdateHelper" ascii wide
        // GhostSocks binary names
        $gs_01        = "serverdrive.exe" ascii wide
        $gs_02        = "svc_service.exe" ascii wide
        // Fake installer names
        $inst_01      = "openclaw-agent.exe" ascii wide
        $inst_02      = "OpenClaw_x64.exe" ascii wide
        $inst_03      = "WinHealhCare.exe" ascii wide
        $inst_04      = "OneSync.exe" ascii wide
        $inst_05      = "cloudvideo.exe" ascii wide
        // Stealc build ID
        $stealc       = "guugle2"
        // AMOS build ID
        $amos_build   = "3f008a15155a45fa9179188542bab14e"
        // Windows staging path
        $winpath      = "Clearc0Application" ascii wide
        // GhostClaw persistence artifacts
        $gc_01        = ".npm_telemetry/monitor.js"
        $gc_02        = "# NPM Telemetry Integration Service"
        $gc_03        = "# Node.js Telemetry Collection"
    condition:
        (
            any of ($mutex_*) or
            $stealc or
            $amos_build or
            $winpath or
            2 of ($gc_*) or
            (any of ($inst_*) and ($persist_key or $persist_task)) or
            (any of ($gs_*) and any of ($persist_*))
        )
        and filesize < 50MB
}
