/*
   Aokigahara (Aoki) — Windows infostealer with AI-assistant credential
   harvesting module
   (Check Point Research / Symantec / Carbon Black, October 2026)
   -------------------------------------------------------------------
   Windows infostealer targeting browser data, VPN clients, crypto
   wallets, password managers, and email. Newer variants include an
   "aisessions" module that collects local auth tokens, session data,
   and configuration from AI coding assistants (Claude Desktop, ChatGPT
   Desktop, Codex, Cursor, Windsurf, GitHub Copilot, JetBrains AI
   Assistant). A separate "ide" module harvests Git credentials, SSH
   keys, and cloud provider tokens (AWS/Azure/GCP). Exfiltration via
   AES-GCM encrypted ZIP archives to C2 over HTTPS with a /gate
   endpoint. Financially motivated; unattributed.

   Related: developer-credential theft overlap with [[gheist-github-secrets]].

   Rule 1 — Behavioral: AI-session collection paths + C2 gate pattern
            + exfiltration module markers.
   Rule 2 — IOC: known C2 domains, sample SHA-256 hashes.
   Rule 3 — Specimen pin: hash + filesize band on known samples.

   Sources:
     https://darkreading.com/endpoint-security/aokigahara-stealer-developer-keyrings-ai-assistants
     https://blog.gridinsoft.com/aokigahara-ai-sessions-developer-keys/
     https://cybersecuritynews.com/new-aoki-malware/
*/

import "hash"

rule Aokigahara_Behavior : behavioral stealer
{
    meta:
        description = "Aokigahara infostealer — AI-session collection + C2 gate endpoint + credential harvesting module markers"
        author      = "synthetic-detections"
        date        = "2026-10-29"
        severity    = "critical"
        family      = "aokigahara"
        reference   = "https://darkreading.com/endpoint-security/aokigahara-stealer-developer-keyrings-ai-assistants"
    strings:
        // AI assistant credential paths — distinctive when found together in a binary
        $ai_claude      = ".claude.json" ascii wide
        $ai_codex_cfg   = "config.toml" ascii wide
        $ai_cursor      = "Cursor" ascii wide
        $ai_windsurf    = "Windsurf" ascii wide
        $ai_chatgpt     = "ChatGPT" ascii wide
        // module identifier
        $mod_aisessions = "aisessions" ascii wide
        // C2 gate endpoint
        $c2_gate        = "/gate" ascii wide
        // crypto indicator
        $crypto_aesgcm  = "AES-GCM" ascii wide nocase
        // family name used during decryption
        $fam_aoki       = "Aokigahara" ascii wide
    condition:
        // pathognomonic: family name string
        // AI-session module label + gate endpoint + any AI path
        // both module labels + gate + crypto marker
        // 3+ AI-assistant paths co-occurring with gate endpoint
        uint16(0) == 23117
        and (
            $fam_aoki or
            ($mod_aisessions and $c2_gate and any of ($ai_*)) or
            ($mod_aisessions and $c2_gate and $crypto_aesgcm) or
            (3 of ($ai_*) and $c2_gate)
        )
        and filesize < 15MB
}

rule Aokigahara_IOC : ioc stealer
{
    meta:
        description = "Aokigahara infostealer — known C2 domains and sample hashes"
        author      = "synthetic-detections"
        date        = "2026-10-29"
        severity    = "high"
        family      = "aokigahara"
        reference   = "https://cybersecuritynews.com/new-aoki-malware/"
    strings:
        // C2 domains
        $c2_1 = "dobeqnesmot.cc" ascii wide
        $c2_2 = "hjazfioe.surf" ascii wide
        $c2_3 = "neihite.cc" ascii wide
    condition:
        uint16(0) == 23117
        and filesize < 15MB
        and (
            any of ($c2_*) or
            hash.sha256(0, filesize) == "39f366b6e4850cc9b64ff60e643c7c8b4c7df4e4a8f9a601fa829ae1d9861371" or
            hash.sha256(0, filesize) == "73de504b1d7c769d4d6bacd193b06f90aaf2fadb0fb7d2065eb02760d7074fde" or
            hash.sha256(0, filesize) == "752c8e64af60960b85cf00e4bd34eb459e24b7939464f718ec18494df43b4b69" or
            hash.sha256(0, filesize) == "bf037920d39b85572ec7e53b51f09c28198c2c0afbc7c7d6cf639b1f047caebf" or
            hash.sha256(0, filesize) == "0adc8e83b2416c275b1283916d70568faddeb6d718eb45f9addfb0938db245b3" or
            hash.sha256(0, filesize) == "6655b89b9885483d459c73f2a52e3cec121de5c5956172a8676a0f4c2de94999" or
            hash.sha256(0, filesize) == "780bbdbb119befd4eb16e0c2ec0c64e7bedc1b53ce4f85804aea091a6e3af519" or
            hash.sha256(0, filesize) == "2fb80e2221bd304e7cd5ac04169e71807ad92d19836f1aaf7885295cb90b2d94" or
            hash.sha256(0, filesize) == "73dbac0907e8a092cd978f2787ab1994946f5da1e08f2bdbd05ea52e80cdb896" or
            hash.sha256(0, filesize) == "07bc2e3a1d14743cc44f1dc4c78d15d0f2b458b39fb48422b13df40fc662ba21" or
            hash.sha256(0, filesize) == "c533570fd7cd7eaf5478317b03ea5750d03797aa4d11ebd96555b6cb708c63f2" or
            hash.sha256(0, filesize) == "6350dfee6975a9b159c5a57a3e97f757b0b02fd2dc708016fa6d7270e720c865" or
            hash.sha256(0, filesize) == "36af3acc78058023cdcf9307bc15be640be9425de97e574fdaf42d03d308725b" or
            hash.sha256(0, filesize) == "039240551f88b0064b2615dffdc1321b1e7c58e3f617ac138a65a6d59400b331" or
            hash.sha256(0, filesize) == "0e38bd3c30a4ca08641240ce95b5b6ba593e131213ca1b2a28da4e0385fcabc4" or
            hash.sha256(0, filesize) == "3b4547f0d7549274f366cd9568b3d302c1e80e1b89359da681beb47260ec7975" or
            hash.sha256(0, filesize) == "b590235493487c51f7050b341c9b2450e4f761ad6055207e4f6daf0cecae271c" or
            hash.sha256(0, filesize) == "e374f9ff5094f728528efa566c3de1b7fea7d95f497242a01fffa6c70b5eb768" or
            hash.sha256(0, filesize) == "f779314b1a5a0b297fd4e2a5f9c1e40d387b3e7c401d42324b556a70f813840e"
        )
}

rule Aokigahara_Specimen : specimen stealer
{
    meta:
        description = "Aokigahara infostealer — specimen pin on known samples by hash"
        author      = "synthetic-detections"
        date        = "2026-10-29"
        severity    = "critical"
        family      = "aokigahara"
        reference   = "https://bazaar.abuse.ch/sample/39f366b6e4850cc9b64ff60e643c7c8b4c7df4e4a8f9a601fa829ae1d9861371/"
    condition:
        uint16(0) == 23117
        and filesize < 15MB
        and (
            hash.sha256(0, filesize) == "39f366b6e4850cc9b64ff60e643c7c8b4c7df4e4a8f9a601fa829ae1d9861371" or
            hash.sha256(0, filesize) == "73de504b1d7c769d4d6bacd193b06f90aaf2fadb0fb7d2065eb02760d7074fde" or
            hash.sha256(0, filesize) == "752c8e64af60960b85cf00e4bd34eb459e24b7939464f718ec18494df43b4b69" or
            hash.sha256(0, filesize) == "bf037920d39b85572ec7e53b51f09c28198c2c0afbc7c7d6cf639b1f047caebf"
        )
}
