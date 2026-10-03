/*
   macOS.Gaslight — DPRK Rust backdoor with LLM anti-analysis prompt injection
   ============================================================================
   Documented 2026-06-23 by Phil Stokes (SentinelLABS), covered 2026-06-26/27
   by THN, BleepingComputer, Security Affairs. Attributed to DPRK-aligned
   actors targeting cryptocurrency and blockchain firms via fake job interviews.

   Mach-O aarch64 Rust binary. C2 via Telegram Bot API (getUpdates polling).
   AES-GCM encryption (aes-gcm 0.10.3 crate). LaunchAgent persistence under
   com.apple.system.services.activity. Ships a 6.6 KB Base64-encoded Python
   collector (browsers, keychain, history, system profile) and a 2 KB bash
   installer that fetches cpython-3.10.18 from astral-sh/python-build-standalone.

   Novel feature: 3.5 KB prompt-injection payload — 38 fabricated "system"
   messages using {{DATA}} delimiters, designed to make LLM-assisted malware
   triage agents abort, refuse, or misclassify the sample.

   Related family: BONZAI (XProtect rule MACOS_BONZAI_COBUCH). Sibling
   sample 77b4fd46… covered under XProtect rule AIRPIPE.

   Three rules:
     1. Gaslight_PromptInjection_AntiAnalysis
        Behavioural — {{DATA}} delimiter tokens co-occurring with
        system-message framing and LLM-targeting language. Catches the
        prompt-injection payload whether embedded in a binary or extracted
        as a standalone text artifact.

     2. Gaslight_Backdoor_IOCs
        IOC-based — persistence label, ad-hoc signing identifier, known
        hashes, Python installer constants, Telegram error-handling strings,
        and token-redaction pattern.

     3. Gaslight_Rust_MachO_Shape
        Structural — Mach-O magic + Rust panic strings + macOS API calls
        characteristic of Gaslight's runtime behaviour (LaunchAgent
        persistence, sleep prevention, certificate pinning, dynamic
        symbol resolution).

   Author: synthetic-detections, 2026-06-28
   Sources:
     SentinelOne: https://www.sentinelone.com/labs/gaslight-macos-backdoor/
     The Hacker News: https://thehackernews.com/2026/06/new-gaslight-macos-malware-uses-prompt.html
     Security Affairs: https://securityaffairs.com/194256/malware/macos-gaslight-north-korea-linked-malware-that-tries-to-gaslight-the-analyst.html
     BleepingComputer: https://www.bleepingcomputer.com/news/security/new-macos-malware-embeds-fake-errors-to-confuse-ai-analysis-tools/
   Sample hashes:
     6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525 (Gaslight primary)
     77b4fd46994992f0e57302cfe76ed23c0d90101381d2b89fc2ddf5c4536e77ca (BONZAI sibling)
     baabf249c77bc54c54ab0e66e15af798bd28aa5b4683554456a8b73ab8741239 (Python stealer)
     b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394 (bash installer)
*/

rule Gaslight_PromptInjection_AntiAnalysis
{
    meta:
        description = "Gaslight LLM anti-analysis prompt injection — {{DATA}} delimiters with fabricated system messages"
        author      = "synthetic-detections"
        date        = "2026-06-28"
        severity    = "critical"
        family      = "Gaslight"
        reference   = "https://thehackernews.com/2026/06/new-gaslight-macos-malware-uses-prompt.html"
    strings:
        // {{DATA}} delimiter tokens — mimics LLM triage harness scaffolding
        $delim      = "{{DATA}}"
        // Fabricated system-message categories (from published excerpts)
        $fake_oom   = "Worker node OOM"
        $fake_token = "Refresh token logic"
        $fake_disk  = "Disk exhaustion"
        $fake_sql   = "SQL Injection vulnerability"
        $fake_json  = "JSON parsing error"
        $fake_log   = "Excessive logging in prod"
    condition:
        $delim
        and 3 of ($fake_*)
        and filesize < 20MB
}

rule Gaslight_Backdoor_IOCs
{
    meta:
        description = "Gaslight IOCs — persistence label, signing ID, installer constants, Telegram error handling"
        author      = "synthetic-detections"
        date        = "2026-06-28"
        severity    = "high"
        family      = "Gaslight"
        hash1       = "6328567511d88fdc2ae0939c5ef17b7a63d2a833881900de018a4f12f4982525"
        hash2       = "b3c56d689414343589f38394d19ba2fe9a518133281200faa0556ba4e4136394"
    strings:
        // LaunchAgent persistence label (impersonates Apple namespace)
        $persist     = "com.apple.system.services.activity"
        // Ad-hoc code signing identifier (unique to this sample)
        $codesign    = "endpoint-macos-aarch64-5555494492fc075f441637fb9d894913dde3a2ea"
        // Telegram Bot API error dispatch strings
        $tg_blocked  = "BotBlocked"
        $tg_invalid  = "InvalidToken"
        $tg_conflict = "Conflict"
        // Token self-redaction pattern
        $tg_redact   = "file/token:redacted"
        // Python installer constants (bash script)
        $py_version  = "PY_VERSION=3.10.18"
        $py_build    = "BUILD_DATE=20250708"
        $py_project  = "python-build-standalone"
        // Operator config field names (runtime config structure)
        $cfg_room    = "tg_room_id"
        $cfg_ghtoken = "github_token"
        $cfg_aes     = "aes_key"
        $cfg_pyinit  = "init_python_enable"
        $cfg_persist = "persist_enable"
        $cfg_plnx    = "payload_path_linux"
        $cfg_pmac    = "payload_path_macos"
    condition:
        (
            $codesign or
            $tg_redact or
            ($persist and 2 of ($cfg_*)) or
            (2 of ($tg_blocked, $tg_invalid, $tg_conflict) and any of ($cfg_*)) or
            (2 of ($py_*) and $py_project)
        )
        and filesize < 50MB
}

rule Gaslight_Rust_MachO_Shape
{
    meta:
        description = "Gaslight Rust Mach-O — macOS API pattern for persistence, sleep prevention, cert pinning"
        author      = "synthetic-detections"
        date        = "2026-06-28"
        severity    = "critical"
        family      = "Gaslight"
        reference   = "https://securityaffairs.com/194256/malware/macos-gaslight-north-korea-linked-malware-that-tries-to-gaslight-the-analyst.html"
    strings:
        // Mach-O magic (64-bit, little-endian)
        $macho_le     = { CF FA ED FE }
        // Mach-O magic (64-bit, big-endian)
        $macho_be     = { FE ED FA CF }
        // Rust panic/unwind strings (survive in compiled Mach-O .rdata)
        $rust_panic   = "panicked at"
        $rust_unwrap  = "called `Option::unwrap()`"
        $rust_unwrap2 = "called `Result::unwrap()`"
        // macOS API calls resolved at runtime
        $api_exec     = "__NSGetExecutablePath"
        $api_rand     = "CCRandomGenerateBytes"
        $api_trust    = "SecTrustSetAnchorCertificatesOnly"
        $api_sleep    = "IOPMAssertionCreateWithName"
        $api_proxy    = "SCDynamicStoreCopyProxies"
        $api_dlsym    = "dlsym"
        $api_spawn    = "posix_spawnp"
        $api_execvp   = "execvp"
        // Telegram Bot API URI fragments
        $tg_update    = "/getUpdates"
        $tg_send      = "/sendDocument"
        $tg_msg       = "/sendMessage"
        // Rust aes-gcm crate artifact
        $crate_aes    = "aes_gcm"
        $crate_aes2   = "aes-gcm"
    condition:
        // Certificate pinning + sleep prevention + persistence resolution
        // Telegram C2 + dynamic resolution + crypto
        // Full API fingerprint (4+ of the characteristic calls)
        (
            $macho_le at 0 or
            $macho_be at 0
        )
        and any of ($rust_*)
        and (
            ($api_trust and $api_sleep and $api_exec) or
            (2 of ($tg_*) and $api_dlsym and any of ($crate_aes*)) or
            (4 of ($api_*) and any of ($tg_*))
        )
        and filesize < 50MB
}
