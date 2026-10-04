/*
   Kimsuky HelloDoor — Rust PebbleDash variant detection
   =====================================================
   Targets the HelloDoor RAT used by Kimsuky / APT43 against South Korean
   government and chaebol targets, disclosed by Securelist (Kaspersky)
   on 2026-05-29. HelloDoor is notable as one of the cleanest publicly
   documented cases of an AI-authored implant shipping into a real-world
   DPRK espionage campaign.

   Three rules:
     1. Kimsuky_HelloDoor_LLM_Tells
        Behavioural — emoji-laden debug strings + phonetic typos that
        survive into the compiled artefact. The co-occurrence is the
        AI-authorship fingerprint; no human-reviewed Rust DLL targeting
        a government PKI store ships ✅/❌/🔍 logging together with
        "decrytion failed". Highest fidelity.

     2. Kimsuky_HelloDoor_IOCs
        IOC-based — C2 host, RC4 key, PebbleDash 10-char query-string
        fingerprint, persistence registry pattern, and shell-exec
        template. Broader; will fire on legitimate threat-intel notes
        containing the same strings.

     3. Kimsuky_HelloDoor_PE_DLL
        For the compiled Rust DLL — PE magic at offset 0 paired with
        a HelloDoor-unique discriminator. The Rust language choice and
        the regsvr32-loaded DLL packaging produce a recognisable
        filesize band.

   Author: synthetic-detections, 2026-05-30
   Source: Securelist (Kaspersky), 2026-05-29
   Sample hashes: Securelist published one MD5 only
                  (c42ae004badddd3017adadbdd1421e00).
                  SHA256 not yet disclosed publicly.
   References:
     https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/
*/

import "pe"

rule Kimsuky_HelloDoor_LLM_Tells : malware
{
    meta:
        description = "HelloDoor AI-authorship tells — emoji telemetry + phonetic typos"
        author      = "synthetic-detections"
        date        = "2026-05-30"
        severity    = "critical"
        family      = "HelloDoor"
        hash_md5    = "c42ae004badddd3017adadbdd1421e00"
        reference1  = "https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/"
    strings:
        // Emoji-laden production debug strings — diagnostic for LLM authorship.
        // Kept ASCII-only because Rust strings are UTF-8 in .rdata; YARA's `wide`
        // would mangle multi-byte UTF-8 by widening each byte to xx 00 rather than
        // re-encoding the codepoints.
        $emoji_listen   = "\xE2\x9C\x85 Port is now listening (no accepting)"
        $emoji_inuse    = "\xE2\x9D\x8C Port is already in use"
        $emoji_regsvr   = "\xF0\x9F\x94\x8D regsvr32.exe detected as parent. Attempting to terminate..."
        // Phonetic typos that a linter or human reviewer would have caught.
        // Pure ASCII, so `wide` works correctly as a defence against UTF-16 variants.
        // intended: "decryption failed"
        $typo_decryt    = "decrytion failed" ascii wide
        // intended: "autorun failed"
        $typo_autorum   = "autorum failed" ascii wide
        $typo_resultsnd = "result send fail" ascii wide
    condition:
        any of ($emoji_*) and any of ($typo_*) and filesize < 10MB
}

rule Kimsuky_HelloDoor_IOCs : c2 ioc
{
    meta:
        description = "HelloDoor IOCs — C2 host, RC4 key, PebbleDash query fingerprint, persistence"
        author      = "synthetic-detections"
        date        = "2026-05-30"
        severity    = "high"
        family      = "HelloDoor"
    strings:
        // C2 (Cloudflare Tunnel host) — current observed
        $c2_host        = "female-disorder-beta-metropolitan.trycloudflare.com" nocase
        // RC4 key used to decrypt Base64-then-RC4 server responses
        $rc4_key        = "fwr3errsettwererfs"
        // PebbleDash family fingerprint — ten-char-repeating parameter names
        $pebbledash_qs  = /aaaaaaaaaa=[0-9]&bbbbbbbbbb=/
        // Persistence registry value: regsvr32-loaded DLL named "tdll"
        $persistence    = /"tdll"="regsvr32\.exe \/s/
        // Shell-exec template used by the backdoor
        $shell_template = "chcp 65001 > nul & cmd /U /C"
    condition:
        any of them and filesize < 50MB
}

rule Kimsuky_HelloDoor_PE_DLL : malware
{
    meta:
        description = "HelloDoor compiled Rust DLL — PE + HelloDoor-unique discriminator"
        author      = "synthetic-detections"
        date        = "2026-05-30"
        severity    = "critical"
        family      = "HelloDoor"
        notes       = "Rust DLL invoked via regsvr32.exe /s"
    strings:
        // HelloDoor-unique anchors (any one is sufficient when paired with PE+DLL)
        $rc4_key      = "fwr3errsettwererfs"
        $emoji_listen = "\xE2\x9C\x85 Port is now listening (no accepting)"
        $emoji_inuse  = "\xE2\x9D\x8C Port is already in use"
        $typo_decryt  = "decrytion failed" ascii wide
        $typo_autorum = "autorum failed" ascii wide
    condition:
        // Universally-portable PE+DLL gate (works in both classic YARA and
        // YARA-X). pe.is_pe / pe.is_dll are inconsistent between engines.
        uint16(0) == 0x5a4d
        and uint32(uint32(60)) == 0x4550
        and pe.characteristics & pe.DLL != 0
        and any of ($rc4_key, $emoji_*, $typo_*)
        and filesize > 20KB
        and filesize < 10MB
}
