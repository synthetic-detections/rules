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

rule Kimsuky_HelloDoor_LLM_Tells
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
        $emoji_listen   = "✅ Port is now listening (no accepting)" ascii
        $emoji_inuse    = "❌ Port is already in use" ascii
        $emoji_regsvr   = "🔍 regsvr32.exe detected as parent. Attempting to terminate..." ascii

        // Phonetic typos that a linter or human reviewer would have caught.
        // Pure ASCII, so `wide` works correctly as a defence against UTF-16 variants.
        $typo_decryt    = "decrytion failed" ascii wide        // intended: "decryption failed"
        $typo_autorum   = "autorum failed" ascii wide          // intended: "autorun failed"
        $typo_resultsnd = "result send fail" ascii wide

    condition:
        filesize < 10MB and
        any of ($emoji_*) and
        any of ($typo_*)
}

rule Kimsuky_HelloDoor_IOCs
{
    meta:
        description = "HelloDoor IOCs — C2 host, RC4 key, PebbleDash query fingerprint, persistence"
        author      = "synthetic-detections"
        date        = "2026-05-30"
        severity    = "high"
        family      = "HelloDoor"

    strings:
        // C2 (Cloudflare Tunnel host) — current observed
        $c2_host        = "female-disorder-beta-metropolitan.trycloudflare.com" ascii nocase

        // RC4 key used to decrypt Base64-then-RC4 server responses
        $rc4_key        = "fwr3errsettwererfs" ascii

        // PebbleDash family fingerprint — ten-char-repeating parameter names
        $pebbledash_qs  = /aaaaaaaaaa=[0-9]&bbbbbbbbbb=/ ascii

        // Persistence registry value: regsvr32-loaded DLL named "tdll"
        $persistence    = /"tdll"="regsvr32\.exe \/s/ ascii

        // Shell-exec template used by the backdoor
        $shell_template = "chcp 65001 > nul & cmd /U /C" ascii

    condition:
        filesize < 50MB and
        any of them
}

rule Kimsuky_HelloDoor_PE_DLL
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
        $rc4_key      = "fwr3errsettwererfs" ascii
        $emoji_listen = "✅ Port is now listening (no accepting)" ascii
        $emoji_inuse  = "❌ Port is already in use" ascii
        $typo_decryt  = "decrytion failed" ascii wide
        $typo_autorum = "autorum failed" ascii wide

    condition:
        // Universally-portable PE+DLL gate (works in both classic YARA and
        // YARA-X). pe.is_pe / pe.is_dll are inconsistent between engines.
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and (pe.characteristics & pe.DLL) != 0
        and filesize > 20KB and filesize < 10MB
        and any of ($rc4_key, $emoji_*, $typo_*)
}
