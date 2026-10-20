/*
   Heartbreaker — metamorphic macOS ransomware (Rust/ARM64)
   --------------------------------------------------------
   Disclosed 2026-10-18 by Patrick Wardle (Objective-See, blog_0x8A).
   Discovered by Megan Carney via VirusTotal hunting; sample uploaded
   May 2025 with zero AV detections at time of publication.

   ARM64 Mach-O, Rust + eframe GUI, ad hoc signed. Encrypts files
   under ~/Downloads with AES-256-GCM using a hardcoded static key
   and appends .heartbreaker. Persists via LaunchAgent at
   ~/Library/LaunchAgents/com.network.startup.plist (Label mismatch:
   com.myapp.startup). Contains a metamorphic engine that embeds its
   own source via include_str!, randomises identifiers, injects junk
   functions, and recompiles with Cargo — will install Rust if absent.

   Rule 1 — Behavioural: metamorphic engine markers + encryption
            string pattern + persistence artefacts.
   Rule 2 — IOC: specific strings unique to this family with
            co-occurrence guards.
   Rule 3 — Specimen pin: SHA-256 of the known sample.

   [[sibling]] families/wallpaper-chrome-adfraud (adfraud, not related)

   Sources:
     https://objective-see.org/blog/blog_0x8A.html
*/

import "hash"

rule Heartbreaker_Behavioral : behavioral critical
{
    meta:
        description = "Heartbreaker macOS ransomware — metamorphic engine markers combined with encryption activity and LaunchAgent persistence"
        author      = "synthetic-detections"
        date        = "2026-10-20"
        severity    = "critical"
        family      = "heartbreaker-macos-ransomware"
        reference   = "https://objective-see.org/blog/blog_0x8A.html"
    strings:
        $meta_start  = "METAMORPHIC_MARKER_START"
        $meta_end    = "METAMORPHIC_MARKER_END"
        $morph_fn    = "mimicore::morph()"
        $startup_fn  = "mimicore::add_to_startup()"
        $encrypt_msg = "Encrypting file:"
        $extension   = ".heartbreaker"
        $plist_label = "com.myapp.startup"
        $plist_file  = "com.network.startup.plist"
        $cargo_build = "cargo build --release"
        $modified_rs = "modified_source.rs"
    condition:
        (
            ($meta_start and $meta_end) or
            ($morph_fn and $modified_rs) or
            ($cargo_build and $modified_rs)
        )
        and ($encrypt_msg or $extension)
        and ($plist_label or $plist_file or $startup_fn)
        and filesize < 20MB
}

rule Heartbreaker_IOC : high ioc
{
    meta:
        description = "Heartbreaker macOS ransomware — IOC sweep for unique strings with co-occurrence guards"
        author      = "synthetic-detections"
        date        = "2026-10-20"
        severity    = "high"
        family      = "heartbreaker-macos-ransomware"
        reference   = "https://objective-see.org/blog/blog_0x8A.html"
    strings:
        $key         = "g_w`:D2Xq6Yxez-5{#3mfd=VcB.Qhsub"
        $codesign_id = "heartbreaker-e2c97a640967e3f6"
        $ransom_warn = "HEARTBREAKER WARNING!"
        $ransom_body = "Your system has been encrypted!"
        $ransom_btc  = "Please send 0.003 BTC"
        $meta_start  = "METAMORPHIC_MARKER_START"
        $meta_end    = "METAMORPHIC_MARKER_END"
        $plist_file  = "com.network.startup.plist"
        $morph_fn    = "mimicore::morph()"
        $extension   = ".heartbreaker"
        $mimicore    = "saaaarwar/mimicore"
    condition:
        3 of them and filesize < 20MB
}

rule Heartbreaker_Specimen : critical specimen
{
    meta:
        description = "Heartbreaker macOS ransomware — specimen pin on the known Mach-O sample"
        author      = "synthetic-detections"
        date        = "2026-10-20"
        severity    = "critical"
        family      = "heartbreaker-macos-ransomware"
        reference   = "https://objective-see.org/blog/blog_0x8A.html"
    condition:
        filesize < 20MB
        and hash.sha256(0, filesize) == "6bdf42a575d2daee3de2530161cb5b1fef6ca78b4abfa74f329d6b6c72890d18"
}
