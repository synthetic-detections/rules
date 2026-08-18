/*
   AmnesiaStealer — macOS Rust infostealer with live CDP browser control
   (Jamf Threat Labs, disclosed 2026-08-13)
   ---------------------------------------------------------------------
   Multi-stage Rust macOS stealer delivered via the ClickFix technique: a
   fake GitHub download page lures the victim into pasting a base64 shell
   one-liner into Terminal, which fetches a password-protected ZIP. Beyond
   standard theft (macOS Keychain, Safari cookies, Chromium data across
   Chrome/Brave/Arc/Edge/Opera/Vivaldi/Chromium), it is assessed as the
   first macOS malware to combine a CLONED Chromium profile with CDP-based
   live remote control — a hidden headless browser is driven against the
   copied profile over the DevTools Protocol so the operator interacts with
   authenticated sessions while the victim's visible browser is untouched.
   Persistence via a root LaunchDaemon impersonating a crash reporter;
   TCC-avoidance AppleScript "quiet path".

   Related: same ClickFix delivery class as [[clicklock-macos-stealer]] and
   [[steam-clickfix-xmrig]]; DPRK-adjacent macOS stealer [[gaslight-macos-dprk]].

   Rule 1 — Behavioral: distinctive build/config/module strings
            (leetspeak XOR key, [HYBRID_DEBUG], stream module, v3 markers).
   Rule 2 — IOC: C2/delivery domains, API path + X-API-Key, sample SHA-256.
   Rule 3 — Specimen-pin: the tight, distinctive artifact combination.

   Sources:
     https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/
     https://www.bleepingcomputer.com/news/security/new-amnesiastealer-macos-malware-hijacks-browser-sessions-via-remote-control/
*/

rule AmnesiaStealer_macOS_Behavior
{
    meta:
        description = "AmnesiaStealer macOS Rust stealer — distinctive build/config/module artifacts (leetspeak XOR key, HYBRID_DEBUG, stream module, v3 markers)"
        author      = "synthetic-detections"
        date        = "2026-08-18"
        severity    = "critical"
        family      = "amnesiastealer-macos-stealer"
        reference   = "https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/"

    strings:
        // near-unique embedded secrets (leetspeak "amnesia 2026")
        $x_xorkey  = "4mn3s1a_2o26!xK" ascii
        $x_ss      = "pqz8N3vKxRmY2aLcQ" ascii     // "safe storage" destructive-rewrite password

        // module / debug markers
        $b_hybrid  = "[HYBRID_DEBUG]" ascii
        $b_stream  = ".local/share/.stream" ascii  // cached cloned browser keys/profiles
        $b_runctl  = "run_controller" ascii
        $b_dumpmail= "dump_mail" ascii
        $b_smoke   = "/tmp/mail_accounts_smoke" ascii
        $b_marker  = "BUILD_V3_MARKER.txt" ascii
        $b_v3      = "v3_shell_chrome" ascii

    condition:
        filesize < 30MB
        and (
            // the leetspeak key or the safe-storage password are pathognomonic
            $x_xorkey or $x_ss
            // debug tag + any module/staging marker
            or ($b_hybrid and (any of ($b_stream, $b_runctl, $b_dumpmail, $b_smoke, $b_marker, $b_v3)))
            // the two build markers together
            or ($b_marker and $b_v3)
            // any two distinctive module strings co-occurring (guards $b_cargo alone)
            or (2 of ($b_stream, $b_runctl, $b_dumpmail, $b_smoke, $b_marker, $b_v3))
        )
}

rule AmnesiaStealer_macOS_IOC
{
    meta:
        description = "AmnesiaStealer macOS stealer — C2/delivery domains, API path + X-API-Key, sample SHA-256 hashes"
        author      = "synthetic-detections"
        date        = "2026-08-18"
        severity    = "high"
        family      = "amnesiastealer-macos-stealer"
        reference   = "https://www.bleepingcomputer.com/news/security/new-amnesiastealer-macos-malware-hijacks-browser-sessions-via-remote-control/"

    strings:
        // C2 + delivery infrastructure (matched as literals)
        $d_c2     = "debug.allllowef.space" ascii nocase
        $d_deliv  = "github.aoitour.com" ascii nocase
        $d_apikey = "86770e8759abf2dad9ae85f5e11a25e9" ascii nocase   // X-API-Key value

        // API endpoints (co-occurrence guarded)
        $p_actions= "/api/bot/actions?build_id=" ascii
        $p_join   = "/api/bot/join" ascii

        // sample SHA-256 (stage 1 + stage 2 "stream" module)
        $h1 = "de5748aac4a4d4cb48cf050652679e6bc49eda33d9ffaa0d280b578122fab55a" ascii nocase
        $h2 = "e853748ca8f9a5a9168263617409a9039ab09f4ffc7d860374c1e3b0b67b31a5" ascii nocase

    condition:
        filesize < 60MB
        and (
            // an exact sample hash, or the distinctive C2/delivery/key literal, or the API-path pair
            any of ($h*)
            or $d_c2 or $d_deliv or $d_apikey
            or ($p_actions and $p_join)
        )
}

rule AmnesiaStealer_macOS_Specimen
{
    meta:
        description = "AmnesiaStealer macOS stealer — tight specimen pin (distinctive artifact combination)"
        author      = "synthetic-detections"
        date        = "2026-08-18"
        severity    = "critical"
        family      = "amnesiastealer-macos-stealer"
        reference   = "https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/"

    strings:
        $x_xorkey = "4mn3s1a_2o26!xK" ascii
        $x_ss     = "pqz8N3vKxRmY2aLcQ" ascii
        $b_hybrid = "[HYBRID_DEBUG]" ascii
        $b_stream = ".local/share/.stream" ascii
        $b_marker = "BUILD_V3_MARKER.txt" ascii
        $b_v3     = "v3_shell_chrome" ascii
        $d_c2     = "debug.allllowef.space" ascii nocase

    condition:
        filesize < 30MB
        and (
            ($x_xorkey or $x_ss)
            and ($b_hybrid or $b_stream or $d_c2 or ($b_marker and $b_v3))
        )
}
