/*
   MALFEX — npm supply-chain malware (Overlord RAT + movinlike stealer), 2026-10
   ------------------------------------------------------------------------------
   Long-running npm supply-chain campaign (since Aug 2023) by a solo operator.
   Publishes trojanised npm packages (function-flag, function-color, cdn-img-fetch,
   img-to-native, native-runner) whose postinstall drops one of three payloads:

   1. Overlord RAT — AutoIt-compiled RAT dropped into
      %LOCALAPPDATA%\ScopeSmart Technologies Inc\ as AutoIt3.exe + h.a3x (or
      Oxygen.a3x). Scheduled task "\Maiden" (every 5 min, author "Welcome",
      comment "Wichita", backdated 2020-01-01). Process hollows TapiUnattend.exe
      with explorer.exe parent spoofing. AES key "malfexteam2027". Fake vendor
      "ScopeSmart Technologies Inc". Solana blockchain C2 resolution.
   2. movinlike stealer — Node.js infostealer targeting Discord tdata, browser
      creds, crypto wallets. Payload served as PNG from api.imghippo.com.
   3. npm worm component — propagates via compromised npm tokens.

   Actor markers: GitHub "cavecrew", email corpmalfex@gmail.com.
   C2: 104.234.65[.]75 (port 700/80), 45.89.30[.]194, 191.96.81[.]101,
       51.137.158[.]178.

   Rule 1 — behavioural: "ScopeSmart Technologies" co-occurring with the
            scheduled task name "Maiden", AES key "malfexteam2027", or the
            hollowed process "TapiUnattend". These strings are unique to
            MALFEX and extremely unlikely in legitimate software.
   Rule 2 — IOC sweep: C2 IPs, api.imghippo.com paths, cavecrew GitHub
            references, npm package names, actor email, with co-occurrence
            guards on generic tokens.
   Rule 3 — specimen pin: SHA-256 hashes of known Overlord RAT samples.

   Sources:
     https://checkmarx.com/zero-post/malfex-npm-malware-campaign-three-payloads-and-an-adversary-that-signs-their-work/
     https://www.cloudsek.com/pt-br/blog/malfex-malicious-npm-postinstall-supply-chain-campaign
     https://hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/
*/

import "hash"

rule MALFEX_OverlordRAT_Behavioral : behavioral rat supply_chain
{
    meta:
        description = "MALFEX Overlord RAT behavioural — ScopeSmart Technologies fake vendor with scheduled task Maiden, AES key, or TapiUnattend hollowing"
        author      = "synthetic-detections"
        date        = "2026-10-09"
        severity    = "critical"
        family      = "malfex"
        reference   = "https://checkmarx.com/zero-post/malfex-npm-malware-campaign-three-payloads-and-an-adversary-that-signs-their-work/"
    strings:
        // Fake vendor name — not a real company, unique to MALFEX
        $vendor    = "ScopeSmart Technologies" ascii wide nocase
        // Scheduled task name, backdated 2020-01-01
        $task      = "Maiden" ascii wide
        // AES decryption key hardcoded in Overlord RAT
        $aes_key   = "malfexteam2027" ascii wide
        // Process hollowing target
        $hollow    = "TapiUnattend" ascii wide nocase
        // AutoIt script payload filenames
        $script1   = "h.a3x" ascii wide nocase
        $script2   = "Oxygen.a3x" ascii wide nocase
        // Scheduled task metadata
        $task_auth = "Welcome" ascii wide
        $task_cmt  = "Wichita" ascii wide
    condition:
        // ScopeSmart is the unique anchor — require it plus any operational marker
        $vendor
        and ($task or $aes_key or $hollow or any of ($script*) or ($task_auth and $task_cmt))
        and filesize < 20MB
}

rule MALFEX_IOC : ioc rat stealer supply_chain
{
    meta:
        description = "MALFEX IOC sweep — C2 IPs, staging domains, actor identifiers, npm package names (co-occurrence guarded)"
        author      = "synthetic-detections"
        date        = "2026-10-09"
        severity    = "high"
        family      = "malfex"
        reference   = "https://www.cloudsek.com/pt-br/blog/malfex-malicious-npm-postinstall-supply-chain-campaign"
    strings:
        // --- Globally unique indicators (fire with minimal co-occurrence) ---
        // Actor email
        $actor_email = "corpmalfex@gmail.com" ascii wide
        // AES key (campaign-unique string)
        $aes_key     = "malfexteam2027" ascii wide
        // Fake vendor
        $vendor      = "ScopeSmart Technologies" ascii wide nocase
        // --- C2 infrastructure ---
        $c2_1        = "104.234.65.75" ascii wide
        $c2_2        = "45.89.30.194" ascii wide
        $c2_3        = "191.96.81.101" ascii wide
        $c2_4        = "51.137.158.178" ascii wide
        // --- Staging / delivery ---
        $staging     = "api.imghippo.com" ascii wide nocase
        $gh_actor    = "cavecrew" ascii wide nocase
        // --- npm package names (need co-occurrence — individually too generic) ---
        $pkg1        = "function-flag" ascii wide
        $pkg2        = "function-color" ascii wide
        $pkg3        = "cdn-img-fetch" ascii wide
        $pkg4        = "img-to-native" ascii wide
        $pkg5        = "native-runner" ascii wide
        // --- Campaign co-occurrence anchors ---
        $hollow      = "TapiUnattend" ascii wide nocase
        $task        = "Maiden" ascii wide
    condition:
        // Unique actor identifiers fire standalone
        // Any two C2 IPs together
        // Single C2 IP with a campaign anchor
        // Staging domain with any campaign marker
        // GitHub actor account with campaign markers
        // npm package names require co-occurrence with campaign-specific indicator
        (
            any of ($actor_email, $aes_key, $vendor) or
            2 of ($c2_*) or
            (any of ($c2_*) and any of ($hollow, $task, $staging, $gh_actor)) or
            ($staging and any of ($hollow, $task, $gh_actor, $c2_1, $c2_2, $c2_3, $c2_4)) or
            ($gh_actor and any of ($hollow, $task, $staging, $c2_1, $c2_2, $c2_3, $c2_4)) or
            (any of ($pkg*) and any of ($actor_email, $aes_key, $vendor, $hollow, $task, $staging, $gh_actor))
        )
        and filesize < 50MB
}

rule MALFEX_Specimen : rat specimen stealer supply_chain
{
    meta:
        description = "MALFEX specimen pin — SHA-256 hashes of known Overlord RAT and movinlike stealer samples"
        author      = "synthetic-detections"
        date        = "2026-10-09"
        severity    = "critical"
        family      = "malfex"
        reference   = "https://hackread.com/malfex-npm-windows-rat-steals-discord-browser-data/"
    condition:
        // Overlord RAT loader (AutoIt3.exe + h.a3x dropper)
        // AutoIt3.exe (legitimate binary abused for sideloading)
        // Overlord RAT decoded payload
        // movinlike stealer
        (
            hash.sha256(0, filesize) == "9aba4685af072231aee049e1a5e294965580001b364d7d00152d84fcec1ce793" or
            hash.sha256(0, filesize) == "5d69a932a077fee044b193c28e84564143f5c7e51079ab48e88fef74ab0b77b7" or
            hash.sha256(0, filesize) == "2989244eac2a4bc7a13a09dec003e5c05ef7c80b2afe0958ce25042d5b804210" or
            hash.sha256(0, filesize) == "c9c374afba4658dff15f71801e88c4d199c91dd2622d72c7b0c55577c8f73437"
        )
        and filesize < 50MB
}
