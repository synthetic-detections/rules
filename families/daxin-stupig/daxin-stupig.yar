/*
   Daxin (kernel rootkit) + Stupig (pre-login SYSTEM backdoor) — Taiwan 2026
   (Symantec / Carbon Black Threat Hunter, 2026-07; China-nexus espionage)
   -----------------------------------------------------------------------
   Daxin resurfaced on a Taiwanese manufacturer's network — a signed kernel-mode
   rootkit (driver srt64.sys) byte-identical to the 2022 Symantec sample, with
   activity traced to 2013. It does NOT initiate outbound connections: it passively
   watches inbound TCP for a trigger and hijacks legitimate connections for encrypted
   C2, relaying multi-hop to reach air-gapped hosts.

   Deployed with it: Stupig (a.dll -> kbdus1.dll), a backdoor masquerading as a
   Windows keyboard-layout component. It registers on a keyboard-layout path so
   winlogon.exe loads it at startup, then monitors the LOGON SCREEN for a username
   beginning with "stupig" — text after that prefix is executed as SYSTEM before any
   user signs in (a pre-authentication command channel via the login box).

   Rules anchor on the campaign-specific artifacts (the "stupig" logon trigger, the
   kbdus1.dll keyboard-layout hijack, the srt64.sys driver) rather than generic
   winlogon/keyboard-layout strings, so a normal keyboard-layout DLL does not match.

   Rule 1 — Behavioral (critical): Stupig logon-screen SYSTEM backdoor / Daxin driver.
   Rule 2 — IOC (high): distinctive filenames + published sample hashes.
   Rule 3 — Specimen pin (critical): full Stupig implant shape.

   Samples (SHA-256):
     Daxin  : 49c827cf48efb122a9d6fd87b426482b7496ccd4a2dbca31ebbf6b2b80c98530
     Stupig : 5bb5cffda4647940919a185df37aab2aef71ca3010a6c1d05bdcc8bc8fb3af3f

   Sources:
     https://www.security.com/threat-intelligence/daxin-returns-stupig
     https://thehackernews.com/2026/07/daxin-resurfaces-in-taiwan-alongside.html

   Related: [[turla-stockstay]] [[moonlight-maze-loki2-penquin]] — long-dwell
            state-nexus espionage implants.
*/

import "hash"

rule Daxin_Stupig_Behavior
{
    meta:
        description = "Daxin kernel rootkit driver srt64.sys OR Stupig keyboard-layout-DLL logon-screen SYSTEM backdoor (kbdus1.dll loaded by winlogon, 'stupig' username trigger)"
        author      = "synthetic-detections"
        date        = "2026-07-23"
        severity    = "critical"
        family      = "daxin-stupig"
        reference   = "https://www.security.com/threat-intelligence/daxin-returns-stupig"

    strings:
        // Stupig logon-screen trigger prefix (campaign-unique)
        $stupig   = "stupig" ascii wide nocase

        // Stupig keyboard-layout-DLL hijack
        $kbdus1   = "kbdus1.dll" ascii wide nocase
        $kbdus1b  = "kbdus1" ascii wide nocase
        $winlogon = "winlogon.exe" ascii wide nocase
        $kbdlay   = "Keyboard Layouts" ascii wide nocase
        $kbddos   = "DosKeybCodes" ascii wide nocase

        // Daxin kernel driver
        $srt64    = "srt64.sys" ascii wide nocase

    condition:
        filesize < 10MB
        and (
            // Daxin driver name is specific to this rootkit
            $srt64
            or
            // Stupig: the "stupig" logon trigger co-occurring with the
            // keyboard-layout-DLL-via-winlogon persistence shape
            (
                $stupig
                and any of ($kbdus1, $kbdus1b, $winlogon, $kbdlay, $kbddos)
            )
        )
}

rule Daxin_Stupig_IOC
{
    meta:
        description = "Daxin/Stupig IOC — published sample hashes and the distinctive srt64.sys / kbdus1.dll filenames"
        author      = "synthetic-detections"
        date        = "2026-07-23"
        severity    = "high"
        family      = "daxin-stupig"
        reference   = "https://www.security.com/threat-intelligence/daxin-returns-stupig"

    strings:
        $srt64   = "srt64.sys" ascii wide nocase
        $kbdus1  = "kbdus1.dll" ascii wide nocase
        $stupig  = "stupig" ascii wide nocase

    condition:
        // exact published samples
        hash.sha256(0, filesize) == "49c827cf48efb122a9d6fd87b426482b7496ccd4a2dbca31ebbf6b2b80c98530"
        or hash.sha256(0, filesize) == "5bb5cffda4647940919a185df37aab2aef71ca3010a6c1d05bdcc8bc8fb3af3f"
        // or the distinctive filenames co-occurring with the trigger
        or ($kbdus1 and $stupig)
        or $srt64
}

rule Daxin_Stupig_Specimen
{
    meta:
        description = "Stupig specimen pin — full shape: kbdus1.dll keyboard-layout hijack loaded by winlogon with the 'stupig' logon-screen SYSTEM command trigger"
        author      = "synthetic-detections"
        date        = "2026-07-23"
        severity    = "critical"
        family      = "daxin-stupig"
        reference   = "https://www.security.com/threat-intelligence/daxin-returns-stupig"

    strings:
        $stupig   = "stupig" ascii wide nocase
        $kbdus1   = "kbdus1" ascii wide nocase
        $winlogon = "winlogon" ascii wide nocase
        $kbdlay   = "Keyboard Layout" ascii wide nocase

    condition:
        filesize < 10MB
        and $stupig
        and $kbdus1
        and ($winlogon or $kbdlay)
}
