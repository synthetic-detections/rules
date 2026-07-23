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
        // full published Daxin sample set (Symantec 2022 cores/droppers/suspected)
        // + the 2026 Stupig sample, matched exactly via the hash module
        (
            hash.sha256(0, filesize) == "81c7bb39100d358f8286da5e9aa838606c98dfcc263e9a82ed91cd438cb130d1" or
            hash.sha256(0, filesize) == "06a0ec9a316eb89cb041b1907918e3ad3b03842ec65f004f6fa74d57955573a4" or
            hash.sha256(0, filesize) == "0f82947b2429063734c46c34fb03b4fa31050e49c27af15283d335ea22fe0555" or
            hash.sha256(0, filesize) == "3e7724cb963ad5872af9cfb93d01abf7cd9b07f47773360ad0501592848992f4" or
            hash.sha256(0, filesize) == "447c3c5ac9679be0a85b3df46ec5ee924f4fbd8d53093125fd21de0bff1d2aad" or
            hash.sha256(0, filesize) == "49c827cf48efb122a9d6fd87b426482b7496ccd4a2dbca31ebbf6b2b80c98530" or
            hash.sha256(0, filesize) == "5bc3994612624da168750455b363f2964e1861dba4f1c305df01b970ac02a7ae" or
            hash.sha256(0, filesize) == "5c1585b1a1c956c7755429544f3596515dfdf928373620c51b0606a520c6245a" or
            hash.sha256(0, filesize) == "6908ebf52eb19c6719a0b508d1e2128f198d10441551cbfb9f4031d382f5229f" or
            hash.sha256(0, filesize) == "7867ba973234b99875a9f5138a074798b8d5c65290e365e09981cceb06385c54" or
            hash.sha256(0, filesize) == "7a08d1417ca056da3a656f0b7c9cf6cd863f9b1005996d083a0fc38d292b52e9" or
            hash.sha256(0, filesize) == "8d9a2363b757d3f127b9c6ed8f7b8b018e652369bc070aa3500b3a978feaa6ce" or
            hash.sha256(0, filesize) == "b0eb4d999e4e0e7c2e33ff081e847c87b49940eb24a9e0794c6aa9516832c427" or
            hash.sha256(0, filesize) == "b9dad0131c51e2645e761b74a71ebad2bf175645fa9f42a4ab0e6921b83306e3" or
            hash.sha256(0, filesize) == "e7af7bcb86bd6bab1835f610671c3921441965a839673ac34444cf0ce7b2164e" or
            hash.sha256(0, filesize) == "ea3d773438c04274545d26cc19a33f9f1dbbff2a518e4302addc1279f9950cef" or
            hash.sha256(0, filesize) == "08dc602721c17d58a4bc0c74f64a7920086f776965e7866f68d1676eb5e7951f" or
            hash.sha256(0, filesize) == "53d23faf8da5791578c2f5e236e79969289a7bba04eee2db25f9791b33209631" or
            hash.sha256(0, filesize) == "705be833bd1880924c99ec9cf1bd0fcf9714ae0cec7fd184db051d49824cbbf4" or
            hash.sha256(0, filesize) == "c791c007c8c97196c657ac8ba25651e7be607565ae0946742a533af697a61878" or
            hash.sha256(0, filesize) == "5bb5cffda4647940919a185df37aab2aef71ca3010a6c1d05bdcc8bc8fb3af3f"
        )
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
