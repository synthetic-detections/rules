/*
   CoreRAT — Core Werewolf's revamped custom C++ RAT
   -------------------------------------------------
   Source: BI.ZONE, "Arsenal revamped: Core Werewolf hits Russian organizations
   with CoreRAT" (2026-08-26); corroborated by GBHackers and CyberSecurityNews
   (2026-08-26/27). Attributed to the Core Werewolf espionage cluster targeting
   Russian government and defence-industry organisations.

   Tradecraft: Telegram phishing delivers a 7z self-extracting archive (7zSFX) or a
   Rust-based dropper that shows a decoy PDF (military/government theme) while
   installing CoreRAT. The RAT is written in C++, AES-CBC-encrypts its embedded
   strings and C2 addresses, Base58-encodes exfiltrated JSON, and reaches its C2
   over HTTPS/443 on short hex URI paths. Anti-analysis: it terminates if fewer
   than 15 .lnk files exist in the recent-items AutomaticDestinations directory
   (a sparse LNK history reads as a fresh sandbox).

   The static string artifacts below (mutex, URI paths, deployment EXE names,
   decoy PDF names) are OSINT-derived from the vendor report; a live sample was
   not held at authoring time, so rules 1/3 co-occurrence-guard the mutex against
   at least one CoreRAT-specific URI path or EXE name to avoid a bare-number FP.

   Rule shape:
     (1) CoreRAT_Behaviour      — critical: PE + mutex + >=1 CoreRAT C2 URI path
                                   or deployment EXE name
     (2) CoreRAT_C2_IOC         — high: >=2 distinct CoreRAT C2 domains/IPs
                                   (co-occurrence guard against a single common host)
     (3) CoreRAT_Delivery_Pin   — critical/specimen-pin: decoy PDF name +
                                   deployment EXE name co-occurrence

   File-hash / network IOC set is tracked in the digest hash + IOC store.

   Related: [[sleepwalker-backdoor]] (same digest cadence, espionage backdoor).
*/

private rule corerat_is_pe {
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 12MB
}

rule CoreRAT_Behaviour {
    meta:
        description = "CoreRAT C++ RAT — hardcoded mutex co-occurring with a CoreRAT C2 URI path or deployment EXE name"
        author = "synthetic-detections"
        date = "2026-08-27"
        severity = "critical"
        family = "corerat-core-werewolf"
        reference = "https://bi-zone.medium.com/arsenal-revamped-core-werewolf-hits-russian-organizations-with-corerat-452d58ef1b6b"
    strings:
        $mutex = "301525677" ascii wide
        $uri1 = "/5743e279" ascii wide
        $uri2 = "/0a445b0e" ascii wide
        $uri3 = "/ba4b6dc1" ascii wide
        $uri4 = "/97e8be66" ascii wide
        $exe1 = "Firepoin.exe" ascii wide nocase
        $exe2 = "Baresl.exe" ascii wide nocase
        $exe3 = "Biostars.exe" ascii wide nocase
    condition:
        corerat_is_pe and $mutex and (any of ($uri*) or any of ($exe*))
}

rule CoreRAT_C2_IOC {
    meta:
        description = "CoreRAT command-and-control infrastructure — Core Werewolf 2026 campaign (>=2 distinct hosts)"
        author = "synthetic-detections"
        date = "2026-08-27"
        severity = "high"
        family = "corerat-core-werewolf"
        reference = "https://gbhackers.com/core-werewolf-espionage-cluster/"
    strings:
        $d1 = "teambusiness-mail.ru" ascii wide nocase
        $d2 = "xakklinkprik.ru" ascii wide nocase
        $d3 = "dezinsekciya-top.ru" ascii wide nocase
        $d4 = "ahmetgurses.net" ascii wide nocase
        $d5 = "msgntfsys.link" ascii wide nocase
        $d6 = "arendelle.ru" ascii wide nocase
        $d7 = "sgpsib.ru" ascii wide nocase
        $i1 = "185.102.139.30" ascii wide fullword
        $i2 = "130.49.181.212" ascii wide fullword
        $i3 = "138.124.76.77" ascii wide fullword
        $i4 = "95.81.125.145" ascii wide fullword
        $i5 = "178.253.39.45" ascii wide fullword
        $i6 = "104.128.129.184" ascii wide fullword
        $i7 = "95.215.108.140" ascii wide fullword
    condition:
        2 of them
}

rule CoreRAT_Delivery_Pin {
    meta:
        description = "CoreRAT delivery specimen — decoy PDF name co-occurring with a deployment EXE name"
        author = "synthetic-detections"
        date = "2026-08-27"
        severity = "critical"
        family = "corerat-core-werewolf"
        reference = "https://bi-zone.medium.com/arsenal-revamped-core-werewolf-hits-russian-organizations-with-corerat-452d58ef1b6b"
    strings:
        $pdf1 = "Scan_125992145_TLG_na_perepodgotovku_dsp.pdf" ascii wide nocase
        $pdf2 = "FOhf6.pdf" ascii wide nocase
        $exe1 = "Firepoin.exe" ascii wide nocase
        $exe2 = "Baresl.exe" ascii wide nocase
        $exe3 = "Biostars.exe" ascii wide nocase
    condition:
        any of ($pdf*) and any of ($exe*)
}
