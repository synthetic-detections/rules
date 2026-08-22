/*
   Gunra ransomware — Conti-derived double-extortion RaaS
   ------------------------------------------------------
   Source: CISA/FBI/DoD/NSA/USSS + South Korea KNPA joint #StopRansomware
   advisory AA26-222A (2026-08-10). Gunra emerged April 2025 from leaked Conti
   source, became a full RaaS in early 2026 (alias "Golden Community"). Windows +
   Linux lockers; ChaCha20 + RSA-4096; appends .ENCRT (older .CRYPT), drops
   R3ADM3.txt in every directory; deletes shadow copies via WMI; negotiation over
   Tor + qTox. Initial access via Fortinet CVE-2024-55591 / CVE-2025-24472 and
   default-credential SSL-VPN abuse.

   Because Gunra is Conti-derived, generic Conti-family strings would over-match;
   these rules key on Gunra's OWN distinctive artifacts (the .ENCRT extension and
   the R3ADM3.txt note name), always co-occurrence-guarded.

   Rule shape:
     (1) Gunra_Encryptor       — behavioural/critical: PE + .ENCRT ext +
         R3ADM3.txt note name (+ debugger/anti-analysis token)
     (2) Gunra_Ransom_Note     — high: R3ADM3.txt note text (Client ID + qTox +
         5-7 day window language)
     (3) Gunra_Campaign_C2     — IOC/high: advisory C2 IPs + datapub.news mirror,
         count-guarded

   File-hash IOCs: the CISA advisory publishes hashes in its downloadable IOC
   package (not in the HTML body); track those in the digest hash store as they
   become available. This rule keys on content.

   Attribution: financially motivated RaaS, Conti code lineage; no state nexus.

   Related: [[xentry-team-bitlocker-extortion]], [[deadlock-ransomware]]
   (same digest, RaaS double-extortion).
*/

private rule gunra_is_pe {
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule Gunra_Encryptor {
    meta:
        description = "Gunra ransomware encryptor — .ENCRT extension + R3ADM3 note name co-occurrence"
        author = "synthetic-detections"
        date = "2026-08-12"
        severity = "critical"
        family = "gunra-ransomware"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a"
    strings:
        $ext1 = ".ENCRT" ascii wide
        $ext2 = ".CRYPT" ascii wide
        $note = "R3ADM3.txt" ascii wide nocase
        $note2 = "R3ADM3" ascii wide nocase
    condition:
        gunra_is_pe and (any of ($ext*)) and (any of ($note*))
}

rule Gunra_Ransom_Note {
    meta:
        description = "Gunra ransom note — R3ADM3 recovery text (Client ID + qTox + deadline)"
        author = "synthetic-detections"
        date = "2026-08-12"
        severity = "high"
        family = "gunra-ransomware"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a"
    strings:
        $r1 = "R3ADM3" ascii wide nocase
        $q  = "qTox" ascii wide nocase
        $c  = "Client ID" ascii wide nocase
        $e  = ".ENCRT" ascii wide
        $t  = "Tor" ascii wide
    condition:
        // note body carries the extortion text (the file itself is named
        // R3ADM3.txt, so "R3ADM3" need not appear in the content)
        filesize < 64KB and $e and $q and 1 of ($c, $t, $r1)
}

rule Gunra_Campaign_C2 {
    meta:
        description = "Gunra AA26-222A C2 indicators (IPs + clearnet DLS mirror), count-guarded"
        author = "synthetic-detections"
        date = "2026-08-12"
        severity = "high"
        family = "gunra-ransomware"
        reference = "https://media.defense.gov/2026/Aug/10/2003976697/-1/-1/0/CSA_STOPRANSOMWARE_GUNRA_RANSOMWARE.PDF"
    strings:
        $i1 = "23.239.119.2" ascii
        $i2 = "23.239.119.3" ascii
        $i3 = "23.239.119.4" ascii
        $i4 = "23.239.119.5" ascii
        $i5 = "23.239.119.6" ascii
        $i6 = "86.54.28.216" ascii
        $i7 = "103.125.234.14" ascii
        $i8 = "70.36.99.82" ascii
        $i9 = "211.21.210.181" ascii
        $i10 = "123.184.143.105" ascii
        $i11 = "182.204.21.240" ascii
        $i12 = "182.204.16.112" ascii
        $i13 = "123.244.187.144" ascii
        $mirror = "datapub.news" ascii nocase
    condition:
        // The IP strings are substring matches (e.g. 23.239.119.2 matches
        // 23.239.119.20-29), so a bare "2 of them" false-positives on asset
        // inventories / netflow. Require the distinctive clearnet DLS mirror,
        // or three co-occurring C2 IPs, under a filesize guard.
        filesize < 2MB and ($mirror or 3 of ($i*))
}
