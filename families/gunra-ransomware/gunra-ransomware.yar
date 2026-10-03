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
        uint16(0) == 23117 and uint32(uint32(60)) == 17744
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
        gunra_is_pe and any of ($ext*) and any of ($note*)
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
        $q = "qTox" ascii wide nocase
        $c = "Client ID" ascii wide nocase
        $e = ".ENCRT" ascii wide
        $t = "Tor" ascii wide
    condition:
        $e and $q and any of ($c, $t, $r1) and filesize < 64KB
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
        $i1 = "23.239.119.2" fullword
        $i2 = "23.239.119.3" fullword
        $i3 = "23.239.119.4" fullword
        $i4 = "23.239.119.5" fullword
        $i5 = "23.239.119.6" fullword
        $i6 = "86.54.28.216" fullword
        $i7 = "103.125.234.14" fullword
        $i8 = "70.36.99.82" fullword
        $i9 = "211.21.210.181" fullword
        $i10 = "123.184.143.105" fullword
        $i11 = "182.204.21.240" fullword
        $i12 = "182.204.16.112" fullword
        $i13 = "123.244.187.144" fullword
        $mirror = "datapub.news" nocase
    condition:
        ($mirror or 3 of ($i*)) and filesize < 2MB
}
