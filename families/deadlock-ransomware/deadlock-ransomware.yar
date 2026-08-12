/*
   DeadLock ransomware — Rust encryptor with blockchain-resident C2
   ----------------------------------------------------------------
   Source: Microsoft Threat Intelligence, "DeadLock ransomware: Breaking down a
   Rust-based encryptor with decentralized recovery infrastructure" (2026-08-10).
   First seen July 2025; scaled up 2026 (80+ victims). Extortion/recovery
   pointers (chat proxy, blog) are stored in Polygon (MATIC) smart contracts to
   resist takedown; negotiation runs over the Session messaging network. The
   locker disables Defender/backups/event-logs, appends .dlock, drops two ransom
   notes, and stamps a 'dDlK' footer on encrypted files. Affiliate overlap with
   the Lynx and INC ecosystems (partial RaaS).

   Rule shape:
     (1) DeadLock_Encryptor      — behavioural/critical: PE + the on-disk crypto
         artifacts (dDlK footer magic + .dlock ext + a ransom-note name)
     (2) DeadLock_Ransom_Note    — high: the two note filenames + recovery text
     (3) DeadLock_Blockchain_C2  — IOC/high: Polygon contract addrs/selectors and
         leak-site domains, count-guarded

   File-hash IOC (encryptor a1fdf650...) is tracked in the 2026-08-12 digest hash
   store; this rule keys on content to stay corpus-scannable.

   Attribution: financially motivated, partial RaaS; affiliate overlap with Lynx
   and INC per Microsoft. No nation-state nexus claimed.

   Related: [[xentry-team-bitlocker-extortion]] (extortion tradecraft).
*/

private rule dl_is_pe {
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule DeadLock_Encryptor {
    meta:
        description = "DeadLock ransomware Rust encryptor — dDlK footer + .dlock extension + ransom-note artifacts"
        author = "synthetic-detections"
        date = "2026-08-12"
        severity = "critical"
        family = "deadlock-ransomware"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/"
    strings:
        $magic = "dDlK" ascii
        $ext   = ".dlock" ascii wide
        $note1 = "HOW_RECOVER" ascii wide
        $note2 = "RECOVERY_CHAT" ascii wide
        $svc   = "windefend" ascii wide nocase
    condition:
        dl_is_pe and $magic and $ext and (any of ($note*)) and $svc
}

rule DeadLock_Ransom_Note {
    meta:
        description = "DeadLock ransom note — recovery filenames + Session/Polygon recovery instructions"
        author = "synthetic-detections"
        date = "2026-08-12"
        severity = "high"
        family = "deadlock-ransomware"
        reference = "https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/"
    strings:
        $n1 = "HOW_RECOVER" ascii wide
        $n2 = "RECOVERY_CHAT" ascii wide
        $b1 = "liveblog365.com" ascii wide nocase
        $b2 = "Session" ascii wide
        $b3 = ".dlock" ascii wide
    condition:
        filesize < 100KB and ( (all of ($n*)) or ($n1 and 2 of ($b*)) )
}

rule DeadLock_Blockchain_C2 {
    meta:
        description = "DeadLock Polygon smart-contract C2 and leak-site indicators (count-guarded)"
        author = "synthetic-detections"
        date = "2026-08-12"
        severity = "high"
        family = "deadlock-ransomware"
        reference = "https://thehackernews.com/2026/08/deadlock-ransomware-uses-polygon-smart.html"
    strings:
        $c1 = "0x8EF7c3e531d871D3B9D559722DE77EB1dEc19dAe" ascii nocase
        $c2 = "0x757984507c82c8dA1d3969c535dB5706eEE6426C" ascii nocase
        $sel1 = "933a9ce8" ascii nocase
        $sel2 = "d4070542" ascii nocase
        $d1 = "deadlock.liveblog365.com" ascii nocase
        $d2 = "dlock.liveblog365.com" ascii nocase
        $onion = "deadblogdbdu5wprek7wa2o4ce7rnt6u6ntqeud3hzjjcveosgpsqqqd" ascii nocase
        $pk = "03bf50bbf97c4e951e66ff12b689a37a3ce675b4921e254eae76da77573843e4a9" ascii nocase
    condition:
        2 of them
}
