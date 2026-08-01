/*
   GenieLocker ransomware (Toy Ghouls / Bearlyfy)
   (Kaspersky GReAT, disclosed 2026-07-31; active since 2026-03)
   -----------------------------------------------------------------------
   Cross-platform encryptor (Windows PE + Linux/ESXi ELF) from the Toy Ghouls
   crew (aka Bearlyfy/Labubu), who graduated from renting RedAlert/LockBit/Babuk
   to their own locker. Encryption via libsodium: XChaCha20-Poly1305 for content
   + Curve25519-XSalsa20-Poly1305 per-file key wrap + an embedded attacker
   public key; BLAKE2b per-chunk. Execution is gated on a hex "secret" first
   argument SHA-256-validated against a hardcoded value (anti-sandbox). Appends
   the extension .03ffc1c4a3da0f02, writes .lock/.journal sidecars (journal
   magic "VCJOURN"), kills DB/backup/VM processes and services, and the ESXi
   build rewrites /etc/vmware/welcome. Drops NO ransom note; no exfiltration.

   NOTE: libsodium/XChaCha20 are legitimate. Rules anchor on the campaign-unique
   constants (the .03ffc1c4a3da0f02 extension, the VCJOURN journal magic, the
   exact kill-list strings) plus MZ/ELF gating, not on generic crypto strings.

   Rule 1 - Behavioral: hardcoded extension + journal magic + kill-list combo.
   Rule 2 - IOC: encrypted-file extension, C2 IP, sample MD5 pins.

   Related in-repo: [[prinz-eugen-ransomware]] [[vect-ransomware]]

   Sources:
     https://securelist.com/genielocker-ransomware-for-windows-linux-and-esxi/120843/
*/

rule GenieLocker_Ransomware_Behavior
{
    meta:
        description = "GenieLocker ransomware (Toy Ghouls/Bearlyfy) - hardcoded .03ffc1c4a3da0f02 extension, VCJOURN journal magic, libsodium XChaCha20 + Curve25519 key wrap, SHA-256 secret-gated exec, ESXi /etc/vmware/welcome rewrite"
        author      = "synthetic-detections"
        date        = "2026-08-01"
        severity    = "critical"
        family      = "genielocker-ransomware"
        reference   = "https://securelist.com/genielocker-ransomware-for-windows-linux-and-esxi/120843/"

    strings:
        // Campaign-unique constants
        $ext   = ".03ffc1c4a3da0f02" ascii wide
        $journ = "VCJOURN" ascii

        // Kill-list fragments (exact GenieLocker lists)
        $kp = "dbeng50;sqbcoreservice;excel;infopath;msaccess" ascii
        $ks = "GxVss;GxBlr;GxFWD;GxCVD;GxCIMgr" ascii

        // ESXi behaviour + libsodium key-wrap scheme markers
        $esxi = "/etc/vmware/welcome" ascii
        $wrap = "Curve25519-XSalsa20-Poly1305" ascii nocase

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F)   // MZ or ELF
        and filesize < 30MB
        and (
            $ext                                   // extension is campaign-unique
            or $journ                              // journal magic is campaign-unique
            or any of ($kp, $ks)                   // exact kill-list fragment
            or ( $esxi and $wrap )                 // ESXi build + the key-wrap scheme
        )
}

rule GenieLocker_IOC
{
    meta:
        description = "GenieLocker hard IOCs - encrypted-file extension, C2 IP, and Kaspersky sample MD5 pins (Windows PE + Linux/ESXi ELF)"
        author      = "synthetic-detections"
        date        = "2026-08-01"
        severity    = "high"
        family      = "genielocker-ransomware"
        reference   = "https://securelist.com/genielocker-ransomware-for-windows-linux-and-esxi/120843/"

    strings:
        $ext = ".03ffc1c4a3da0f02" ascii wide
        $c2  = "89.125.66.101" ascii

        $m1 = "5d62c1349b8981c396c9a23f4f8f053c" ascii nocase
        $m2 = "9201e35e2993612612919a3c71302cab" ascii nocase
        $m3 = "a50eaaf514f4f84e61ca2455a8789753" ascii nocase
        $m4 = "de3cfbb50f66079bfee20a6f64e59433" ascii nocase
        $m5 = "34a7f28e0bb69b0d49bacc88bdf20ac1" ascii nocase

    condition:
        any of them
}
