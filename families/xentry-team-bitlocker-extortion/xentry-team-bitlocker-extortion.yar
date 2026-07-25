/*
   XEntry Team — BitLocker + printer extortion (Kaspersky Securelist, 2026-07-21)
   ------------------------------------------------------------------------------
   Financially-motivated extortion crew observed against organizations in
   Colombia and Mexico. Deliberately builds NO custom ransomware: encrypts
   business-critical volumes with the built-in Windows BitLocker (manage-bde),
   then delivers ransom demands by hijacking office printers and by leaving a
   blue-screen message reading "Hacked by XEntry Team". Because encryption is
   pure living-off-the-land, there is no encryptor binary or file-magic to pin;
   the durable static artifacts are the actor's reused ransom-note prose and
   brand string.

   Kill chain: internet-exposed RDP (EPP disabled first) or misconfigured MSSQL
   with xp_cmdshell + source-leaked creds -> lateral movement via GPO ->
   persistence via RMM (ManageEngine Endpoint Central, Mesh Agent, Tactical RMM)
   + scheduled tasks -> BitLocker encryption of critical drives -> printed +
   on-screen ransom notes. Months-long dwell in the Mexico case; $3,000 demand
   in the Colombia case. No file hashes or C2 published by the vendor.

   Kaspersky detection names (context, not YARA anchors):
     Trojan.Multi.Agent.gen, Trojan.Win32.GenAutorunMsSqlServerCommandRun.a,
     Exploit.Win32.SCShell.a

   Because this family is text/LOLBin-only, these rules target the ransom note
   as delivered (printed page, dropped note file, on-screen message) rather than
   a binary. See the sibling ransomware note-text rules for the same approach:
     [[prinz-eugen-ransomware]]

   Rule 1 — Behavioral/critical: the two reused "guarantee" sentences that
            appear across incidents; together they are near-unique to XEntry.
   Rule 2 — IOC/high: the "Hacked by XEntry Team" brand string with a
            co-occurrence guard (brand + one supporting extortion artifact),
            since the brand token alone, while distinctive, is short.
   Rule 3 — Specimen-pin/critical: full note — brand string AND both guarantee
            sentences present together (effectively zero false positives).

   Sources:
     https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/
     https://www.kaspersky.com/about/press-releases/prints-of-darkness-hackers-printing-demands-during-ransomware-campaigns-across-latin-america-kaspersky
*/

rule XEntry_Team_RansomNote_Behavior
{
    meta:
        description = "XEntry Team ransom note — the two reused 'guarantee' sentences seen across the LATAM BitLocker/printer extortion incidents"
        author      = "synthetic-detections"
        date        = "2026-07-25"
        severity    = "critical"
        family      = "xentry-team-bitlocker-extortion"
        reference   = "https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/"

    strings:
        // Reused verbatim across incidents — highly distinctive phrasing
        $g1 = "Our reputation is the guarantee that all content will be fulfilled" ascii wide nocase
        $g2 = "we have no negative online reviews about non-fulfillment of our obligations" ascii wide nocase

    condition:
        // Both guarantee sentences together are effectively unique to XEntry;
        // note files / printed pages are small
        filesize < 200KB
        and all of them
}

rule XEntry_Team_Branding_IOC
{
    meta:
        description = "XEntry Team brand string 'Hacked by XEntry Team' co-occurring with a supporting extortion artifact"
        author      = "synthetic-detections"
        date        = "2026-07-25"
        severity    = "high"
        family      = "xentry-team-bitlocker-extortion"
        reference   = "https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/"

    strings:
        // Blue-screen / on-screen brand message
        $brand = "Hacked by XEntry Team" ascii wide nocase

        // Supporting extortion artifacts (guard against a bare brand mention)
        $g1        = "Our reputation is the guarantee that all content will be fulfilled" ascii wide nocase
        $g2        = "we have no negative online reviews about non-fulfillment of our obligations" ascii wide nocase
        $bde1      = "manage-bde" ascii wide nocase          // BitLocker CLI
        $bde2      = "BitLocker" ascii wide
        $xp_cmd    = "xp_cmdshell" ascii wide nocase          // MSSQL initial access
        $note_hint = "XEntry Team" ascii wide nocase

    condition:
        filesize < 5MB
        and $brand
        and (
            any of ($g1, $g2)
            or ($note_hint and any of ($bde1, $bde2, $xp_cmd))
        )
}

rule XEntry_Team_RansomNote_Pin
{
    meta:
        description = "XEntry Team full ransom note — brand string with both reused guarantee sentences (specimen pin, near-zero FP)"
        author      = "synthetic-detections"
        date        = "2026-07-25"
        severity    = "critical"
        family      = "xentry-team-bitlocker-extortion"
        reference   = "https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/"

    strings:
        $brand = "Hacked by XEntry Team" ascii wide nocase
        $g1    = "Our reputation is the guarantee that all content will be fulfilled" ascii wide nocase
        $g2    = "we have no negative online reviews about non-fulfillment of our obligations" ascii wide nocase

    condition:
        filesize < 200KB
        and $brand and $g1 and $g2
}
