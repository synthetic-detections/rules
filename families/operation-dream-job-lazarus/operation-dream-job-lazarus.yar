/*
   Operation Dream Job (Lazarus / DPRK) — 2026 defence-sector wave
   ---------------------------------------------------------------
   Source: Check Point Research, "Shattering the Dream — When a Job Offer
   Becomes a Zero-Day Attack" (2026-08-11). Lazarus used a fake-recruiter lure
   to deliver a trojanized PDF viewer (SecurityPDF), an in-memory downloader
   (MISTPEN), the Troy and ForestTiger backdoors, and — via an afd.sys
   admin-to-kernel zero-day (CVE-2026-68820) — a new build of the FudModule
   kernel rootkit (v3.1). A parallel Roundcube chain (CVE-2025-49113) planted
   the RelayShell PHP webshell as a C2 relay.

   Distinctive, low-churn artifacts keyed here (not the forgeable CVE numbers):
     - FudModule "god-mode" telemetry strings + Smart App Control tamper token
     - Troy backdoor: the Troy_Handle PDB fragment + its command-word set
     - SecurityPDF: the hard-coded SumatraPDF "encrypted" decoy marker
     - RelayShell: the embedded base64-ish operator identifier + session naming

   Rule shape (repo convention):
     (1) Lazarus_FudModule_GodMode   — behavioural/critical: PE + >=3 FudModule
         telemetry strings (data-only rootkit, no BYOVD signature to key on)
     (2) Lazarus_Troy_Backdoor       — behavioural/critical: PE + Troy PDB
         fragment OR >=4 Troy command words + the CONNECTED handshake
     (3) Lazarus_SecurityPDF_Decoy   — high: the SumatraPDF decoy marker in a
         PDF/loader, guarded by the sideload DLL name
     (4) Lazarus_RelayShell_Webshell — high: PHP + the RelayShell operator id
     (5) Lazarus_DreamJob_C2         — IOC/high: 2026-wave C2 domains/IPs, with a
         count guard so a single mention in a report doesn't fire

   File-hash IOCs for this campaign are tracked out-of-band in the digest hash
   store (2026-08-12 digest); this rule keys on content, not hashes, to stay
   corpus-scannable.

   Attribution: DPRK-linked Lazarus Group (APT38 = financial arm). Consistent
   Operation Dream Job tradecraft + shared FudModule lineage (afd.sys:
   CVE-2024-38193, CVE-2025-60719, now CVE-2026-68820). Stated by Check Point;
   do not overstate beyond the vendor report.

   Related: [[wel1dropper-npm-rat]] (same digest week), [[turla-stockstay]]
   (state-actor implant tradecraft).
*/

import "pe"

private rule is_pe {
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule Lazarus_FudModule_GodMode {
    meta:
        description = "Lazarus FudModule kernel rootkit (v3.1) — god-mode telemetry + Smart App Control tamper"
        author = "synthetic-detections"
        date = "2026-08-12"
        severity = "critical"
        family = "operation-dream-job-lazarus"
        reference = "https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/"
    strings:
        $t1 = "enable_god_mode passed." ascii
        $t2 = "GetGodMode failed" ascii
        $t3 = "GetSystemHandle passed." ascii
        $t4 = "CreateRemoteProcess passed." ascii
        $t5 = "RemoteDllExecute passed." ascii
        $t6 = "SuspendDefender passed." ascii
        $sac = "VerifiedAndReputablePolicyState" ascii wide
        $vac = "ClearVaccine" ascii
    condition:
        is_pe and (3 of ($t*) or (2 of ($t*) and ($sac or $vac)))
}

rule Lazarus_Troy_Backdoor {
    meta:
        description = "Lazarus Troy backdoor — PDB fragment and command-word protocol"
        author = "synthetic-detections"
        date = "2026-08-12"
        severity = "critical"
        family = "operation-dream-job-lazarus"
        reference = "https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/"
    strings:
        $pdb = "\\Troy_Handle\\" ascii nocase
        $pdb2 = "Troy_Create_Dll_Tool" ascii
        $c1 = "ZIPDOWNLOAD" ascii
        $c2 = "DEFAULTSLEEP" ascii
        $c3 = "GET_CONFIG" ascii
        $c4 = "SET_CONFIG" ascii
        $c5 = "DRIVES" ascii
        $hs = "CONNECTED" ascii
    condition:
        is_pe and ( any of ($pdb*) or (4 of ($c*) and $hs) )
}

rule Lazarus_SecurityPDF_Decoy {
    meta:
        description = "Lazarus SecurityPDF trojanized viewer / decoy PDF — SumatraPDF encrypted marker + libmupdf sideload"
        author = "synthetic-detections"
        date = "2026-08-12"
        severity = "high"
        family = "operation-dream-job-lazarus"
        reference = "https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/"
    strings:
        $marker = "This document is encrypted with sumatrapdf reader!!!!!!!!!!!!!!" ascii
        $dll = "libmupdf.dll" ascii nocase
        $pdfhdr = "%PDF-"
    condition:
        $marker and ($dll or $pdfhdr at 0 or is_pe)
}

rule Lazarus_RelayShell_Webshell {
    meta:
        description = "Lazarus RelayShell PHP webshell — embedded operator identifier and session naming"
        author = "synthetic-detections"
        date = "2026-08-12"
        severity = "high"
        family = "operation-dream-job-lazarus"
        reference = "https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/"
    strings:
        $php = "<?php" ascii
        $id  = "D9hWnVEqdgzJ67/B8euS0yKCIMrw5jc:fGUX3AakLH2oYQRp" ascii
    condition:
        filesize < 200KB and $php and $id
}

rule Lazarus_DreamJob_C2 {
    meta:
        description = "Operation Dream Job 2026-wave C2 indicators (domains/IPs) — count-guarded"
        author = "synthetic-detections"
        date = "2026-08-12"
        severity = "high"
        family = "operation-dream-job-lazarus"
        reference = "https://research.checkpoint.com/2026/shattering-the-dream-when-a-job-offer-becomes-a-zero-day-attack/"
    strings:
        $d1 = "envell.xyz" ascii nocase
        $d2 = "enveil.online" ascii nocase
        $d3 = "uxtramine.org" ascii nocase
        $ip1 = "135.181.67.203" ascii
        $ip2 = "135.181.185.158" ascii
    condition:
        2 of them
}
