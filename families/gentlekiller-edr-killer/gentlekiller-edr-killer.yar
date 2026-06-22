/*
   GentleKiller EDR-killer framework (ESET deep-dive 2026-06-17)
   ---------------------------------------------------------------
   Centralized defense-evasion toolkit maintained by the Gentlemen
   ransomware-as-a-service operation and distributed to affiliates.
   At least 8 GentleKiller variants, each impersonating a different
   legitimate security product (Kaspersky, FACEIT, Valorant, Javelin,
   WatchDog, Network Blocker, Cleaner, G11) plus 3 third-party EDR
   killers (HexKiller, ThrottleBlood, HavocKiller) sourced from rival
   gangs. All use BYOVD to load vulnerable/malicious kernel drivers.

   Kills 400+ processes across 48 security products. Filenames carry
   fabricated version info, invalid digital signatures, and icons
   from impersonated vendors. Many variants Enigma- or Themida-packed.

   Staging artifact: payloads consistently placed in a directory named
   "GentlemenCollection" — observed across multiple unrelated intrusions.

   Rules target post-unpacking / memory scans (Rules 1-2) and the
   staging-directory deployment pattern (Rule 3). Packed variants will
   NOT match Rules 1-2 until dumped or memory-scanned.

   Rule 1 — Behavioral: EDR process kill-list density — high count of
            security vendor process names co-occurring in a single binary.
   Rule 2 — Structural: variant PE characteristics — impersonated vendor
            names in version info alongside BYOVD driver filenames.
   Rule 3 — IOC: staging directory name, known variant filenames,
            known driver filenames, OxideHarvest credential stealer.

   Sources:
     https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/
     https://www.bleepingcomputer.com/news/security/gentlemen-ransomware-uses-multiple-edr-killers-to-disable-defenses/
     https://github.com/eset/malware-ioc/blob/master/gentlemen/README.adoc
*/

import "pe"

rule GentleKiller_EDR_KillList
{
    meta:
        description = "GentleKiller EDR-killer — high density of security vendor process names targeted for termination (post-unpack / memory)"
        author      = "synthetic-detections"
        date        = "2026-06-22"
        severity    = "critical"
        family      = "gentlekiller-edr-killer"
        reference   = "https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/"

    strings:
        // CrowdStrike processes
        $edr_cs1 = "CSFalconService" ascii nocase
        $edr_cs2 = "csfalconcontainer" ascii nocase
        $edr_cs3 = "CSAgent" ascii nocase

        // SentinelOne processes
        $edr_s1a = "SentinelAgent" ascii nocase
        $edr_s1b = "SentinelHelperService" ascii nocase
        $edr_s1c = "SentinelStaticEngine" ascii nocase

        // Microsoft Defender processes
        $edr_def1 = "MsMpEng" ascii nocase
        $edr_def2 = "MsSense" ascii nocase
        $edr_def3 = "SenseIR" ascii nocase

        // Sophos processes
        $edr_soph1 = "SophosHealth" ascii nocase
        $edr_soph2 = "SophosCleanM" ascii nocase
        $edr_soph3 = "SophosFileScanner" ascii nocase

        // Palo Alto Cortex XDR
        $edr_pa1 = "CylanceSvc" ascii nocase
        $edr_pa2 = "cyserver" ascii nocase
        $edr_pa3 = "Traps" ascii nocase

        // Carbon Black
        $edr_cb1 = "RepMgr" ascii nocase
        $edr_cb2 = "CbDefense" ascii nocase

        // ESET
        $edr_eset1 = "ekrn" ascii nocase
        $edr_eset2 = "egui" ascii nocase

        // Bitdefender
        $edr_bd1 = "bdagent" ascii nocase
        $edr_bd2 = "bdservicehost" ascii nocase

        // Kaspersky
        $edr_kas1 = "avpui" ascii nocase
        $edr_kas2 = "avp" ascii nocase

        // Elastic
        $edr_el1 = "elastic-agent" ascii nocase
        $edr_el2 = "elastic-endpoint" ascii nocase

        // Trend Micro
        $edr_tm1 = "Ntrtscan" ascii nocase
        $edr_tm2 = "PccNTMon" ascii nocase

        // Qualys
        $edr_ql1 = "QualysAgent" ascii nocase

        // Huntress
        $edr_hu1 = "HuntressAgent" ascii nocase

        // Generic AV service enumeration pattern — DeviceIoControl
        // for kernel driver interaction (BYOVD exploitation)
        $api_ioctl = "DeviceIoControl" ascii

    condition:
        // PE binary, reasonable size for an EDR killer
        uint16(0) == 0x5A4D
        and filesize > 20KB and filesize < 10MB
        and (
            // 8+ distinct EDR vendor process names = kill-list behavior;
            // no legitimate application references this many competing
            // security products by their internal process names
            8 of ($edr_*)
            or
            // 5+ EDR names + kernel driver interaction API
            (5 of ($edr_*) and $api_ioctl)
        )
}

rule GentleKiller_Variant_Artifacts
{
    meta:
        description = "GentleKiller variant — impersonated vendor PE with BYOVD driver filenames embedded"
        author      = "synthetic-detections"
        date        = "2026-06-22"
        severity    = "critical"
        family      = "gentlekiller-edr-killer"
        reference   = "https://github.com/eset/malware-ioc/blob/master/gentlemen/README.adoc"

    strings:
        // BYOVD driver filenames embedded in the killer binaries
        // (loaded as Windows services for kernel access)
        $drv_eb       = "eb.sys" ascii
        $drv_nsec     = "nseckrnl.sys" ascii
        $drv_vgk      = "vgk.sys" ascii wide
        $drv_stpm_old = "stpm_old.sys" ascii
        $drv_stpm_new = "stpm_new.sys" ascii
        $drv_dmx      = "dmx.sys" ascii
        $drv_360      = "360netmon_wfp.sys" ascii
        $drv_imf      = "IMFForceDelete" ascii
        $drv_g11      = "G11.sys" ascii
        $drv_throttle = "ThrottleBlood.sys" ascii
        $drv_havoc    = "havoc.sys" ascii
        $drv_baidu    = "googleApiUtil64.sys" ascii

        // Variant executable naming patterns
        $var_kasp    = "Kasps.exe" ascii wide
        $var_faceit  = "FaceIT1.exe" ascii wide
        $var_valo    = "Valorant2.exe" ascii wide
        $var_javelin = "EAAntiCheatLight.exe" ascii wide
        $var_bitd    = "BitD1.exe" ascii wide
        $var_mb2     = "MB2.exe" ascii wide
        $var_deletor = "Deletor.exe" ascii wide
        $var_symantec = "Symantec.exe" ascii wide

        // OxideHarvest credential stealer (affiliate tooling)
        $oxide1 = "buildx641.exe" ascii wide
        $oxide2 = "buildx64.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 20KB and filesize < 10MB
        and (
            // Any BYOVD driver filename + any variant executable name
            (any of ($drv_*) and any of ($var_*))
            or
            // 2+ driver filenames in a single binary (loader or config)
            2 of ($drv_*)
            or
            // OxideHarvest alongside any driver (affiliate kit bundle)
            (any of ($oxide*) and any of ($drv_*))
        )
}

rule GentleKiller_IOC
{
    meta:
        description = "Static IOC sweep — GentlemenCollection staging, known filenames, driver artifacts, OxideHarvest"
        author      = "synthetic-detections"
        date        = "2026-06-22"
        severity    = "high"
        family      = "gentlekiller-edr-killer"
        reference   = "https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/"

    strings:
        // Primary staging directory — consistent across unrelated
        // intrusions; high-confidence triage artifact
        $staging = "GentlemenCollection" ascii wide nocase

        // GentleKiller variant filenames (all detected as Win64/KillAV.EA)
        $fn_kasps      = "Kasps" ascii wide
        $fn_faceit     = "FaceIT1" ascii wide
        $fn_valorant   = "Valorant2" ascii wide
        $fn_easolo     = "EASolo2Light" ascii wide
        $fn_easolo1    = "EASOLO1clear" ascii wide
        $fn_eaanticheat = "EAAntiCheatLight" ascii wide
        $fn_bitd       = "BitD1" ascii wide
        $fn_mb2        = "MB2" ascii wide
        $fn_deletor    = "Deletor" ascii wide
        $fn_symantec_v = "Symantec.exe" ascii wide

        // Third-party EDR killers bundled by Gentlemen
        $fn_hexkiller  = "Avast.exe" ascii wide
        $fn_throttle   = "Sent.exe" ascii wide
        $fn_havockill  = "Sophos.exe" ascii wide

        // BYOVD driver names (less specific individually, but
        // together indicate the GentleKiller ecosystem)
        $drv_eb       = "eb.sys" ascii
        $drv_nsec     = "nseckrnl.sys" ascii
        $drv_g11      = "G11.sys" ascii
        $drv_throttle = "ThrottleBlood.sys" ascii
        $drv_havoc    = "havoc.sys" ascii
        $drv_baidu    = "googleApiUtil64.sys" ascii

        // OxideHarvest credential stealer
        $oxide = "buildx641.exe" ascii wide

    condition:
        filesize < 50MB
        and (
            // Staging directory name (strongest single indicator)
            $staging
            or
            // 3+ variant filenames in same file (incident report,
            // config, or toolkit archive)
            3 of ($fn_*)
            or
            // 3+ driver names co-occurring
            3 of ($drv_*)
            or
            // OxideHarvest + any staging or variant indicator
            ($oxide and ($staging or any of ($fn_*) or any of ($drv_*)))
        )
}
