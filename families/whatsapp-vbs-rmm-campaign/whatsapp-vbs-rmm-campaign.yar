/*
   WhatsApp VBScript → ManageEngine RMM campaign (Kaspersky GReAT, 2026-06-22)
   ---------------------------------------------------------------------------
   Active campaign delivering VBScript droppers via compromised WhatsApp
   accounts. Lures disguised as invoices, debt notices, and financial
   statements in English, Portuguese, French, German, and Malay.

   Three-stage chain:
     Stage 1 — VBS lure creates working directory under
               C:\Users\Public\Documents\ (Temp_*, MSUpdate_*, Sys*, Data*)
     Stage 2 — Two VBS scripts: one disables UAC (ConsentPromptBehaviorAdmin=0),
               other downloads ZIP with ManageEngine Endpoint Central package
     Stage 3 — setup1.vbs silently installs ManageEngine agent via msiexec +
               MST transform; installs attacker root CA (DMRootCA.crt) so the
               agent trusts the attacker's management server

   Evasion: char-by-char string concatenation, renamed LOLBins (curl/bitsadmin
   given DLL-like filenames), Zone.Identifier ADS removal, Simplified Chinese
   comments mimicking Windows Update components, junk padding.

   Infrastructure overlaps with ValleyRAT/Gh0st RAT (202.61.160.201).
   Targeting: Malaysia (~80%), Brazil, India, Mexico, Singapore, UK, Spain,
   Taiwan, Australia, Russia, Vietnam.

   Rule 1 — Technique: VBScript UAC bypass + ManageEngine silent install pattern
   Rule 2 — Artifact: ManageEngine deployment package with attacker certificates
   Rule 3 — IOC: campaign-specific domains, staging paths, and lure filenames

   Sources:
     https://securelist.com/whatsapp-vbs-rmm-campaign/120290/
     https://securityaffairs.com/194031/malware/whatsapp-malware-campaign-hijacks-trust-installs-legitimate-admin-tools.html
*/

rule WhatsApp_VBS_RMM_Technique
{
    meta:
        description = "VBScript dropper — UAC bypass via ConsentPromptBehaviorAdmin + ManageEngine silent install chain"
        author      = "synthetic-detections"
        date        = "2026-06-23"
        severity    = "critical"
        family      = "whatsapp-vbs-rmm-campaign"
        reference   = "https://securelist.com/whatsapp-vbs-rmm-campaign/120290/"

    strings:
        // UAC bypass — registry path for ConsentPromptBehaviorAdmin
        $uac_key   = "ConsentPromptBehaviorAdmin" ascii wide nocase
        $uac_hive  = "CurrentVersion\\Policies\\System" ascii wide nocase

        // ManageEngine silent install indicators
        $msi_exec  = "msiexec" ascii wide nocase
        $msi_agent = "UEMSAgent" ascii wide nocase
        $msi_setup = "setup1.vbs" ascii wide nocase

        // Working directory patterns under Public\Documents
        $dir_temp     = "\\Public\\Documents\\Temp_" ascii wide nocase
        $dir_msupdate = "\\Public\\Documents\\MSUpdate_" ascii wide nocase
        $dir_sys      = "\\Public\\Documents\\Sys" ascii wide nocase
        $dir_data     = "\\Public\\Documents\\Data" ascii wide nocase

        // Zone.Identifier ADS removal (MOTW bypass)
        $motw_del = "Zone.Identifier" ascii wide

        // Shell.Application CopyHere for ZIP extraction
        $shell_app = "Shell.Application" ascii wide nocase
        $copy_here = "CopyHere" ascii wide nocase

        // VBScript engine marker
        $createobj = "CreateObject" ascii wide nocase

    condition:
        filesize < 5MB
        and $createobj
        and (
            // UAC bypass + ManageEngine install in same script
            (any of ($uac_*) and any of ($msi_*))
            or
            // Working directory creation + ZIP extraction + UAC tampering
            (any of ($dir_*) and $shell_app and $copy_here and any of ($uac_*))
            or
            // ManageEngine agent install + MOTW bypass + staging directory
            (any of ($msi_*) and $motw_del and any of ($dir_*))
        )
}

rule WhatsApp_VBS_RMM_ManageEngine_Package
{
    meta:
        description = "Attacker-crafted ManageEngine Endpoint Central deployment package with rogue CA certificates"
        author      = "synthetic-detections"
        date        = "2026-06-23"
        severity    = "high"
        family      = "whatsapp-vbs-rmm-campaign"
        reference   = "https://securelist.com/whatsapp-vbs-rmm-campaign/120290/"

    strings:
        // ManageEngine agent MSI and transform
        $me_msi   = "UEMSAgent.msi" ascii wide
        $me_mst   = "UEMSAgent.mst" ascii wide

        // Attacker-installed root CA certificate files
        $cert_root   = "DMRootCA.crt" ascii wide
        $cert_server = "DMRootCA-Server.crt" ascii wide

        // Agent server configuration
        $config_json = "DCAgentServerInfo.json" ascii wide

        // VBS installer script in the package
        $setup_vbs = "setup1.vbs" ascii wide
        $setup_bat = "setup.bat" ascii wide

    condition:
        filesize < 50MB
        and (
            // The deployment package: MSI + attacker CA certs + config
            ($me_msi and any of ($cert_*) and $config_json)
            or
            // MSI + MST transform + installer script (ZIP contents)
            ($me_msi and $me_mst and ($setup_vbs or $setup_bat))
            or
            // Rogue CA certs + agent config (even without MSI name visible)
            ($cert_root and $cert_server and $config_json)
        )
}

rule WhatsApp_VBS_RMM_IOC
{
    meta:
        description = "Static IOC sweep — campaign domains, staging paths, lure filenames, cloud payload buckets"
        author      = "synthetic-detections"
        date        = "2026-06-23"
        severity    = "high"
        family      = "whatsapp-vbs-rmm-campaign"
        reference   = "https://securelist.com/whatsapp-vbs-rmm-campaign/120290/"

    strings:
        // C2 / staging domains
        $dom_baskwms  = "baskwms.top" ascii wide nocase
        $dom_msopsa   = "msopsa.top" ascii wide nocase
        $dom_shoppes  = "shoppes.help" ascii wide nocase
        $dom_shaasl   = "shaaslong.one" ascii wide nocase
        $dom_baoxis   = "baoxis.cc" ascii wide nocase

        // Alibaba Cloud OSS payload buckets
        $oss_baolong = "baolongwes.oss-ap-southeast-1" ascii wide nocase
        $oss_sdcwww  = "sdcwww.oss-ap-southeast-1" ascii wide nocase

        // AWS S3 payload buckets
        $s3_baoyuw   = "baoyuw2s.s3.ap-southeast-1" ascii wide nocase
        $s3_hksha    = "hksha3.s3.ap-southeast-1" ascii wide nocase
        $s3_sjdkjj   = "sjdkjj23.s3.ap-southeast-1" ascii wide nocase
        $s3_xijkwm   = "xijkwm2.s3.ap-southeast-1" ascii wide nocase
        $s3_yifubafu = "yifubafu.s3.ap-southeast-1" ascii wide nocase

        // Backblaze B2 payload buckets
        $b2_caiwu  = "caiwuascw.s3.us-east-005.backblazeb2" ascii wide nocase
        $b2_facaia = "facaia.s3.us-east-005.backblazeb2" ascii wide nocase

        // Internal/dev payload filenames
        $dev_sleestak = "sleestak_payload_1" ascii wide
        $dev_payload  = "payload_1.vbs" ascii wide
        $dev_home3    = "home3.vbs" ascii wide
        $dev_btksfmsi = "btksfmsi.vbs" ascii wide
        $dev_zipats   = "zipats.vbs" ascii wide

        // Campaign-specific lure filenames
        $lure_penyata = "Penyata bank.vbs" ascii wide
        $lure_semak   = "Sila semak bil anda.vbs" ascii wide
        $lure_extrato = "Extrato de Conciliacao.vbs" ascii wide
        $lure_aviso   = "Aviso de divida.vbs" ascii wide
        $lure_umsatz  = "Umsatzsteuer-Nullsatz" ascii wide

    condition:
        filesize < 50MB
        and (
            any of ($dom_*)
            or any of ($oss_*, $s3_*, $b2_*)
            or 2 of ($dev_*)
            or 2 of ($lure_*)
        )
}
