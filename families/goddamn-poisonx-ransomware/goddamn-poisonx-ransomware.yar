/*
   GodDamn ransomware + PoisonX signed BYOVD driver
   --------------------------------------------------------------------------
   Reported 2026-07-09 (Symantec Threat Hunter Team / Broadcom; also The Hacker
   News). GodDamn (first seen in the wild 2026-05-21) is a rebrand of the Beast
   ransomware, itself an evolution of the Delphi "Monster" family (March 2022);
   Broadcom tracks the developer as "Hyadina".

   The escalation is defense evasion via PoisonX — a malicious kernel driver
   (g11.sys) that its operators got Microsoft to sign under "Microsoft Windows
   Hardware Compatibility Publisher". PoisonX terminates security-product
   processes and strips user-mode API hooks, blinding endpoint tools (classic
   bring-your-own-vulnerable/malicious-driver, BYOVD).

   Observed intrusion (early June 2026): AnyDesk for remote access (two services
   "AnyDeskService" and "AnyDesk_D-Drive Service" pointing at D:\ad_data),
   PsExec for lateral movement, and a 14-tool NirSoft-based credential-harvest
   kit (Mimikatz, WebBrowserPassView, ChromePass, PasswordFox, VNCPassView,
   MailPassView, CredentialsFileView, WirelessKeyView, ...). The encryptor
   appends ".God8Damn" (or the victim org name) to encrypted files.

   Rules: (1) the ransomware binary by its distinctive extension + GUI encrypter
   name gated on a PE; (2) the PoisonX driver by filename + the abused signer,
   gated on a native/driver PE so the common signer string cannot fire alone;
   (3) hard host/network IOCs (AnyDesk service+path combo, C2 relays). The bare
   AnyDesk service name and the signer string are legitimate on their own and are
   therefore never allowed to match in isolation. SHA256 listed for reference.

   Siblings (BYOVD / ransomware / destructive):
     [[gentlekiller-edr-killer]], [[prinz-eugen-ransomware]],
     [[gigawiper-destructive-backdoor]]

   Sources:
     https://www.security.com/blog-post/goddamn-ransomware-beast-rebrand
     https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html

   Known samples (SHA256):
     e097f3b445b63b07afacde8d6a67f0be654dd51e228a3610fb0710a1f7e29a69  (encrypter-windows-gui-x86.exe)
     2d91a78e739891c9854c254f5b2a6b84c0e167dfa253466cbccd2cdd1c20145d  (g11.sys / PoisonX)
*/

rule GodDamn_Ransomware_Binary
{
    meta:
        description = "GodDamn ransomware (Beast/Monster rebrand by Hyadina) — .God8Damn extension marker and GUI encrypter name in a PE"
        author      = "synthetic-detections"
        date        = "2026-07-10"
        severity    = "critical"
        family      = "goddamn-poisonx-ransomware"
        reference   = "https://www.security.com/blog-post/goddamn-ransomware-beast-rebrand"

    strings:
        $ext1  = ".God8Damn" ascii wide
        $ext2  = "God8Damn" ascii wide
        $enc   = "encrypter-windows-gui-x86.exe" ascii wide nocase
        // Beast/Monster lineage supporting markers
        $b1    = "Beast" ascii wide
        $b2    = "Monster" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 30MB and (
            $ext1
            or $enc
            or ($ext2 and (any of ($b*)))
        )
}

rule PoisonX_Signed_BYOVD_Driver
{
    meta:
        description = "PoisonX malicious kernel driver (g11.sys) abused by GodDamn — killer driver signed via 'Microsoft Windows Hardware Compatibility Publisher'; signer never matches alone"
        author      = "synthetic-detections"
        date        = "2026-07-10"
        severity    = "critical"
        family      = "goddamn-poisonx-ransomware"
        reference   = "https://thehackernews.com/2026/07/goddamn-ransomware-uses-poisonx-driver.html"

    strings:
        $drv    = "g11.sys" ascii wide nocase
        $signer = "Microsoft Windows Hardware Compatibility Publisher" ascii wide
        // driver process-kill / hook-removal surface (supporting)
        $k1     = "ZwTerminateProcess" ascii
        $k2     = "ObRegisterCallbacks" ascii
        $k3     = "PsSetCreateProcessNotifyRoutine" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and (
            // the driver filename is specific enough with any driver context
            ($drv and (any of ($k*) or $signer))
            // the abused signer only counts alongside kernel-kill behaviour
            or ($signer and 2 of ($k*))
        )
}

rule GodDamn_IOC
{
    meta:
        description = "GodDamn intrusion IOCs — AnyDesk masquerade service+path combo and AnyDesk relay C2 addresses"
        author      = "synthetic-detections"
        date        = "2026-07-10"
        severity    = "high"
        family      = "goddamn-poisonx-ransomware"
        reference   = "https://www.security.com/blog-post/goddamn-ransomware-beast-rebrand"

    strings:
        // distinctive second AnyDesk service + its data dir (legit AnyDesk uses neither)
        $svc     = "AnyDesk_D-Drive Service" ascii wide
        $addata  = "D:\\ad_data" ascii wide nocase
        // AnyDesk relay C2 addresses observed in the intrusion
        $c2_1    = "15.235.230.188" ascii wide
        $c2_2    = "185.229.191.39" ascii wide
        $c2_3    = "141.95.145.210" ascii wide
        $c2_4    = "162.19.171.150" ascii wide

    condition:
        filesize < 30MB and (
            $svc
            or $addata
            or 2 of ($c2_*)
        )
}
