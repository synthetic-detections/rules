/*
   SEO-poisoned ScreenConnect -> AsyncRAT ("FlowProxy Monitor V3")
   (disclosed 2026-07-01; Kaspersky + Hunt.io — unattributed, financially motivated)
   -----------------------------------------------------------------------
   A long-running, "massive, multi-domain, multi-language" campaign (some
   infrastructure registered Aug 2025 - Mar 2026) that distributes trojanized
   installers for popular software (OBS Studio, DNS Jumper, DS4Windows,
   Bandicam) via 90+ SEO-poisoned / spoofed download sites localized across
   ~10 languages.

   Kill chain (composited from both reports):
     - A signed Microsoft install.exe side-loads a rogue install.res.1033.dll
       (DLL side-loading) which deploys a ScreenConnect (ConnectWise RMM)
       client as the implant.
     - ScreenConnect runs a PowerShell loader (Skype.ps1, ~235 KB) that adds
       Microsoft Defender exclusions, disables UAC (EnableLUA=0), and stages a
       VBScript (Ab.vbs / Ab.js) plus encoded blobs (pe.txt AMSI bypass,
       q.txt config, 1.txt payload, logs.idk/logs.idr).
     - A native injector (libPK.dll, exports Execute) injects the final
       AsyncRAT build labelled internally "FlowProxy Monitor V3" into
       AppLaunch.exe. That build carries a keylogger, clipboard monitor and a
       16-currency crypto clipper.
     - Persistence via scheduled tasks "SystemInstallTask" (10 min) and
       "3losh" (2 min). Delivery also seen via ClickOnce
       (event_support-pdf.Client.exe) and a Microsoft.lnk shortcut.

   NOTE: AsyncRAT and ScreenConnect are both commodity/legitimate; these rules
   deliberately anchor on campaign-specific artifacts (scheduled-task names,
   the internal build label, the side-load DLL name, the loader-chain
   filenames, and the tracked C2 set) rather than generic AsyncRAT or
   ScreenConnect strings, so a normal ScreenConnect deployment does not match.

   Rule 1 — Behavioral: loader/injector chain + AsyncRAT config artifacts.
   Rule 2 — Structural: multi-stage loader script/artifact shape.
   Rule 3 — IOC: C2 IPs, domains, file hashes, loader filenames.

   Sources:
     https://hunt.io/blog/asyncrat-screenconnect-open-directory-campaigns
     https://thehackernews.com/2026/07/seo-poisoned-software-sites-abuse.html
     https://www.scworld.com/brief/screenconnect-used-to-deploy-asyncrat-in-widespread-campaign
*/

rule AsyncRAT_ScreenConnect_SEO_Behavior
{
    meta:
        description = "SEO-poisoned ScreenConnect->AsyncRAT loader/injector chain — side-load DLL, PowerShell loader that disables Defender/UAC, libPK injector into AppLaunch, FlowProxy Monitor V3 build, scheduled-task persistence"
        author      = "synthetic-detections"
        date        = "2026-07-02"
        severity    = "critical"
        family      = "asyncrat-screenconnect-seo"
        reference   = "https://hunt.io/blog/asyncrat-screenconnect-open-directory-campaigns"

    strings:
        // Internal AsyncRAT build label unique to this campaign
        $build_label = "FlowProxy Monitor V3" ascii wide

        // Scheduled-task persistence names
        $task_install = "SystemInstallTask" ascii wide
        $task_3losh   = "3losh" ascii wide

        // DLL side-load: rogue resource DLL bundled with signed install.exe
        $sideload_dll = "install.res.1033.dll" ascii wide nocase

        // Loader / injector chain filenames
        $loader_ps = "Skype.ps1" ascii wide nocase
        $injector  = "libPK.dll" ascii wide nocase
        $inject_tg = "AppLaunch.exe" ascii wide nocase
        $lnk       = "Microsoft.lnk" ascii wide nocase
        $vbs       = "Ab.vbs" ascii wide nocase

        // Defense evasion performed by the PowerShell loader
        $def_excl  = "Add-MpPreference" ascii wide nocase
        $def_path  = "-ExclusionPath" ascii wide nocase
        $uac_off   = "EnableLUA" ascii wide nocase
        $amsi      = "AmsiScanBuffer" ascii wide nocase
        $ps_hidden = "-w hidden" ascii wide nocase
        $ps_bypass = "-ep bypass" ascii wide nocase

        // ScreenConnect implant (only ever used in combination below)
        $sc_client = "screenconnect.client.exe" ascii wide nocase

    condition:
        filesize < 20MB
        and (
            // Path 1: the internal build label is campaign-unique
            $build_label
            or
            // Path 2: both scheduled-task persistence names
            ($task_install and $task_3losh)
            or
            // Path 3: side-load DLL used to stand up the ScreenConnect implant
            ($sideload_dll and ($sc_client or $def_excl or $uac_off))
            or
            // Path 4: injector chain — native injector into AppLaunch
            ($injector and $inject_tg and ($loader_ps or $vbs or $lnk))
            or
            // Path 5: PowerShell loader behavior — Defender exclusion +
            // UAC/AMSI tampering + hidden/bypass execution
            (
                $def_excl and $def_path
                and any of ($uac_off, $amsi)
                and any of ($ps_hidden, $ps_bypass)
            )
        )
}

rule AsyncRAT_ScreenConnect_SEO_LoaderShape
{
    meta:
        description = "Multi-stage loader artifact shape — VBS/PowerShell/LNK launchers plus the .txt/.idk/.idr staging blobs used to assemble the AsyncRAT payload"
        author      = "synthetic-detections"
        date        = "2026-07-02"
        severity    = "high"
        family      = "asyncrat-screenconnect-seo"
        reference   = "https://hunt.io/blog/asyncrat-screenconnect-open-directory-campaigns"

    strings:
        // Stage filenames observed across the open directories
        $ab_vbs   = "Ab.vbs" ascii wide nocase
        $ab_js    = "Ab.js" ascii wide nocase
        $skype_ps = "Skype.ps1" ascii wide nocase
        $ms_lnk   = "Microsoft.lnk" ascii wide nocase
        $libpk    = "libPK.dll" ascii wide nocase

        // Encoded staging blobs pulled by the loader
        $pe_txt   = "pe.txt" ascii wide nocase
        $q_txt    = "q.txt" ascii wide nocase
        $one_txt  = "1.txt" ascii wide nocase
        $logs_idk = "logs.idk" ascii wide nocase
        $logs_idr = "logs.idr" ascii wide nocase

        // ClickOnce delivery artifact
        $clickonce = "event_support-pdf.Client.exe" ascii wide nocase

        // Injection target for the assembled RAT
        $applaunch = "AppLaunch.exe" ascii wide nocase

    condition:
        filesize < 20MB
        and (
            // ClickOnce dropper filename is campaign-specific
            $clickonce
            or
            // 3+ distinct loader-stage filenames co-located
            3 of ($ab_vbs, $ab_js, $skype_ps, $ms_lnk, $libpk, $pe_txt, $q_txt, $one_txt, $logs_idk, $logs_idr)
            or
            // Injector library + injection target + any staging blob
            ($libpk and $applaunch and any of ($pe_txt, $q_txt, $one_txt, $logs_idk, $logs_idr))
        )
}

rule AsyncRAT_ScreenConnect_SEO_IOC
{
    meta:
        description = "Static IOC sweep — tracked C2 IPs, disposable domains, delivery hosts, and file hashes (Hunt.io) for the SEO-poisoned ScreenConnect/AsyncRAT campaign"
        author      = "synthetic-detections"
        date        = "2026-07-02"
        severity    = "high"
        family      = "asyncrat-screenconnect-seo"
        reference   = "https://hunt.io/blog/asyncrat-screenconnect-open-directory-campaigns"

    strings:
        // C2 / staging IPs
        $ip1 = "176.65.139.119" ascii wide
        $ip2 = "45.74.16.71" ascii wide
        $ip3 = "164.68.120.30" ascii wide
        $ip4 = "78.161.14.229" ascii wide
        $ip5 = "78.162.57.179" ascii wide
        $ip6 = "88.229.27.40" ascii wide
        $ip7 = "185.208.159.71" ascii wide
        $ip8 = "94.154.173.145" ascii wide

        // Delivery / redirect / disposable domains
        $dom1 = "dual.saltuta.com" ascii wide nocase
        $dom2 = "verify.uniupdate.net" ascii wide nocase
        $dom3 = "galusa.ac.mz" ascii wide nocase
        $dom4 = "dp.vdpanxxs.top" ascii wide nocase
        $dom5 = "sc.vdpanxxs.top" ascii wide nocase
        $dom6 = "vixgstxpnl.top" ascii wide nocase

        // File hashes (SHA-256)
        $h_abvbs   = "6142295a7f7ce60b86738e07d79b72d5a3edb3d5915aa9fb6c81ea752a9cd229" ascii nocase
        $h_abvbs2  = "c7936cc04631bc9d4ed7a9be3a5638193fac57cb3ccfa7ce037aa2b0fe24cad7" ascii nocase
        $h_lnk     = "521769c955761f7fc625eae2006f4dabcf36ce3169309e0ad111e7b7b29748af" ascii nocase
        $h_skype   = "54b762e05af1a1138786a78e9936d63f4e419bbeb0d116c2cee7376566420382" ascii nocase
        $h_skype2  = "8d5b8061b3f6b899583bbf20e78c13bb2b44b9dff4c6c302c8c278725dc5a34d" ascii nocase
        $h_libpk   = "b97d0a646c8aece8f5c4cedb26da808ec5104038c7871ad0481f75df7a75c59d" ascii nocase
        $h_scc     = "701e702f91942acef4d6afdda2abf70ed8618cde2f2ef3b174b092373c63c033" ascii nocase
        $h_1txt    = "ff529b5e54b079ff9a449e933b6042c2403f15d0de9ee9dbfb0c51e56bf13fad" ascii nocase
        $h_petxt   = "1f7b509db8424453b8bb3a45053f3bc47f98414b168a67f253c10f0f6fb83936" ascii nocase
        $h_qtxt    = "5705e818447ec8f7c480a2bf28337b002d66b293b7450b7a993bf26ac9fee60f" ascii nocase
        $h_police  = "0736e890f62b920c4489928254d5c0e5e67584dfb1c8649f08b62e400d28e882" ascii nocase

        // File hashes (MD5)
        $m_stub    = "cd5207483b78ef50d3dbd3f6a36d2a98" ascii nocase
        $m_clickon = "c596910b65fb3af81b9ca67ce11ebcc3" ascii nocase

    condition:
        filesize < 50MB
        and (
            any of ($ip*)
            or any of ($dom*)
            or any of ($h_*)
            or any of ($m_*)
        )
}
