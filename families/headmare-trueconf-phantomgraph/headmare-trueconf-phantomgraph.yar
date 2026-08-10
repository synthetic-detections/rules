/*
   Head Mare — TrueConf supply-chain intrusion: PhantomCore / PhantomGraph
   ----------------------------------------------------------------------
   Kaspersky (disclosed 2026-08-08, activity found July 2026) attributes to the
   pro-Ukraine hacktivist group Head Mare a campaign against Russian organizations
   that used unpatched TrueConf Server as a supply-chain vector.

   Kill chain:
     - Unauthenticated access over default-open TCP 4307, chaining KLCERT-26-057 +
       KLCERT-26-058 to run code and escalate to NT AUTHORITY\SYSTEM.
     - Web shell dropped at public\js\locale.php (md5 4d27b4eb…523e).
     - The legitimate TrueConf Windows client installer replaced with trojanized
       builds (trueconf_windows_update.exe, md5 748c9f8c…207f) that side-load the
       PhantomCore backdoor as %LOCALAPPDATA%\TrueConf\Client\
       api-ms-win-crt-time-l1-1-0-2.dll.
     - PhantomGraph: a second backdoor comprising SysExcSvc.dll (C2 module) and
       SysReadSvc.dll installed under C:\Windows\System32\inetsrv\, registered as
       Windows services SysExcSvc / SysReadSvc, tasking over a Microsoft OneDrive
       account, using graphi-refresh.dat and share\input_*.txt / output_*.txt for
       file I/O, and dumping credentials from LSASS.
     - Linux ELF backdoors + a rootkit, persisted as services impersonating
       Acronis / OMI: /etc/systemd/system/omicluster.service and schedul2-bin.service
       (/opt/acronis/bin/schedul2-bin, /omi/bin/omicluster, /usr/lib64/libzvbi-tchain.so.2).

   Attribution: Head Mare (pro-Ukraine hacktivist, active vs Russia/Belarus).
   A separate April-2026 campaign against the same TrueConf flaws was tentatively
   tied to Chinese actors using Havoc — a different cluster; do not conflate.

   Rule shape:
     (1) HeadMare_PhantomGraph_Artifacts — behavioural/critical: the PhantomGraph
         DLL/service/path constellation with co-occurrence guard.
     (2) HeadMare_TrueConf_Linux_Persistence — behavioural/high: the masquerading
         Acronis/OMI Linux service + path artifacts.
     (3) HeadMare_TrueConf_IOC — IOC/high: hashes + web-shell/installer/registry
         pins with a co-occurrence guard.

   Siblings (supply-chain / trojanized-installer):
     [[ironworm-npm-worm]], [[famous-chollima-packagist]]

   Sources:
     https://securelist.ru/tr/head-mare-targets-trueconf-server-with-phantomcore/116557/
     https://www.bleepingcomputer.com/news/security/hackers-breach-trueconf-to-trojanize-client-installers-with-backdoors/
*/

import "pe"

rule HeadMare_PhantomGraph_Artifacts
{
    meta:
        description = "Head Mare PhantomGraph backdoor: SysExcSvc/SysReadSvc DLLs, inetsrv install path, OneDrive C2 tasking artifacts"
        author      = "synthetic-detections"
        date        = "2026-08-10"
        severity    = "critical"
        family      = "headmare-trueconf-phantomgraph"
        reference   = "https://securelist.ru/tr/head-mare-targets-trueconf-server-with-phantomcore/116557/"

    strings:
        $svc1  = "SysExcSvc.dll" ascii wide nocase
        $svc2  = "SysReadSvc.dll" ascii wide nocase
        $path1 = "\\System32\\inetsrv\\SysExcSvc.dll" ascii wide nocase
        $path2 = "\\System32\\inetsrv\\SysReadSvc.dll" ascii wide nocase
        $dat   = "graphi-refresh.dat" ascii wide nocase
        $io1   = "\\share\\input_" ascii wide nocase
        $io2   = "\\share\\output_" ascii wide nocase
        $clsid = "{0340F119-A598-4ed9-B0AC-6F6A12D3E755}" ascii wide nocase

    condition:
        uint16(0) == 0x5a4d and
        (
            (1 of ($path*)) or
            $clsid or
            (all of ($svc*) and ($dat or 1 of ($io*)))
        )
}

rule HeadMare_TrueConf_Linux_Persistence
{
    meta:
        description = "Head Mare Linux persistence masquerading as Acronis/OMI services (TrueConf campaign)"
        author      = "synthetic-detections"
        date        = "2026-08-10"
        severity    = "high"
        family      = "headmare-trueconf-phantomgraph"
        reference   = "https://securelist.ru/tr/head-mare-targets-trueconf-server-with-phantomcore/116557/"

    strings:
        $s1 = "/etc/systemd/system/omicluster.service" ascii
        $s2 = "/etc/systemd/system/schedul2-bin.service" ascii
        $s3 = "/opt/acronis/bin/schedul2-bin" ascii
        $s4 = "/omi/bin/omicluster" ascii
        $s5 = "/usr/lib64/libzvbi-tchain.so.2" ascii
        $s6 = "/var/tmp/cx2" ascii

    condition:
        2 of them
}

rule HeadMare_TrueConf_IOC
{
    meta:
        description = "Head Mare TrueConf campaign IOC pins: web shell, trojanized installer, PhantomCore/PhantomGraph sample hashes"
        author      = "synthetic-detections"
        date        = "2026-08-10"
        severity    = "high"
        family      = "headmare-trueconf-phantomgraph"
        reference   = "https://securelist.ru/tr/head-mare-targets-trueconf-server-with-phantomcore/116557/"

    strings:
        $webshell = "public/js/locale.php" ascii wide nocase
        $inst     = "trueconf_windows_update.exe" ascii wide nocase
        $sideload = "api-ms-win-crt-time-l1-1-0-2.dll" ascii wide nocase
        // MD5 pins (PhantomCore / PhantomGraph / web shell / installer), lowercase hex
        $h01 = "4d27b4eb1c5dbb3d8160f29b8119523e" ascii nocase
        $h02 = "748c9f8cb1065000616204935f96207f" ascii nocase
        $h03 = "c5a460e4e68a088f6e51b2c6474642ec" ascii nocase
        $h04 = "489f43be558b2679284ceabed7adc4f3" ascii nocase
        $h05 = "dd1fd2b459b97b7d59375cb8383cd19a" ascii nocase
        $h06 = "0e4541c3153ec5ed01497f19cf4f63d0" ascii nocase
        $h07 = "12d4e8f5295f2ef7e0f9bfc0f4830939" ascii nocase
        $h08 = "7f267006cac10f341c356b62fe493527" ascii nocase
        $h09 = "ee2861d5965e8730708cd1da8a93fa4c" ascii nocase

    condition:
        (2 of ($webshell, $inst, $sideload)) or any of ($h*)
}
