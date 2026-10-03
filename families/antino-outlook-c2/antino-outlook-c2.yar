/*
   Antino — Rust backdoor using Outlook / OneDrive C2, 2026-10-03
   ---------------------------------------------------------------
   Actor UAT-11587 deploys a Rust-compiled backdoor ("Antino") that
   communicates via Microsoft Outlook (Graph API) and OneDrive for C2.
   Delivery chain: GatherOsState.exe (legitimate Windows binary) side-loads
   slc.dll (Antino DLL proxy), with a .NET downloader stage
   (TestAssembly.dll). The backdoor uses Outlook emails with a subject
   prefix "command_req_" to receive commands and exfiltrate data.
   Build metadata reveals zh-CN locale and UTC+08:00 timezone.
   Infrastructure: rsproxy[.]cn (Rust crate mirror, used as staging),
   d32tpl7xt7175h.cloudfront.net (payload delivery CDN).

   Related families: [[sauron-loader]], [[star-blizzard-redflick]].

   Rule 1 — behavioural: DLL sideloading pattern — GatherOsState.exe +
            slc.dll co-location with Outlook C2 subject prefix.
   Rule 2 — IOC sweep: C2 domains, DLL names, .NET loader, Outlook
            subject prefix, build metadata (co-occurrence guarded).
   Rule 3 — specimen pin: structural anchor for the Antino DLL (PE with
            Rust compilation markers + Outlook Graph API strings).

   Sources:
     https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html
*/

import "pe"

rule Antino_DllSideload_Behavioral {
  meta:
    description = "Antino backdoor behavioural — DLL sideloading via GatherOsState.exe with Outlook Graph API C2 subject prefix"
    author = "synthetic-detections"
    date = "2026-10-03"
    severity = "critical"
    family = "antino-outlook-c2"
    reference = "https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html"
  strings:
    $sideload_host = "GatherOsState" ascii wide nocase
    $subject_pfx = "command_req_" ascii wide
    $graph1 = "graph.microsoft.com" ascii wide
    $graph2 = "/me/messages" ascii wide
    $graph3 = "/me/drive" ascii wide
    $slc_dll = "slc.dll" ascii wide nocase
  condition:
    $subject_pfx and ($sideload_host and any of ($graph*) or $slc_dll and any of ($graph*)) and filesize < 10MB
}

rule Antino_IOC {
  meta:
    description = "Antino IOC sweep — C2 domains, DLL names, .NET loader, Outlook subject prefix, build metadata"
    author = "synthetic-detections"
    date = "2026-10-03"
    severity = "high"
    family = "antino-outlook-c2"
    reference = "https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html"
  strings:
    $c2_rsproxy = "rsproxy.cn" nocase
    $c2_cdn = "d32tpl7xt7175h.cloudfront.net" nocase
    $subject_pfx = "command_req_" ascii wide
    $dll_slc = "slc.dll" ascii wide nocase
    $dll_test = "TestAssembly.dll" ascii wide nocase
    $host_exe = "GatherOsState.exe" ascii wide nocase
    $locale_zh = "zh-CN" ascii wide
    $tz_utc8 = "UTC+08:00" ascii wide
    $tz_utc8b = "+08:00" ascii wide
  condition:
    (any of ($c2_rsproxy, $c2_cdn) or $subject_pfx and any of ($dll_slc, $dll_test, $host_exe) or $dll_slc and $dll_test and $host_exe or any of ($locale_zh, $tz_utc8, $tz_utc8b) and any of ($dll_slc, $dll_test) and $subject_pfx) and filesize < 50MB
}

rule Antino_Specimen {
  meta:
    description = "Antino Rust backdoor specimen — PE/DLL with Rust markers, Outlook Graph API C2 strings, and sideloading anchor"
    author = "synthetic-detections"
    date = "2026-10-03"
    severity = "critical"
    family = "antino-outlook-c2"
    reference = "https://thehackernews.com/2026/10/antino-backdoor-uses-outlook-and.html"
  strings:
    $rust1 = ".rustc"
    $rust2 = "rust_panic"
    $rust3 = "/rustc/"
    $cmd_pfx = "command_req_"
    $graph_api = "graph.microsoft.com"
    $messages = "/me/messages"
    $drive = "/me/drive"
  condition:
    pe.is_pe and any of ($rust*) and $cmd_pfx and any of ($graph_api, $messages, $drive) and filesize < 10MB
}
