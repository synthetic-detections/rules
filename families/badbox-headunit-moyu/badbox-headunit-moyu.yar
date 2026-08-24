/*
   BADBOX / MoYu Group — Android automotive head-unit malware (June 2026)
   --------------------------------------------------------------------------
   Reported by Kaspersky/Securelist (2026-08): the first documented Android
   malware with an infection chain specific to CAR HEAD UNITS. A multi-stage
   downloader rides the legitimate TWCore analytics/update app (baked into DoFun
   firmware) to install ad-fraud + residential-proxy-botnet modules. Impact
   concentrated in Ukraine and Russia. Foothold via CVE-2021-33044/33045
   (auth-bypass, CVSS 9.8).

   Stages / distinctive artifacts:
     - JarService dropper     : package com.tw.jar1
     - Stage-2 loader         : thread "mosdk-host-loader", entry com.c.j.qbh.wa
     - Stage-3 clicker/loader : com.ast.sdk.BillingMain.init()
     - Zhima reverse-proxy    : class com.miyc.transfer.Client
     - MoYu/BADBOX markers     : "AdmoyuService", Vo1d overlap
     - Legit vector (NOT keyed alone): TWCore package com.tw.core
     - C2 API paths           : /cpc/api/task, /cpc/api/report, /cpc/api/xml
     - Update broker (MQTT)    : cardoor.cn
     - C2 domains (.sbs et al.): xmsae.sbs, ishano456.sbs, xshaon123.sbs,
                                 kshahnd.sbs, mdsjhd.sbs, nmnsny.sbs, kookjar.com,
                                 ty54fgd435.my, ue886578433.online, ty4523.space
     - C2 IPs                  : 144.217.243.201, 107.151.248.132, 128.14.210.58

   Rule shape:
     (1) MoYu_BADBOX_HeadUnit_Behavior  — critical: >=3 of the ultra-distinctive
         class/thread/service tokens co-occurring (com.tw.core is deliberately
         excluded from the strong set — it is the LEGITIMATE TWCore package)
     (2) MoYu_BADBOX_HeadUnit_IOC       — high: C2 domains / API paths with a
         co-occurrence guard so a single stray host cannot fire
     (3) MoYu_BADBOX_HeadUnit_Specimen  — critical: tight pin of the three rarest
         tokens (loader thread + MoYu service + Zhima client)

   Attribution: MoYu Group, linked to the BADBOX botnet platform (Kaspersky,
   high confidence) via the "mosdk-host-loader" thread name, the "AdmoyuService"
   component, and Vo1d overlap. Do not overstate beyond BADBOX-nexus.

   Siblings (Android / ad-fraud / botnet proxy):
     [[wallpaper-chrome-adfraud]], [[rokarolla-android-banker]]

   Sources:
     https://securelist.com/android-head-unit-malware/121106/
     https://thehackernews.com/2026/08/android-car-malware-spreads-through.html
     https://www.bleepingcomputer.com/news/security/hackers-infect-android-car-head-units-with-proxy-botnet-malware/

   Known samples (MD5, from the Securelist IOC appendix; recorded to the digest
   hash store 2026-08-24, MalShare 0/24 at authoring):
     JarService : ba27951b…69ecd3, d63bacd6…c7835, 6c2e34b3…6107d4, 8b5e5131…f9da2,
                  e1198458…88f316
     Loader     : e9f3a0da…80ae1a
     Clicker    : 0fbaa709…014774, 1dcf031c…cf3d11, 44b6b213…e95ecb, 67dc78e5…dfbc58,
                  9642ae61…1abe24, b067d5b0…dba77e, f0e3f7eb…b47422
     Zhima      : 412e9243…05b3b8, 71ab5517…f2ae320, 89ef78f7…20be362, a4223ce4…639045,
                  bd4d81cd…468499, c6bfb164…187fdb, de77c330…41441c, f8cf8c23…df8bac
     TWCore     : 2a64c3ef…6446c9, 7a4d3ba2…ee2671, ea244879…63bcc5
*/

rule MoYu_BADBOX_HeadUnit_Behavior
{
    meta:
        description = "MoYu Group / BADBOX Android car head-unit malware — distinctive multi-stage class/thread/service artifacts"
        author = "synthetic-detections"
        date = "2026-08-24"
        severity = "critical"
        family = "badbox-headunit-moyu"
        reference = "https://securelist.com/android-head-unit-malware/121106/"

    strings:
        $jar    = "com.tw.jar1" ascii
        $thread = "mosdk-host-loader" ascii
        $svc    = "AdmoyuService" ascii
        $bill   = "com.ast.sdk.BillingMain" ascii
        $zhima  = "com.miyc.transfer.Client" ascii
        $entry  = "com.c.j.qbh" ascii

    condition:
        filesize < 50MB and 3 of them
}

rule MoYu_BADBOX_HeadUnit_IOC
{
    meta:
        description = "MoYu Group / BADBOX head-unit malware — C2 domains and API paths (co-occurrence guarded)"
        author = "synthetic-detections"
        date = "2026-08-24"
        severity = "high"
        family = "badbox-headunit-moyu"
        reference = "https://securelist.com/android-head-unit-malware/121106/"

    strings:
        $d1 = "xmsae.sbs" ascii nocase
        $d2 = "ishano456.sbs" ascii nocase
        $d3 = "xshaon123.sbs" ascii nocase
        $d4 = "kshahnd.sbs" ascii nocase
        $d5 = "mdsjhd.sbs" ascii nocase
        $d6 = "nmnsny.sbs" ascii nocase
        $d7 = "ty54fgd435.my" ascii nocase
        $d8 = "ue886578433.online" ascii nocase
        $d9 = "ty4523.space" ascii nocase
        $d10 = "cardoor.cn" ascii nocase
        $api1 = "/cpc/api/task" ascii
        $api2 = "/cpc/api/report" ascii
        $api3 = "/cpc/api/xml" ascii

    condition:
        filesize < 50MB and
        (2 of ($d*) or (1 of ($d*) and 1 of ($api*)) or 2 of ($api*))
}

rule MoYu_BADBOX_HeadUnit_Specimen
{
    meta:
        description = "MoYu Group / BADBOX head-unit malware — tight specimen pin (loader thread + MoYu service + Zhima client)"
        author = "synthetic-detections"
        date = "2026-08-24"
        severity = "critical"
        family = "badbox-headunit-moyu"
        reference = "https://securelist.com/android-head-unit-malware/121106/"

    strings:
        $thread = "mosdk-host-loader" ascii
        $svc    = "AdmoyuService" ascii
        $zhima  = "com.miyc.transfer.Client" ascii

    condition:
        filesize < 50MB and all of them
}
