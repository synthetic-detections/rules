/*
   cavern-manticore-net-c2 — Iran MOIS-nexus modular .NET C2 "Cavern"
   ------------------------------------------------------------------
   Disclosed by Check Point Research ("Cavern Manticore: Exposing Iran-Linked
   Modular C2 Framework", 2026-07-06; broad secondary pickup 2026-07-10→13).
   Iran-nexus APT (assessed MOIS-linked, tradecraft/infra overlap with the
   OilRig subgroup Lyceum) targeting Israeli government and IT-service
   providers, pivoting provider->provider before the intended victim. Initial
   access via abuse of RMM software already present in the target.

   The agent (internal "Cavern" / legacy "Cav3rn") is side-loaded as uxtheme.dll
   behind a legitimate WinDirStat.exe. Modules ship in deliberately awkward .NET
   formats (.NET Framework, Mixed-Mode C++/CLI, Native AOT) with per-module
   AppDomain isolation. C2 is steganographic PNG-magic files (.CvnC/.CvnA/.CvnR
   .png) staged via inpt/ outpt/, traffic XOR'd (key 0x48), delimited _;;_ / _,_.

   These rules key on the CAVERN framework's own tells, not on side-load hosts
   (uxtheme.dll / WinDirStat.exe are legitimate): the developer PDB prefix, the
   fixed MYMUTEX123HELLP mutex family, the misspelled internal error strings,
   the distinctive n-*.dll module names, the Cvn.cfg config, and the specific
   C2 domains. Generic module names (mhm.dll/db.dll/ode.dll) and the bare word
   "cavern" are deliberately excluded so they cannot fire alone.

   Siblings (state-nexus modular implants / APT tradecraft):
     [[kimsuky-hellodoor]], [[apt28-promptsteal]],
     [[moonlight-maze-loki2-penquin]], [[codedome-pakistan-police-implant]]

   Sources:
     https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/
     https://thehackernews.com/2026/07/iran-linked-hackers-use-new-cavern-c2.html
     https://www.infosecurity-magazine.com/news/new-iran-hacking-group-targets/
*/

import "hash"

rule Cavern_Manticore_Agent_Behavior
{
    meta:
        description = "Cavern/Cav3rn .NET agent operational shape: the developer PDB prefix, or the MYMUTEX123HELLP mutex co-occurring with a Cavern internal marker, or two misspelled internal strings together"
        author      = "synthetic-detections"
        date        = "2026-07-14"
        severity    = "critical"
        family      = "cavern-manticore-net-c2"
        reference   = "https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/"

    strings:
        $pdb   = "\\Desktop\\Modules\\cavern\\" ascii wide nocase
        $mtx   = "MYMUTEX123HELLP" ascii wide
        $proj  = "Cav3rn" ascii wide
        $err1  = "where is get_version?!?" ascii wide
        $err2  = "handeling connect ms" ascii wide
        $err3  = "tunnel message receivecd" ascii wide
        $steg1 = ".CvnC.png" ascii wide nocase
        $steg2 = ".CvnA.png" ascii wide nocase
        $steg3 = ".CvnR.png" ascii wide nocase

    condition:
        $pdb
        or ($mtx and 1 of ($proj, $err1, $err2, $err3, $steg1, $steg2, $steg3))
        or 2 of ($err1, $err2, $err3, $steg1, $steg2, $steg3)
}

rule Cavern_Manticore_IOC
{
    meta:
        description = "Cavern Manticore distinctive tokens: fixed mutex, Cvn.cfg config, C2 domains, and the unusual n-*.dll transport/recon/tunnel module names (generic mhm/db/ode.dll excluded)"
        author      = "synthetic-detections"
        date        = "2026-07-14"
        severity    = "high"
        family      = "cavern-manticore-net-c2"
        reference   = "https://thehackernews.com/2026/07/iran-linked-hackers-use-new-cavern-c2.html"

    strings:
        $mtx  = "MYMUTEX123HELLP" ascii wide
        $cfg  = "Cvn.cfg" ascii wide nocase
        $c2a  = "hospitalinstallation" ascii wide nocase
        $c2b  = "adserviceupdate.com" ascii wide nocase
        $c2c  = "hygienehistory.com" ascii wide nocase
        $mod1 = "n-HTCommp.dll" ascii wide nocase
        $mod2 = "n-ten.dll" ascii wide nocase
        $mod3 = "n-sws.dll" ascii wide nocase

    condition:
        $mtx or $cfg
        or any of ($c2a, $c2b, $c2c)
        or any of ($mod1, $mod2, $mod3)
}

rule Cavern_Manticore_Specimen
{
    meta:
        description = "Published Cavern Manticore sample SHA-256 pins (Check Point appendix): uxtheme.dll agents, n-HTCommp.dll comms, mhm.dll file manager"
        author      = "synthetic-detections"
        date        = "2026-07-14"
        severity    = "critical"
        family      = "cavern-manticore-net-c2"
        reference   = "https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/"

    condition:
        filesize < 6MB and (
            hash.sha256(0, filesize) == "37e123bd7998af4eae32718ce254776f36365a80ba56952593dab46f536d4066"
            or hash.sha256(0, filesize) == "92cae0ad7f98f51a14bcc0ee05e372ebdc29ea96ea7bd161bd3f55198767603b"
            or hash.sha256(0, filesize) == "5dc08bda6919a57a85e5f38b857985fa71529ca39c8299868d5a49a987e19b18"
            or hash.sha256(0, filesize) == "a4aa217def4c38f4ecacdf47b1cd687f60cc74c18ab75195be3c4357a790bf41"
            or hash.sha256(0, filesize) == "b630c96d3763182533d4fb9b614134382bd644cb02c6c1c3ade848b6ecc31e86"
            or hash.sha256(0, filesize) == "8e9425c0b46eeb516610ae913d13f2b3f44a023043cb099277031d4ec38a6134"
        )
}
