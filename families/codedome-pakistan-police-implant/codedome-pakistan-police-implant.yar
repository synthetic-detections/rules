/*
   codedome — CMS watering-hole implant, Pakistani law-enforcement espionage
   --------------------------------------------------------------------------
   Disclosed by SentinelLABS ("One Target, Two Flags"), reporting wave through
   2026-07-11. Four espionage clusters — three China-nexus (PlugX, ShadowPad,
   Cobalt Strike) and one India-nexus (Remcos / TAG-179) — independently hit
   Pakistani law enforcement (Balochistan / Khyber Pakhtunkhwa / Islamabad
   Police, Punjab Safe Cities Authority) from 2024-02 to 2026-04.

   The Balochistan Police Complaint Management System (CMS) was turned into a
   watering hole serving a fake "update" download, cms_plugin.exe, from
   hxxps://cms.balochistanpolice[.]gov[.]pk/client%20scripts/cms_plugin.exe .
   Two variants: a Rust-based stager, and a .NET variant masquerading as Qihoo
   360's 360Safe.exe that reflectively loads an AsyncRAT (C2 41.216.188[.]140).
   Multiple China-nexus samples share a `D:\codedome\` build path, simplified-
   Chinese log strings, and pinyin markers (e.g. `xinshi`) in PDB paths — that
   shared build environment, not the commodity RATs, is the durable anchor.

   The RAT families themselves (AsyncRAT/PlugX/ShadowPad/CS/Remcos) are broadly
   covered elsewhere; these rules key on the codedome CLUSTER: the shared build
   path, the exact AsyncRAT PDB, the fake-update lure, and the CMS delivery URL
   / C2. Behaviour rule requires the codedome path to co-occur with a second
   campaign marker so a bare mention of 360Safe.exe or an unrelated build path
   does not fire.

   Siblings (state-nexus RAT / watering-hole tradecraft):
     [[sidecopy-xenofiscal]], [[apt28-promptsteal]], [[turla-stockstay]],
     [[kimsuky-hellodoor]]

   Sources:
     https://www.sentinelone.com/labs/one-target-china-india-espionage-converge-on-pakistani-law-enforcement/
     https://thehackernews.com/2026/07/hackers-weaponize-balochistan-police.html
     https://therecord.media/india-pakistan-cyber-campaign-apt
*/

import "hash"

rule Codedome_CMS_Implant_Behavior
{
    meta:
        description = "codedome-cluster implant: the shared D:\\codedome\\ build path co-occurring with a campaign marker (fake-update lure, 360Safe masquerade, pinyin build tag), or the exact AsyncRAT PDB path"
        author      = "synthetic-detections"
        date        = "2026-07-12"
        severity    = "critical"
        family      = "codedome-pakistan-police-implant"
        reference   = "https://www.sentinelone.com/labs/one-target-china-india-espionage-converge-on-pakistani-law-enforcement/"

    strings:
        $build   = "D:\\codedome\\" ascii wide nocase
        $pdbfull = "D:\\codedome\\case\\six\\Client\\Client2\\obj\\Debug\\Client2.pdb" ascii wide nocase
        $upd     = "Update Complete! Please refresh the page" ascii wide
        $pin     = "xinshi" ascii wide nocase
        $masq    = "360Safe.exe" ascii wide nocase

    condition:
        $pdbfull
        or ($build and 1 of ($upd, $pin, $masq))
}

rule Codedome_CMS_Implant_IOC
{
    meta:
        description = "codedome CMS watering-hole delivery IOCs: the Balochistan Police CMS download path/host, the cms_plugin.exe stager name, and the AsyncRAT C2 — guarded by co-occurrence so a bare filename does not fire"
        author      = "synthetic-detections"
        date        = "2026-07-12"
        severity    = "high"
        family      = "codedome-pakistan-police-implant"
        reference   = "https://thehackernews.com/2026/07/hackers-weaponize-balochistan-police.html"

    strings:
        $dom  = "cms.balochistanpolice" ascii wide nocase
        $path = "/client%20scripts/cms_plugin.exe" ascii wide nocase
        $c2   = "41.216.188.140" ascii wide
        $fn   = "cms_plugin.exe" ascii wide nocase

    condition:
        $path
        or ($dom and $fn)
        or ($c2 and $fn)
        or 2 of ($dom, $c2, $path)
}

rule Codedome_CMS_Implant_Specimen
{
    meta:
        description = "Published cms_plugin.exe artifacts (SentinelLABS SHA-1 pins) — codedome Pakistani-police espionage cluster"
        author      = "synthetic-detections"
        date        = "2026-07-12"
        severity    = "critical"
        family      = "codedome-pakistan-police-implant"
        reference   = "https://www.sentinelone.com/labs/one-target-china-india-espionage-converge-on-pakistani-law-enforcement/"

    condition:
        filesize < 8MB and (
            hash.sha1(0, filesize) == "23f6781919a50b118d8d4e6a7e9ae63b71ecc885"
            or hash.sha1(0, filesize) == "4039454c9189e64285e93fc075a30b93f814b5b5"
            or hash.sha1(0, filesize) == "58cb2d95063b9df807b7aa8dc106b74ce988a491"
        )
}
