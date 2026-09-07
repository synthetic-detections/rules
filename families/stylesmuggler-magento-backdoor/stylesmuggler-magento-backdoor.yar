/*
   StyleSmuggler — Magento / Adobe Commerce unauthenticated RCE 0-day + Rust backdoor
   --------------------------------------------------------------------------
   Disclosed 2026-09-05 (Sansec); in-the-wild exploitation from 2026-09-04
   22:20 UTC. An unauthenticated RCE chain in Magento Open Source and Adobe
   Commerce (all versions through 2.4.9) abuses the template system's `styles`
   properties to inject PHP, then deliberately triggers Magento's standard
   "Payment Transaction Failed Reminder" email — the payload executes the
   moment Magento renders that message internally, so no human interaction is
   needed. The dropped implant is a Rust backdoor (unknown to other vendors at
   disclosure) that masquerades as the kernel worker `[kworker/u:8:0]` and as
   `fc-cache`, hides in /tmp and ~/.local/share/.gvfsd/ + ~/.cache/fontconfig/,
   persists via crontab, and beacons over WebSocket-in-TLS and NTP-shaped UDP.
   No CVE/patch as of 2026-09-06.

   Rules (three-rule shape):
     1 StyleSmuggler_Rust_Backdoor_HostArtifacts  (critical) — implant on disk:
       process masquerade + hidden /tmp & .gvfsd drops + crontab persistence,
       requiring >=2 categories so a lone "fc-cache" mention does not fire.
     2 StyleSmuggler_C2_Infrastructure            (high)     — typosquat C2 /
       download hosts, guarded by co-occurrence (>=2 C2 indicators, or 1 C2 +
       an implant marker).
     3 StyleSmuggler_Backdoor_KnownHashes         (critical) — SHA-256 pins.

   Sibling (Magento/e-commerce; earlier Sansec Magento activity):
     [[ironworm-npm-worm]], [[mirasvit-cache-warmer-cve-2026-45247]]

   Sources:
     https://sansec.io/research/stylesmuggler
     https://thehackernews.com/2026/09/unpatched-magento-and-adobe-commerce.html
*/

import "hash"

rule StyleSmuggler_Rust_Backdoor_HostArtifacts
{
    meta:
        description = "StyleSmuggler Rust backdoor on disk: kernel-worker/fc-cache process masquerade plus hidden /tmp and ~/.local/share/.gvfsd drops and crontab persistence (>=2 categories required)"
        author      = "synthetic-detections"
        date        = "2026-09-07"
        severity    = "critical"
        family      = "stylesmuggler-magento-backdoor"
        reference   = "https://sansec.io/research/stylesmuggler"

    strings:
        // (1) process masquerade
        $proc1 = "[kworker/u:8:0]" ascii
        // (2) hidden gvfsd persistence dir/binary
        $gv1 = "/.local/share/.gvfsd/gvfsd-user" ascii
        $gv2 = "/.local/share/.gvfsd/.gvfsd_" ascii
        // (3) hidden /tmp drops (StyleSmuggler-specific prefixes)
        $tmp1 = "/tmp/.kw_" ascii
        $tmp2 = "/tmp/.fc-" ascii
        $tmp3 = "/tmp/.fc_" ascii
        // (4) crontab persistence lines
        $cron1 = ".gvfsd/gvfsd-user" ascii
        $cron2 = ".cache/fontconfig/fc-cache" ascii
        $cron3 = "13,43 * * * *" ascii

    condition:
        // >=2 of the 4 artifact categories {proc, gvfsd, tmp-drop, crontab}
        ( $proc1 and ( 1 of ($gv*) or 1 of ($tmp*) or 1 of ($cron*) ) )
        or ( 1 of ($gv*) and ( 1 of ($tmp*) or 1 of ($cron*) ) )
        or ( 1 of ($tmp*) and 1 of ($cron*) )
}

rule StyleSmuggler_C2_Infrastructure
{
    meta:
        description = "StyleSmuggler typosquat C2 / malware-download infrastructure, guarded by co-occurrence so a single incidental domain does not fire"
        author      = "synthetic-detections"
        date        = "2026-09-07"
        severity    = "high"
        family      = "stylesmuggler-magento-backdoor"
        reference   = "https://sansec.io/research/stylesmuggler"

    strings:
        $c2a = "windwsecurity.run" ascii nocase
        $c2b = "ntp.timesysnc.net" ascii nocase
        $c2c = "time.microsft.run" ascii nocase
        $c2d = "pool.microsft.studio" ascii nocase
        $c2e = "ntp.timesync.to" ascii nocase
        $c2f = "ntp.synctime.to" ascii nocase
        $c2g = "ntp.syncstime.to" ascii nocase
        $c2h = "247.cdnflare.xyz" ascii nocase
        // implant markers (allow a single C2 hit to fire only alongside the implant)
        $imp1 = "[kworker/u:8:0]" ascii
        $imp2 = "/.local/share/.gvfsd/gvfsd-user" ascii
        $imp3 = "/tmp/.kw_" ascii

    condition:
        2 of ($c2*) or ( 1 of ($c2*) and 1 of ($imp*) )
}

rule StyleSmuggler_Backdoor_KnownHashes
{
    meta:
        description = "StyleSmuggler Rust backdoor / kworker builds — known SHA-256 specimens (Sansec, 2026-09-05)"
        author      = "synthetic-detections"
        date        = "2026-09-07"
        severity    = "critical"
        family      = "stylesmuggler-magento-backdoor"
        reference   = "https://sansec.io/research/stylesmuggler"

    condition:
        hash.sha256(0, filesize) == "e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7" or
        hash.sha256(0, filesize) == "b79dfdc1eed860e0b76c629d6adfce251db379b0b45a6d728d4ef483f7551420" or
        hash.sha256(0, filesize) == "4352cabaa451e5a894535fbcc4d46628701303322a13745cb5479d7d0534ae8e" or
        hash.sha256(0, filesize) == "d2fbf9eb75c495bfea48790d3b228fab0c15a282419c3d3f5e49294c4e1a3e82"
}
