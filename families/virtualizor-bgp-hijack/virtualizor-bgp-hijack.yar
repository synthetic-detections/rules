/*
   VIRTUALIZOR BGP-HIJACK SUPPLY-CHAIN IMPLANT -- "ne-rat" root backdoor
   (disclosed 2026-08-31; Virtualizor/Softaculous security advisory)
   -----------------------------------------------------------------------
   Between 2026-08-28 20:57 UTC and 2026-08-30 06:10 UTC an attacker
   announced a bogus BGP route for a Hetzner IP block hosting Softaculous /
   Virtualizor update infrastructure, obtained a valid Let's Encrypt cert
   for the diverted endpoint, and served a malicious Virtualizor update to
   a small number of hypervisors. Because the packages had no package-level
   cryptographic verification, the tampered update installed as root.

   Post-install behaviour (compromised-provider forensics via hard2bit /
   The Hacker News / BleepingComputer):
     - Malicious code injected into three legitimate Virtualizor PHP/service
       files: globals.php, _universal.php, zzvirtservice.
     - A root cron job executes the modified code.
     - Installs Java 17 if absent, then fetches + runs a Java payload as root,
       kept alive via a systemd unit "java-jre-update.service".
     - Creates a local account "proxyuser" and adds an attacker SSH key to
       root's authorized_keys.
     - Logs a version bump to 3.2.9.8 while the box still runs 3.2.9.7.
     - C2 / delivery over cdn.nerat[.]cc and connect.ne-rat[.]xyz.

   IOCs:
     payload SHA-256 b81a4e1fab9fc4e404d57224fe71e2c143aa93942bd46998789bdc944a7870c7
     domains  cdn.nerat[.]cc, connect.ne-rat[.]xyz
     SSH src  193.32.127[.]248 ; provider IP 31.77.220[.]138:2025
     account  proxyuser ; service java-jre-update.service

   NOTE: the standalone systemd-unit name and the "proxyuser" account are
   generic-looking, so the behaviour rule requires the ne-rat C2 vocabulary
   or the persistence constellation to co-occur before it fires. globals.php
   / _universal.php are legitimate Virtualizor filenames -- the specimen
   material is the injected loader stub, not the whole file.

   Rule 1 -- Behaviour: injected loader / persistence constellation.
   Rule 2 -- IOC: ne-rat C2 domains + payload host + SSH indicators.
   Rule 3 -- Specimen pin: published payload SHA-256 (hash-pinned).

   Sources:
     https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html
     https://hard2bit.com/en/blog/bgp-hijack-virtualizor-malicious-update-root-hypervisors/
     https://www.bleepingcomputer.com/news/security/hackers-push-malicious-virtualizor-update-in-bgp-hijacking-attack/
   Related families in this repo:
     [[whatsapp-vbs-rmm-campaign]]  -- other 2026 supply/deploy-channel abuse.
*/

import "hash"

rule Virtualizor_BGP_Hijack_Implant_Behaviour
{
    meta:
        description = "Injected Virtualizor update loader: ne-rat payload fetch + java-jre-update.service persistence + proxyuser/root-SSH backdoor constellation"
        author      = "synthetic-detections"
        date        = "2026-09-04"
        severity    = "critical"
        family      = "virtualizor-bgp-hijack"
        reference   = "https://thehackernews.com/2026/09/bgp-hijack-delivers-malicious.html"

    strings:
        // persistence: attacker systemd unit masquerading as a JRE updater
        $svc     = "java-jre-update.service" ascii
        // attacker-created local account
        $acct    = "proxyuser" ascii
        // Virtualizor host-side files the loader tampers with
        $vf1     = "/usr/local/virtualizor/globals.php" ascii
        $vf2     = "/usr/local/virtualizor/_universal.php" ascii
        $vf3     = "zzvirtservice" ascii
        // C2 / delivery vocabulary
        $c2a     = "nerat.cc" ascii nocase
        $c2b     = "ne-rat.xyz" ascii nocase
        // root SSH persistence
        $ssh     = "authorized_keys" ascii

    condition:
        // ne-rat C2 anchor with any Virtualizor/persistence artifact, OR
        // the local persistence constellation without needing the C2 string
        (
            (any of ($c2a, $c2b)) and
            (any of ($svc, $acct, $vf1, $vf2, $vf3))
        )
        or
        (
            $svc and $acct and $ssh
        )
}

rule Virtualizor_BGP_Hijack_IOC
{
    meta:
        description = "ne-rat C2 / delivery domains and attacker SSH source from the 2026-08 Virtualizor BGP-hijack supply-chain compromise"
        author      = "synthetic-detections"
        date        = "2026-09-04"
        severity    = "high"
        family      = "virtualizor-bgp-hijack"
        reference   = "https://hard2bit.com/en/blog/bgp-hijack-virtualizor-malicious-update-root-hypervisors/"

    strings:
        $d1 = "cdn.nerat.cc" ascii nocase
        $d2 = "connect.ne-rat.xyz" ascii nocase
        $d3 = "nerat.cc" ascii nocase
        $d4 = "ne-rat.xyz" ascii nocase
        $ip = "193.32.127.248" ascii fullword
        $ipp = "31.77.220.138:2025" ascii fullword

    condition:
        any of them
}

rule Virtualizor_BGP_Hijack_Payload_Pin
{
    meta:
        description = "Hash pin for the published Virtualizor BGP-hijack Java payload (SHA-256)"
        author      = "synthetic-detections"
        date        = "2026-09-04"
        severity    = "critical"
        family      = "virtualizor-bgp-hijack"
        reference   = "https://hard2bit.com/en/blog/bgp-hijack-virtualizor-malicious-update-root-hypervisors/"

    condition:
        hash.sha256(0, filesize) == "b81a4e1fab9fc4e404d57224fe71e2c143aa93942bd46998789bdc944a7870c7"
}
