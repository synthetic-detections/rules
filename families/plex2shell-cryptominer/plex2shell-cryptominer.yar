/*
   Plex2Shell — CVE-2026-96652/96654/96655/96656 exploit chain + payloads
   ----------------------------------------------------------------------
   Four-CVE chain enabling unauthenticated RCE on Plex Media Server
   before 1.43.3.10861. Discovered by Zach Main (code-zm), disclosed to
   Plex 2026-07-27, patched 2026-08-03, PoC published 2026-10-16,
   in-the-wild exploitation observed 2026-10-17.

   Chain:
     CVE-2026-96652  SSRF via /player/timeline (protocol= parameter)
     CVE-2026-96654  searchOne function abuse → admin token leak
     CVE-2026-96655  Transcoder SSRF → fetch attacker-hosted ELF
     CVE-2026-96656  File path control → write .so to Codecs dir → dlopen

   Post-exploitation payloads observed in the wild:
     - x12345: XMRig miner, fetched from 217.60.194[.]116
     - myawesomeproxy: Linux reverse-proxy backdoor (AISURU proxyware)
       shows consent banner "Running this software on any of your
       devices makes you agree to the potential external use..."
     - mylovelyminer: XMRig variant, mining to ota.proxystream[.]st

   Rule shape:
     (1) Plex2Shell_Proxyware_Behavior — behavioural/critical: the
         AISURU proxyware consent string + proxy/mining indicators
     (2) Plex2Shell_Miner_Behavior — behavioural/high: XMRig miner
         with Plex2Shell campaign-specific pool/process indicators
     (3) Plex2Shell_Campaign_IOCs — IOC/high: sample SHA256 hashes +
         C2/mining infrastructure (atomic, decay expected)

   Sources:
     https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html
     https://securityaffairs.com/?p=201324
     https://github.com/code-zm/plex2shell
*/

rule Plex2Shell_Proxyware_Behavior : backdoor behavioral
{
    meta:
        description = "Plex2Shell post-exploitation proxyware — AISURU consent banner string indicating a residential proxy backdoor that hijacks victim bandwidth; observed dropped via Plex Codecs directory write"
        author      = "synthetic-detections"
        date        = "2026-10-27"
        severity    = "critical"
        family      = "plex2shell-cryptominer"
        reference   = "https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html"
    strings:
        $consent = "Running this software on any of your devices makes you agree to the potential external use of your internet traffic" ascii wide
        $p1      = "proxystream" nocase
        $p2      = "myawesomeproxy" nocase
        $p3      = "proxy.start" nocase
        $p4      = "relay.proxystream" nocase
    condition:
        $consent or ($p2 and any of ($p1, $p3, $p4) and filesize < 50MB)
}

rule Plex2Shell_Miner_Behavior : behavioral miner
{
    meta:
        description = "Plex2Shell post-exploitation miner — XMRig variant with campaign-specific process names (mylovelyminer, x12345) and mining pool (ota.proxystream.st); dropped via Plex Codecs directory .so write"
        author      = "synthetic-detections"
        date        = "2026-10-27"
        severity    = "high"
        family      = "plex2shell-cryptominer"
        reference   = "https://securityaffairs.com/?p=201324"
    strings:
        $m1   = "mylovelyminer" nocase
        $m2   = "x12345"
        $pool = "ota.proxystream" nocase
        $xmr1 = "stratum+tcp://" nocase
        $xmr2 = "stratum+ssl://" nocase
        $xmr3 = "\"algo\""
        $xmr4 = "randomx" nocase
        $xmr5 = "XMRig"
    condition:
        (any of ($m1, $m2) and any of ($pool, $xmr*)) or ($pool and 2 of ($xmr*) and filesize < 50MB)
}

rule Plex2Shell_Campaign_IOCs : c2 ioc miner
{
    meta:
        description = "Plex2Shell campaign hard IOCs — SHA256 hashes of post-exploitation binaries + C2/mining infrastructure IPs and domains (atomic, decay expected)"
        author      = "synthetic-detections"
        date        = "2026-10-27"
        severity    = "high"
        family      = "plex2shell-cryptominer"
        reference   = "https://thehackernews.com/2026/10/hackers-exploit-plex2shell-flaws-to.html"
    strings:
        // x12345 miner
        $h1  = "b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49" nocase
        // myawesomeproxy backdoor
        $h2  = "e546b10aee5edc754da4f9b0baace00392257121911f630145078eafad1e6bd9" nocase
        // C2 / payload hosting IPs
        $ip1 = "217.60.194.116" ascii wide fullword
        $ip2 = "91.92.40.202" ascii wide fullword
        $ip3 = "176.65.139.228" ascii wide fullword
        $ip4 = "45.194.92.222" ascii wide fullword
        // Mining / proxy C2 domains
        $d1  = "ota.proxystream.st" ascii wide nocase
        $d2  = "global.relay.proxystream.st" ascii wide nocase
        $d3  = "proxystream.st" ascii wide nocase
    condition:
        any of ($h*) or 2 of ($ip*) or (any of ($d*) and filesize < 10MB)
}
