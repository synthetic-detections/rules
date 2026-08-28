/*
   ZBTLINK BACKDOOR -- SPEAKINGSTONE + DARKLANTERN router implants
   (disclosed 2026-08-27; VulnCheck "ZBT / DarkLantern / SpeakingStone")
   -----------------------------------------------------------------------
   Firmware-resident Linux implants shipped in Chinese Zbtlink (ZBT / also
   white-labelled) router firmware. The images are cross-compiled ELF
   binaries for the MIPS/ARM router SoCs. VulnCheck names three components:

     yunmgrd     -- SPEAKINGSTONE loader/manager, "zbtProtocol" over UDP/10000
     infosrvd    -- DARKLANTERN backdoor, "revProto" over UDP/9992
     inetdetect  -- connectivity/beacon helper

   Behaviour (VulnCheck):
     - DARKLANTERN listens on UDP/9992; SPEAKINGSTONE on UDP/10000, answering
       from UDP source ports 8897/8898.
     - Commands are dispatched through an exec prefix "/etc/exec/cmd".
     - Device fingerprint uses an MD5 computed over a hardcoded salt
       "mqonu.com".
     - State/config lives at /tmp/yunclient.conf, /tmp/info.txt, /tmp/mac.txt.
     - C2 is ac-link[.]com (47.107.224.89, Alibaba Shenzhen) and the now
       sinkholed www.findmyipaddr[.]com.
     - OEM contact string sales03@zbt-china[.]com is baked into the implant.

   NOTE: generic router paths such as /tmp/info.txt and /tmp/mac.txt, and the
   shared-hoster IP 47.107.224.89, alias legitimate firmware content, so the
   rules require the implant-specific proto/salt/exec tokens or a binary name
   to co-occur before they fire.

   Rule 1 -- Behaviour: ELF + implant proto/salt/exec constellation.
   Rule 2 -- IOC: distinctive strings, C2 domains, OEM contact.
   Rule 3 -- Specimen pin: the three published SHA-256 (hash-pinned).

   Sources:
     https://www.vulncheck.com/blog/zbt-darklantern-speakingstone
   Related families in this repo:
     [[endlessdoors-zbtlink-backdoor]]  -- separate VulnCheck Zbtlink implant
        (rctl-derived, ports 7000/7001); note shared C2 IP 47.107.224.89.
     [[badbox-headunit-moyu]]           -- other embedded-device ELF implant.
*/

import "hash"

rule Zbtlink_Backdoor_Behaviour
{
    meta:
        description = "SPEAKINGSTONE/DARKLANTERN Zbtlink router implant -- ELF with the revProto/zbtProtocol proto vocabulary, MD5 salt mqonu.com, exec prefix /etc/exec/cmd, or implant binary names co-occurring"
        author      = "synthetic-detections"
        date        = "2026-08-28"
        severity    = "critical"
        family      = "zbtlink-backdoor"
        reference   = "https://www.vulncheck.com/blog/zbt-darklantern-speakingstone"

    strings:
        // implant protocol vocabulary
        $proto1 = "revProto" ascii
        $proto2 = "zbtProtocol" ascii
        // MD5 fingerprint salt
        $salt   = "mqonu.com" ascii
        // command-dispatch exec prefix
        $exec   = "/etc/exec/cmd" ascii
        // implant binary / service names
        $bin1   = "yunmgrd" ascii
        $bin2   = "infosrvd" ascii
        $bin3   = "inetdetect" ascii
        // implant-specific config path
        $cfg    = "/tmp/yunclient.conf" ascii

    condition:
        uint32(0) == 0x464c457f and filesize < 8MB
        and (
            ( 1 of ($proto*) and 1 of ($salt, $exec, $bin1, $bin2, $bin3, $cfg) )
            or ( $salt and $exec )
            or ( 2 of ($bin1, $bin2, $bin3) )
        )
}

rule Zbtlink_Backdoor_IOC
{
    meta:
        description = "SPEAKINGSTONE/DARKLANTERN Zbtlink implant IOCs -- proto strings, salt, exec prefix, binary names, OEM contact, and C2 domains (VulnCheck, 2026-08-27)"
        author      = "synthetic-detections"
        date        = "2026-08-28"
        severity    = "high"
        family      = "zbtlink-backdoor"
        reference   = "https://www.vulncheck.com/blog/zbt-darklantern-speakingstone"

    strings:
        // high-signal, implant-specific tokens
        $proto1 = "revProto" ascii
        $proto2 = "zbtProtocol" ascii
        $salt   = "mqonu.com" ascii
        $exec   = "/etc/exec/cmd" ascii
        $bin1   = "yunmgrd" ascii
        $bin2   = "infosrvd" ascii
        $bin3   = "inetdetect" ascii
        $oem    = "sales03@zbt-china.com" ascii nocase
        $cfg    = "/tmp/yunclient.conf" ascii
        // C2 domains
        $d1     = "ac-link.com" ascii nocase
        $d2     = "findmyipaddr.com" ascii nocase
        // generic router paths / shared-hoster IP -- only credited when paired
        $g1     = "/tmp/info.txt" ascii
        $g2     = "/tmp/mac.txt" ascii
        $ip     = "47.107.224.89" ascii

    condition:
        filesize < 50MB
        and (
            any of ($proto*, $salt, $exec, $bin*, $oem, $cfg, $d*)
            or ( $ip and 1 of ($g1, $g2) )
            or ( all of ($g1, $g2) )
        )
}

rule Zbtlink_Backdoor_Specimen_Pin
{
    meta:
        description = "SPEAKINGSTONE (yunmgrd), DARKLANTERN (infosrvd), and inetdetect -- pinned by the three VulnCheck SHA-256"
        author      = "synthetic-detections"
        date        = "2026-08-28"
        severity    = "critical"
        family      = "zbtlink-backdoor"
        reference   = "https://www.vulncheck.com/blog/zbt-darklantern-speakingstone"

    condition:
        uint32(0) == 0x464c457f and filesize < 8MB
        and (
            // yunmgrd / SPEAKINGSTONE
            hash.sha256(0, filesize) == "b77811db4d218c65670a6c9a5b33c30ff81c6d779e15d658643138771178a818"
            // infosrvd / DARKLANTERN
            or hash.sha256(0, filesize) == "7e2e036fec2fe7ab4bbd43978d9296563894c92a112f5ac2f39957f12108e245"
            // inetdetect
            or hash.sha256(0, filesize) == "ae6c356f1f09260b859f84d994ef8423540a6c0bdf98510d86b85834283e4926"
        )
}
