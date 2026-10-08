// fortigatesniffer-credential-harvester.yar
// --------------------------------------------------------------------------
// FortigateSniffer (FortiBleed campaign) — Go-based credential harvesting
// tool that abuses FortiOS diagnostic sniffer functionality to intercept
// authentication traffic across 24 protocols on compromised FortiGate
// appliances. Deployed by a Russian-speaking IAB confirmed as feeding
// INC, Lynx, and Payload ransomware affiliates.
//
// [[sibling]] fortimail-cve-2026-104286
//
// References:
//   https://cybersecuritynews.com/fortigatesniffer-tool-fortibleed/
//   https://thehackernews.com/2026/10/fbi-warns-fortibleed-remains-active.html
//   https://www.securityweek.com/fortibleed-86000-fortinet-device-credentials-compromised/
// --------------------------------------------------------------------------

import "hash"

rule FortigateSniffer_Behavioural : credential_harvester fortigatesniffer
{
    meta:
        description = "Detects FortigateSniffer credential harvesting tool by behavioural strings"
        author      = "synthetic-detections"
        date        = "2026-10-08"
        severity    = "critical"
        family      = "fortigatesniffer-credential-harvester"
        reference   = "https://cybersecuritynews.com/fortigatesniffer-tool-fortibleed/"
    strings:
        $sniffer1     = "fg_sniffer"
        $sniffer2     = "FortigateSniffer"
        $sniffer3     = "fortigatesniffer"
        $diag         = "diagnose sniffer packet"
        $brute        = "mpbrute"
        $forticheck   = "forticheck"
        $ipgeo        = "ipgeo.csv"
        $pcapng       = ".pcapng"
        $proto_radius = "RADIUS"
        $proto_ntlm   = "NTLM"
        $proto_kerb   = "Kerberos"
        $proto_ldap   = "LDAP"
        $proto_winrm  = "WinRM"
        $go_build     = "Go build"
    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f)
        and (
            (any of ($sniffer*) and $diag) or
            (any of ($sniffer*) and 3 of ($proto_*)) or
            ($diag and $go_build and 2 of ($proto_*)) or
            ($brute and $forticheck and any of ($sniffer*)) or
            (any of ($sniffer*) and $ipgeo and $pcapng)
        )
        and filesize < 50MB
}

rule FortigateSniffer_IOC : credential_harvester fortigatesniffer
{
    meta:
        description = "Detects FortigateSniffer tools and companions by co-occurring IOC strings"
        author      = "synthetic-detections"
        date        = "2026-10-08"
        severity    = "high"
        family      = "fortigatesniffer-credential-harvester"
        reference   = "https://cybersecuritynews.com/fortigatesniffer-tool-fortibleed/"
    strings:
        $name1  = "fg_sniffer_linux_amd64"
        $name2  = "fg_sniffer_windows_amd64"
        $name3  = "mpbrute2.bin"
        $name4  = "gen_rotator"
        $name5  = "spray_da.py"
        $c2_1   = "85.11.187"
        $c2_2   = "193.8.187"
        $c2_3   = "194.113.39"
        $c2_4   = "77.91.122"
        $tool1a = "Hashtopolis"
        $tool1b = "hashtopolis"
        $tool2  = "vast.ai"
        $tool3  = "ad_full_audit"
        $tool4  = "match_corps"
        $tool5  = "merge_revenue"
    condition:
        (
            2 of ($name*) or
            (any of ($name*) and any of ($c2_*)) or
            (any of ($name*) and 2 of ($tool*)) or
            (2 of ($c2_*) and any of ($tool*))
        )
        and filesize < 50MB
}

rule FortigateSniffer_Specimen : credential_harvester fortigatesniffer
{
    meta:
        description = "Specimen pin for known FortigateSniffer / FortiBleed campaign samples"
        author      = "synthetic-detections"
        date        = "2026-10-08"
        severity    = "critical"
        family      = "fortigatesniffer-credential-harvester"
        reference   = "https://cybersecuritynews.com/fortigatesniffer-tool-fortibleed/"
    condition:
        filesize < 50MB
        and (
            hash.sha256(0, filesize) == "4d0b62d3162d4be391e3ba1e191dad28e5e5d5b161cfdef60eeb4361a92d8413" or
            hash.sha256(0, filesize) == "80d83eb01f28c87a61b51f1f83805e63a791905f019bd3b87f10a10f66efab1e" or
            hash.sha256(0, filesize) == "2c98c86e6bd6f46cbd6c89d855541b9da91515b1bb986641a77e31c5c6aa2abb" or
            hash.sha256(0, filesize) == "a8b09fd4f7ff2f298b45ca602992f44b3c2ac3746bcdb182c59ab2a20c690954"
        )
}
