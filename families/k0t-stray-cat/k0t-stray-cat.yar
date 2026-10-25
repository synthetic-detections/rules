/*
   k0t / Stray Cat — initial access broker campaign, 2026-10-21
   -------------------------------------------------------------
   Group-IB + NyxLab documented mass credential theft from FortiGate,
   FortiWeb, and Palo Alto GlobalProtect edge devices. Operator k0t
   (aliases CryptoFeel, Member19, Scrooge) uses custom Python scanners,
   AdaptixC2, and MeshCentral for persistence, then sells access to
   ransomware operators (Qilin, The Gentlemen observed downstream).

   Rule 1 — Behavioural: AdaptixC2 agent with campaign infra references.
   Rule 2 — IOC: campaign-specific domains, tool names, and installer
            artifacts with co-occurrence guard.
   Rule 3 — Specimen pin: SHA-256 hashes of known k0t tooling samples.

   Sources:
     https://www.group-ib.com/blog/stray-cat-network-edge/
     https://cybersecuritynews.com/breaking-into-fortigate-fortiweb/
*/

import "hash"

rule K0t_StrayCat_AdaptixC2_Beacon : c2 trojan
{
    meta:
        description = "k0t Stray Cat — AdaptixC2 agent with campaign-specific infrastructure"
        author      = "synthetic-detections"
        date        = "2026-10-25"
        severity    = "critical"
        family      = "k0t-stray-cat"
        reference   = "https://www.group-ib.com/blog/stray-cat-network-edge/"
    strings:
        $adaptix1     = "adaptixc2" nocase
        $adaptix2     = "AdaptixAgent"
        $adaptix3     = "adaptix_config"
        $adaptix4     = "adaptix-client"
        $infra_ts     = "64.94.85.14"
        $infra_beacon = "168.100.11.99"
        $infra_stage1 = "162.33.178.213"
        $mesh1        = "buttruyen.com"
        $mesh2        = "girydsfsggvb.com"
        $agent_host   = "afahimsa.top"
        $stage_d1     = "sthyjk.com"
        $stage_d2     = "alknene.shop"
        $rades        = "radesashar.com"
    condition:
        any of ($adaptix*)
        and (
            any of ($infra_ts, $infra_beacon, $infra_stage1) or
            any of ($mesh1, $mesh2, $agent_host, $stage_d1, $stage_d2, $rades)
        )
        and filesize < 50MB
}

rule K0t_StrayCat_IOC_CoOccurrence : tool trojan
{
    meta:
        description = "k0t Stray Cat — campaign tool names and infrastructure co-occurrence"
        author      = "synthetic-detections"
        date        = "2026-10-25"
        severity    = "high"
        family      = "k0t-stray-cat"
        reference   = "https://www.group-ib.com/blog/stray-cat-network-edge/"
    strings:
        $tool_fort    = "fort.py"
        $tool_fortnew = "fortnew.py"
        $tool_exploit = "exploit_2026_0257"
        $installer    = "clear-thinking_61.92.4"
        $mesh1        = "buttruyen.com"
        $mesh2        = "girydsfsggvb.com"
        $agent_host   = "afahimsa.top"
        $stage_d1     = "sthyjk.com"
        $stage_d2     = "alknene.shop"
        $rades        = "radesashar.com"
        $infra_ts     = "64.94.85.14"
        $infra_beacon = "168.100.11.99"
        $infra_stage1 = "162.33.178.213"
        $h_md5_1      = "5318f29ef434341d989d543b14fd2a48"
        $h_md5_2      = "20dc8f1b8a313336c14e03bcb71ff6c8"
        $h_md5_3      = "032473db4d66748eab524effe57a661d"
        $h_md5_4      = "13367fbba4344de87de418ab17de76f0"
        $h_md5_5      = "197f2621c80da7974c56d2ff1921e994"
        $h_md5_6      = "6f5d18157425aa9697913ae1310f588f"
        $h_md5_7      = "0dc1af7cfd336a7f075228defc730082"
    condition:
        2 of them and filesize < 50MB
}

rule K0t_StrayCat_Specimen_Pin : trojan
{
    meta:
        description = "k0t Stray Cat — SHA-256 specimen pin for known campaign tooling"
        author      = "synthetic-detections"
        date        = "2026-10-25"
        severity    = "critical"
        family      = "k0t-stray-cat"
        reference   = "https://www.group-ib.com/blog/stray-cat-network-edge/"
    condition:
        filesize < 50MB
        and (
            hash.sha256(0, filesize) == "158215c7371e868f3d0c7fd2e92f05026a8678a3635629d89bd6042ee543278a" or
            hash.sha256(0, filesize) == "1d1b76d30a69aa39b224053481483156f82dde026edd6f5d964f6e03f5f04a6d" or
            hash.sha256(0, filesize) == "4db6bea4c1e4bce5020039def4087a073f4753a6b297b2832c19c10423ac842d" or
            hash.sha256(0, filesize) == "552d0096f60c36a35c6096b3e4b38d743c29f8c56f3862fa3b7ef06c932e2a21" or
            hash.sha256(0, filesize) == "39c4decc4881ec02a47cd01c0fd8c3030527b466124ad03c6f99cfaa0ba0b72e" or
            hash.sha256(0, filesize) == "808145ec3351569083fda27a910ebdf9e054e8ca42e40c021af5d6712c2ab87c"
        )
}
