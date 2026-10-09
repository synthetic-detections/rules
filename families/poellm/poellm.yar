/*
   PoeLLM / Canto Incognito — cryptomining botnet targeting AI infrastructure, 2026-10-07
   ---------------------------------------------------------------------------------------
   Financially-motivated botnet tracked by Lumen Black Lotus Labs. Targets exposed
   AI infrastructure services (LiteLLM, Ollama, Gotenberg, Gitea, Ivanti Sentry).
   Main payload is an ELF binary named `libgcrypt` that deploys XMRig and Iron
   cryptocurrency miners, connects to the Kryptex mining pool, and provides
   remote shell / internet-scanning / exploit-deployment capabilities.
   C2 resolution via a GitHub repository (github.com/ejejejdfbbebe).

   Rule 1 — behavioural: ELF with `libgcrypt` filename pattern combined with
            mining-related strings or GitHub-based C2 resolution.
   Rule 2 — IOC sweep: C2 IP addresses and GitHub repo URL with co-occurrence
            guards to prevent individual IPs from FP-ing.
   Rule 3 — specimen pin: exact SHA-256 hashes of 3 known samples.

   Sources:
     https://thehackernews.com/2026/10/poellm-malware-infects-3400-servers-to.html
     https://github.com/blacklotuslabs/IOCs/blob/main/PoeLLM_IOCs.txt
     https://runtimewire.com/article/poellm-exposed-ai-servers-cryptomining-botnet
*/

import "hash"

rule PoeLLM_Behavioral : behavioral cryptominer elf
{
    meta:
        description = "PoeLLM cryptomining botnet behavioural — ELF payload with libgcrypt masquerade, mining pool strings, and GitHub-based C2 resolution"
        author      = "synthetic-detections"
        date        = "2026-10-09"
        severity    = "critical"
        family      = "poellm"
        reference   = "https://thehackernews.com/2026/10/poellm-malware-infects-3400-servers-to.html"
    strings:
        // Masquerade filename — the payload drops as "libgcrypt"
        $name_libgcrypt = "libgcrypt" ascii wide
        // Mining pool and miner references
        $miner_xmrig    = "xmrig" ascii wide nocase
        $miner_iron     = "iron" ascii wide nocase
        $pool_kryptex   = "kryptex" ascii wide nocase
        $pool_stratum   = "stratum+" ascii wide
        // GitHub-based C2 resolution pattern
        $c2_github      = "ejejejdfbbebe" ascii wide
        $c2_raw_gh      = "raw.githubusercontent.com" ascii wide
    condition:
        // Must be an ELF binary
        // Mining indicators: pool name or miner binary name
        // GitHub C2 resolution pattern
        uint32(0) == 0x464c457f
        and $name_libgcrypt
        and (
            any of ($miner_xmrig, $miner_iron, $pool_kryptex, $pool_stratum) or
            ($c2_github and $c2_raw_gh)
        )
        and filesize < 20MB
}

rule PoeLLM_IOC : c2 cryptominer ioc
{
    meta:
        description = "PoeLLM IOC sweep — C2 IPs and GitHub repo URL with co-occurrence guards"
        author      = "synthetic-detections"
        date        = "2026-10-09"
        severity    = "high"
        family      = "poellm"
        reference   = "https://github.com/blacklotuslabs/IOCs/blob/main/PoeLLM_IOCs.txt"
    strings:
        // GitHub C2 repo — globally unique indicator
        $gh_repo        = "ejejejdfbbebe" ascii wide
        // Active C2 IPs
        $c2_act1        = "92.119.164.50" ascii wide
        $c2_act2        = "103.249.201.108" ascii wide
        $c2_act3        = "178.128.14.204" ascii wide
        // Historical C2 IPs
        $c2_hist1       = "136.148.69.233" ascii wide
        $c2_hist2       = "185.132.53.158" ascii wide
        $c2_hist3       = "120.224.114.212" ascii wide
        $c2_hist4       = "5.78.73.122" ascii wide
        $c2_hist5       = "15.204.178.28" ascii wide
        $c2_hist6       = "92.119.165.74" ascii wide
        $c2_hist7       = "45.133.73.28" ascii wide
        $c2_hist8       = "89.39.253.46" ascii wide
        $c2_hist9       = "191.37.28.160" ascii wide
        // Masquerade filename for correlation
        $name_libgcrypt = "libgcrypt" ascii wide
        // Mining pool for correlation
        $pool_kryptex   = "kryptex" ascii wide nocase
    condition:
        // GitHub repo name fires standalone (globally unique)
        // Active C2 IP requires at least one corroborator
        // Historical C2 IPs need at least 2 together, or 1 + corroborator
        (
            $gh_repo or
            (any of ($c2_act*) and (any of ($name_libgcrypt, $pool_kryptex) or 2 of ($c2_act*, $c2_hist*))) or
            (2 of ($c2_hist*) and any of ($name_libgcrypt, $pool_kryptex, $c2_act1, $c2_act2, $c2_act3))
        )
        and filesize < 50MB
}

rule PoeLLM_Specimen : cryptominer specimen
{
    meta:
        description = "PoeLLM specimen pin — exact SHA-256 hashes of known PoeLLM ELF payloads"
        author      = "synthetic-detections"
        date        = "2026-10-09"
        severity    = "critical"
        family      = "poellm"
        reference   = "https://runtimewire.com/article/poellm-exposed-ai-servers-cryptomining-botnet"
    condition:
        filesize < 20MB
        and (
            hash.sha256(0, filesize) == "6fab94577364beec314afae3b082dd680933f08a8349b9f35b92667e8231b501" or
            hash.sha256(0, filesize) == "350a99830b80b5600d3a2757fa996155579ef9d0c53de95f0299f64d280b9bb1" or
            hash.sha256(0, filesize) == "f706aba0d150db2d8f385cbbbb6a6d4fe590a5d184f29e5b1b05fcc4c2cd0932"
        )
}
