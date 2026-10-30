/*
   BLOODALCHEMY -- VAPOR PANDA DLL sideloading implant
   (disclosed 2026-10-29; CrowdStrike "VAPOR PANDA Uses AI-Driven ARTEX")
   -----------------------------------------------------------------------
   Windows implant delivered via GameHook DLL sideloading: a renamed
   legitimate svchost.exe (GameHook binary) loads graphics-hook-filter64.dll,
   which decrypts the BLOODALCHEMY payload from graphics-hook_config.bin.
   Deployed by VAPOR PANDA (China-nexus) as part of an ARTEX-orchestrated
   espionage campaign targeting 200+ organisations in 14 countries.

   Internal development path: D:\ProjectX\Merman_New\
   C2: nginxmysql[.]com, sqlserver-sqlite[.]com, ddduuuppp[.]com

   Rule 1 -- Behaviour: GameHook sideloading triad + Merman_New dev path.
   Rule 2 -- IOC: C2 domains, loader DLL name, config file name.
   Rule 3 -- Specimen pin: three known SHA-256 hashes.

   Sources:
     https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/
   Related families in this repo:
     (none yet)
*/

import "hash"

rule BloodAlchemy_VaporPanda_Behaviour : backdoor behavioral
{
    meta:
        description = "BLOODALCHEMY implant -- GameHook DLL sideloading with graphics-hook loader triad and Merman_New development path"
        author      = "synthetic-detections"
        date        = "2026-10-30"
        severity    = "critical"
        family      = "bloodalchemy-vapor-panda"
        reference   = "https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/"
    strings:
        // GameHook DLL sideloading triad
        $loader   = "graphics-hook-filter64.dll" ascii wide
        $config   = "graphics-hook_config.bin" ascii wide
        // internal development path
        $devpath  = "ProjectX\\Merman_New" ascii wide
        $devpath2 = "ProjectX/Merman_New"
        // C2 infrastructure
        $c2_1     = "nginxmysql.com" ascii wide
        $c2_2     = "sqlserver-sqlite.com" ascii wide
        $c2_3     = "ddduuuppp.com" ascii wide
    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f)
        and (($loader and $config) or any of ($devpath*) or (any of ($c2_*) and ($loader or $config)))
        and filesize < 10MB
}

rule BloodAlchemy_VaporPanda_IOC : backdoor ioc
{
    meta:
        description = "BLOODALCHEMY implant -- C2 domains, GameHook loader artifacts, or ARTEX operational markers in binary context"
        author      = "synthetic-detections"
        date        = "2026-10-30"
        severity    = "high"
        family      = "bloodalchemy-vapor-panda"
        reference   = "https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/"
    strings:
        // C2 domains
        $c2_1   = "nginxmysql.com" ascii wide
        $c2_2   = "sqlserver-sqlite.com" ascii wide
        $c2_3   = "ddduuuppp.com" ascii wide
        // loader DLL and config names
        $loader = "graphics-hook-filter64.dll" ascii wide
        $config = "graphics-hook_config.bin" ascii wide
        // development path
        $merman = "Merman_New" ascii wide
    condition:
        (
            2 of ($c2_*) or
            (any of ($c2_*) and ($loader or $config or $merman)) or
            ($loader and $config and $merman)
        )
        and filesize < 10MB
}

rule BloodAlchemy_VaporPanda_Specimen : backdoor specimen
{
    meta:
        description = "BLOODALCHEMY -- known specimens from the VAPOR PANDA ARTEX campaign (2026-10-29 CrowdStrike disclosure)"
        author      = "synthetic-detections"
        date        = "2026-10-30"
        severity    = "critical"
        family      = "bloodalchemy-vapor-panda"
        reference   = "https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/"
    condition:
        filesize < 10MB
        and (
            hash.sha256(0, filesize) == "49fe70419fd19b81ca8d730a6ef7c1ec71b681d60b390761070d42686c7d2068" or
            hash.sha256(0, filesize) == "3fb5a9fb3e2cb1d6208966bd4e55d10282d19c7250d827efa560463d60a12ee4" or
            hash.sha256(0, filesize) == "364251838edfcf5ef1107fa692da3c5bd9a540482449f645992830134bf807ab"
        )
}
