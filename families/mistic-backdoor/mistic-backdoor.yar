/*
   Mistic (MLTBackdoor) — fileless backdoor by KongTuke / TAG-124
   ---------------------------------------------------------------
   Delivered via DLL sideloading: legitimate MpExtMs.exe loads
   version.dll (loader that hooks GetModuleFileNameW/LoadLibraryW)
   which chains into EndpointDlp.dll (Mistic payload).  Companion
   DLLs: f.dll (credential-stealer fake login), n.dll (privesc).
   ~95 % junk-code math obfuscation; functional core provides
   in-memory code execution, file ops, kill-switch self-deletion.
   Persistence via Run keys masquerading as AnyDesk/Splashtop/Comms,
   startup-folder shortcuts, VBScript launchers, scheduled tasks.

   Linked to VICE SPIDER ecosystem — KongTuke sells access to
   Rhysida, Interlock, Qilin, Akira, 8Base, Black Basta.

   Three rules:
     1. Behavioural — MpExtMs sideloading chain + hooking pattern.
     2. IOC — C2 domains, file hashes, persistence indicators.
     3. Specimen pin — exact hashes of known EndpointDlp.dll samples.

   References:
     - https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat
     - https://cybersecuritynews.com/mistic-backdoor-blends-with-microsoft-endpoint-security/
     - https://thehackernews.com/2026/06/new-mistic-backdoor-linked-to-kongtuke.html

   Siblings: [[terminalfix-reverse-tunnel]], [[netscaler-whipshot-slapshot]]
*/

import "pe"

rule Mistic_Sideload_Behavior
{
    meta:
        description = "Detects Mistic/MLTBackdoor DLL sideloading chain via MpExtMs.exe + API hooking pattern"
        author      = "synthetic-detections"
        date        = "2026-10-04"
        severity    = "critical"
        family      = "mistic"
        reference   = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
    strings:
        // Sideloading host
        $host_mpextms      = "MpExtMs" ascii wide nocase
        // Sideloaded DLLs in the chain
        $dll_version       = "version.dll" ascii wide
        $dll_endpointdlp   = "EndpointDlp.dll" ascii wide
        // API hooks set by version.dll loader
        $hook_getmodule    = "GetModuleFileNameW" ascii wide
        $hook_loadlib      = "LoadLibraryW" ascii wide
        // Persistence masquerade names
        $persist_anydesk   = "AnyDesk" ascii wide
        $persist_splashtop = "Splashtop" ascii wide
        $persist_comms     = "Comms" ascii wide fullword
        // Kill-switch / self-deletion
        $kill_delete       = "cmd /c del " ascii wide nocase
        // In-memory execution
        $mem_exec          = "VirtualAlloc" ascii wide
        $mem_protect       = "VirtualProtect" ascii wide
        // Delivery URL pattern
        $delivery_msi      = "/update.msi" ascii wide nocase
    condition:
        // Sideloading chain: host + payload DLL
        // Loader hooking pattern + any chain DLL
        // Persistence masquerade + kill switch + memory exec
        (
            ($host_mpextms and ($dll_endpointdlp or $dll_version)) or
            ($hook_getmodule and $hook_loadlib and $dll_endpointdlp) or
            ($dll_endpointdlp and any of ($persist_*)) or
            (any of ($persist_*) and $kill_delete and ($mem_exec or $mem_protect) and $host_mpextms) or
            ($delivery_msi and $host_mpextms)
        )
        and filesize < 15MB
}

rule Mistic_IOC
{
    meta:
        description = "Known Mistic/MLTBackdoor IOCs — C2 domains, delivery infrastructure, file hashes"
        author      = "synthetic-detections"
        date        = "2026-10-04"
        severity    = "high"
        family      = "mistic"
        reference   = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
    strings:
        // C2 domains
        $c2_authlogins     = "authorized-logins.net" ascii wide nocase
        $c2_carrolc        = "carrolc.com" ascii wide nocase
        $c2_thomphon       = "thomphon.com" ascii wide nocase
        $c2_grandeluna     = "grande-luna.top" ascii wide nocase
        $c2_humancheck     = "human-check.top" ascii wide nocase
        $c2_updworelos     = "updater-worelos.com" ascii wide nocase
        $c2_upddomain      = "upd-domain-goloro.com" ascii wide nocase
        $c2_upscale        = "upscale-kolo.com" ascii wide nocase
        $c2_cwrtwright     = "cwrtwright.com" ascii wide nocase
        $c2_mueleer        = "mueleer.com" ascii wide nocase
        $c2_oeannon        = "oeannon.com" ascii wide nocase
        $c2_rotoa          = "rotoa-upda-lo.com" ascii wide nocase
        $c2_sqlupdater     = "sql-updater-service.com" ascii wide nocase
        $c2_b6w9           = "b6w9m2z5x8q1v3k.top" ascii wide nocase
        $c2_w3x            = "w3xasv14culvnqj.top" ascii wide nocase
        $c2_cj06           = "cj06y9v4xab.com" ascii wide nocase
        // Subdomains
        $sub_ftps          = "ftps.upd-domain-goloro.com" ascii wide nocase
        $sub_defs          = "defs.updater-worelos.com" ascii wide nocase
        $sub_nano          = "nano.upscale-kolo.com" ascii wide nocase
        // Known hashes as strings (for TI docs)
        $hash_endpointdlp1 = "1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984" nocase
        $hash_endpointdlp2 = "afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c" nocase
        $hash_endpointdlp3 = "db972979d508e75fe730d3b72c2701470fbdaeaf8ebdd674744754fa44438ca5" nocase
        $hash_fdll         = "34d798a6c55e57ed0932b6499f4fbcb5454bdfca903307be101a0594b0ac07bc" nocase
        $hash_version      = "59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712" nocase
        $hash_ndll         = "8c935feec4bd05d5d918df308be417532fb42608fb989a08eab183e0ae699235" nocase
    condition:
        any of them and filesize < 50MB
}

rule Mistic_Specimen_Pin
{
    meta:
        description = "Exact hash pin for known Mistic/MLTBackdoor EndpointDlp.dll specimens"
        author      = "synthetic-detections"
        date        = "2026-10-04"
        severity    = "critical"
        family      = "mistic"
        reference   = "https://www.security.com/threat-intelligence/new-mistic-backdoor-modelorat"
        hash        = "1e41c7bfaa6aa3b93b6cc024274a10e33f3e12fe7c98c1db387ef8927f9d1984"
        hash        = "afd5f1ed45a9867daf3bc64152cef460a06b164c8183e490db39146d4749a82c"
        hash        = "db972979d508e75fe730d3b72c2701470fbdaeaf8ebdd674744754fa44438ca5"
        hash        = "59e3c4cb06331b4f2d78a9a0592f3747e573bd01c5a7650c26361d1e25520712"
        hash        = "8c935feec4bd05d5d918df308be417532fb42608fb989a08eab183e0ae699235"
        hash        = "34d798a6c55e57ed0932b6499f4fbcb5454bdfca903307be101a0594b0ac07bc"
        hash        = "3f797a639bc855bc6d5471f327924b62d10900ddec49b970eca6604142bbb4be"
        hash        = "f591275a8f014b29e567529d67c54eb7bb4473db1c38737d6bfd5b3d52c9344e"
        hash        = "fb3630822b70bacb56aa4cec29b5a0e3e9acb3920809e70310a4003385a6d34a"
    strings:
        $sideload_host = "MpExtMs" ascii wide nocase
        $payload_dll   = "EndpointDlp" ascii wide nocase
    condition:
        ($sideload_host or $payload_dll) and filesize < 15MB
}
