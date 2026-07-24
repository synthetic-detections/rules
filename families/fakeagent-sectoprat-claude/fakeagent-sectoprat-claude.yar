/*
   FakeAgent — fake "Claude Desktop" malvertising -> SectopRAT
   (disclosed 2026-07-22/23; Huntress — unattributed, financially motivated)
   -----------------------------------------------------------------------
   A Bing malvertising / SEO-poisoning campaign that abused Anthropic's own
   claude.ai public-artifact hosting as a trust-laundering redirect. A
   sponsored ad for "Claude Desktop app" pointed at the genuine claude.ai
   domain, but resolved to an attacker-built PUBLIC Claude Artifact
   (claude.ai/public/artifacts/ca456f1f-44c0-42af-b329-4f1c7534a877, ~7,100
   views before Anthropic removed it) that redirected to attacker infra
   serving a fake installer. 29 organizations were compromised on 21-22 Jul.

   Kill chain (Huntress):
     - ClaudeDesktop.exe = a renamed, BENIGN JetBrains jcef_helper.exe
       (Chromium Embedded Framework). It DLL-side-loads a malicious,
       VMProtect-packed libcef.dll.
     - libcef.dll retrieves its C2 configuration from Ethereum BNB Smart
       Chain transactions (EtherHiding), then stages persistence: a
       scheduled task running DockerDesktop.exe (same benign jcef binary
       renamed) and a second side-load chain sslconf.exe (benign IBM SPSS
       binary in %APPDATA%\Roaming\Microsoft\EdgeUpdate\Install\) loading a
       malicious tempdir.dll.
     - tempdir.dll gates execution behind GPU/VRAM anti-VM checks (QEMU
       0x1234, VMware 0x15AD, VRAM<1GB, DirectX shader-timing) and decrypts
       the final .NET SectopRAT assembly from appcfg.dat using DirectX
       shader-based AES-256-CTR with a non-standard MixColumns Row-3 tweak.

   Attribution: Huntress ties FakeAgent to the same actor as an April 2026
   fake Docker Desktop campaign (identical libcef.dll side-loading) and
   earlier StealC distribution; the actor's polse[.]us domain was seized by
   Microsoft under Operation Endgame. The novelty is the delivery (claude.ai
   artifact abuse + EtherHiding C2), not an AI capability.

   NOTE: ClaudeDesktop.exe / DockerDesktop.exe / sslconf.exe / the jcef
   libcef.dll are legitimate/benign binaries when unmodified; these rules
   anchor on campaign-specific combinations (the malicious sample hashes, the
   EtherHiding BSC contract addresses, the attacker domains, the Claude
   artifact UUID, and the fake-installer filename co-occurring with the
   malicious side-load/staging markers) so a genuine JetBrains/SPSS install
   does not match.

   Rule 1 — Behavioral: fake-installer side-load + EtherHiding staging chain.
   Rule 2 — Structural: shader-AES / anti-VM / appcfg staging shape.
   Rule 3 — IOC: sample hashes, BSC EtherHiding contracts, domains, C2 IP.

   Sources:
     https://www.huntress.com/blog/fakeagent-claude-desktop-malvertising-ends-in-dotnet-rat
     https://www.bleepingcomputer.com/news/security/fake-claude-app-promoted-by-bing-ads-pushes-sectoprat-malware/
     https://www.helpnetsecurity.com/2026/07/23/anthropic-claude-artifacts-download-malware/
*/

rule FakeAgent_SectopRAT_SideloadChain
{
    meta:
        description = "FakeAgent fake-Claude-Desktop -> SectopRAT side-load chain — ClaudeDesktop/DockerDesktop jcef sideload of malicious libcef.dll + sslconf/tempdir second stage + EtherHiding BSC C2, anchored on campaign-specific combinations"
        author      = "synthetic-detections"
        date        = "2026-07-24"
        severity    = "critical"
        family      = "fakeagent-sectoprat-claude"
        reference   = "https://www.huntress.com/blog/fakeagent-claude-desktop-malvertising-ends-in-dotnet-rat"

    strings:
        // Fake-installer / renamed benign jcef filenames used by the campaign
        $f_claude   = "ClaudeDesktop.exe" ascii wide nocase
        $f_docker   = "DockerDesktop.exe" ascii wide nocase
        // Second side-load chain
        $f_sslconf  = "sslconf.exe" ascii wide nocase
        $f_tempdir  = "tempdir.dll" ascii wide nocase
        $f_appcfg   = "appcfg.dat" ascii wide nocase

        // Distinctive second-stage install path
        $path_edge  = "\\Microsoft\\EdgeUpdate\\Install\\" ascii wide nocase

        // EtherHiding — BNB Smart Chain contract addresses used for C2 config
        $bsc1       = "0xc1907d7be91f95903ad66d775c397302e7dd9228" ascii wide nocase
        $bsc2       = "0xe012d0f34cde9b870e9d9ed566ea5f8fd9b92228" ascii wide nocase

        // Attacker-controlled delivery / C2 domains
        $d_dl       = "claude.ai.download-app.us" ascii wide nocase
        $d_api      = "downloading-api.it.com" ascii wide nocase
        $d_c2       = "5ca8758c-02d0-4a72-89c8-d468b66dda41.com" ascii wide nocase

        // Malicious Claude public-artifact UUID abused as the redirect
        $artifact   = "ca456f1f-44c0-42af-b329-4f1c7534a877" ascii wide nocase

    condition:
        filesize < 60MB
        and (
            // Path 1: any EtherHiding BSC contract or attacker C2 domain or
            // the abused artifact UUID — each is campaign-unique on its own.
            any of ($bsc1, $bsc2, $d_dl, $d_api, $d_c2, $artifact)
            or
            // Path 2: the fake-installer name co-occurring with a malicious
            // side-load / staging artifact (benign jcef alone won't match).
            (
                any of ($f_claude, $f_docker)
                and any of ($f_tempdir, $f_appcfg, $f_sslconf, $bsc1, $bsc2)
            )
            or
            // Path 3: the distinctive second-stage chain: sslconf side-load of
            // tempdir.dll staging appcfg.dat from the EdgeUpdate install path.
            ($f_sslconf and $f_tempdir and ($f_appcfg or $path_edge))
        )
}

rule FakeAgent_SectopRAT_ShaderStagingShape
{
    meta:
        description = "FakeAgent tempdir.dll staging shape — GPU/VRAM anti-VM gate (QEMU/VMware device IDs) plus DirectX shader-based AES-256-CTR decrypt of the appcfg.dat SectopRAT payload"
        author      = "synthetic-detections"
        date        = "2026-07-24"
        severity    = "high"
        family      = "fakeagent-sectoprat-claude"
        reference   = "https://www.huntress.com/blog/fakeagent-claude-desktop-malvertising-ends-in-dotnet-rat"

    strings:
        $appcfg    = "appcfg.dat" ascii wide nocase
        $tempdir   = "tempdir.dll" ascii wide nocase

        // GPU / VRAM anti-VM gate device IDs referenced by tempdir.dll
        $vm_qemu   = "0x1234" ascii wide nocase
        $vm_vmware = "0x15AD" ascii wide nocase

        // DirectX / shader-model decryption stack (unusual for a loader)
        $dx_d3d    = "D3DCompile" ascii wide nocase
        $dx_dev    = "D3D11CreateDevice" ascii wide nocase
        $dx_dxgi   = "IDXGIAdapter" ascii wide nocase
        $dx_cs     = "CSSetShader" ascii wide nocase
        $dx_dvram  = "DedicatedVideoMemory" ascii wide nocase

        // SectopRAT / EtherHiding markers commonly co-present
        $ethhide   = "eth_call" ascii wide nocase
        $bnb_rpc   = "bsc-dataseed" ascii wide nocase

    condition:
        filesize < 60MB
        and (
            // appcfg staging + anti-VM device IDs + any DirectX shader API:
            // the shader-based decrypt is the campaign's signature.
            (
                ($appcfg or $tempdir)
                and any of ($vm_qemu, $vm_vmware)
                and 2 of ($dx_d3d, $dx_dev, $dx_dxgi, $dx_cs, $dx_dvram)
            )
            or
            // appcfg staging + EtherHiding RPC markers + a shader API
            (
                ($appcfg or $tempdir)
                and any of ($ethhide, $bnb_rpc)
                and any of ($dx_d3d, $dx_dev, $dx_dxgi, $dx_cs, $dx_dvram)
            )
        )
}

rule FakeAgent_SectopRAT_IOC
{
    meta:
        description = "Static IOC sweep — FakeAgent sample hashes (Huntress), EtherHiding BNB Smart Chain contracts, delivery/C2 domains, current C2 IP, and the abused claude.ai artifact UUID"
        author      = "synthetic-detections"
        date        = "2026-07-24"
        severity    = "critical"
        family      = "fakeagent-sectoprat-claude"
        reference   = "https://www.huntress.com/blog/fakeagent-claude-desktop-malvertising-ends-in-dotnet-rat"

    strings:
        // Malicious sample hashes (SHA-256)
        $h_tempdir = "1cd58cfba596da296ab1878d74023e00c399345a1b6c2a0e5446c53563f4e3bb" ascii nocase
        $h_libcef  = "26bae4d7012bf59847ab4036a065419c3d4ca47e020479f55b3b2c6d0d21394a" ascii nocase
        $h_sectop  = "1fe3646d27d286db8123297e06ae7badf3e26f352a04f91b6d82c28869a91664" ascii nocase

        // EtherHiding — BNB Smart Chain contract addresses
        $bsc1 = "0xc1907d7be91f95903ad66d775c397302e7dd9228" ascii wide nocase
        $bsc2 = "0xe012d0f34cde9b870e9d9ed566ea5f8fd9b92228" ascii wide nocase

        // Delivery / redirect / C2 domains
        $d_dl  = "claude.ai.download-app.us" ascii wide nocase
        $d_api = "downloading-api.it.com" ascii wide nocase
        $d_c2  = "5ca8758c-02d0-4a72-89c8-d468b66dda41.com" ascii wide nocase

        // Current C2 IP (Huntress, as of 2026-06-12)
        $ip1 = "2.24.131.246" ascii wide

        // Abused Claude public-artifact UUID
        $artifact = "ca456f1f-44c0-42af-b329-4f1c7534a877" ascii wide nocase

    condition:
        any of ($h_*)
        or any of ($bsc*)
        or any of ($d_*)
        or $ip1
        or $artifact
}
