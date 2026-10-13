/*
   AvisLoader — Windows loader with Tox C2 and process-hiding DLL
   (disclosed 2026-10-13; Varonis Threat Labs / BleepingComputer)
   -----------------------------------------------------------------------
   AvisLoader is a 64-bit Windows loader delivered via ClickFix lures
   hosted on Cloudflare Workers. The main binary (78324.exe) is a 3.4 MB
   statically-linked Tox client with a developer build path retained from
   c-toxcore. It bundles auto.exe (UACME method 41 UAC bypass via the
   ICMLuaUtil COM interface) and hmn_hook.dll (hooks NtQuerySystemInformation
   to hide a specified process). Persistence is achieved through shortcut
   manipulation using a VBScript launcher named VLCAssistant. The loader
   carries 17 additional PE sections of identical size named after common
   packers (Themida, VMProtect, Enigma, UPX) — none executable — likely
   intended to confuse packer identification tools.

   Kill chain:
     - ClickFix lure on workers.dev / trycloudflare.com Quick Tunnel.
     - User pastes command into Run dialog or terminal.
     - 78324.exe drops auto.exe + hmn_hook.dll.
     - auto.exe bypasses UAC via ICMLuaUtil COM elevation (UACME #41).
     - hmn_hook.dll hooks NtQuerySystemInformation to hide process.
     - VLCAssistant VBScript persists via modified desktop/taskbar shortcuts.
     - C2 over Tox P2P (c-toxcore statically linked).
     - Operator panel branded "AvisLoader Command Center".

   Rule 1 — Behavioral: c-toxcore build path + process-hiding hook exports
            + VLCAssistant persistence + fake packer sections.
   Rule 2 — IOC: globally unique tokens and co-occurring indicators.
   Rule 3 — Specimen pin: SHA-256 hashes of 3 known samples.

   Sources:
     https://www.bleepingcomputer.com/news/security/inside-avisloader-a-windows-malware-loader-built-to-resist-disruption/
     https://www.varonis.com/blog/meet-avisloader-a-windows-loader-built-to-outlast-a-takedown
*/

import "hash"
import "pe"

rule AvisLoader_Behavioral : behavioral loader persistence
{
    meta:
        description = "AvisLoader campaign — c-toxcore build path, process-hiding DLL exports, VLCAssistant persistence, fake packer PE sections, ICMLuaUtil UAC bypass"
        author      = "synthetic-detections"
        date        = "2026-10-13"
        severity    = "critical"
        family      = "avisloader"
        reference   = "https://www.bleepingcomputer.com/news/security/inside-avisloader-a-windows-malware-loader-built-to-resist-disruption/"

    strings:
        // Developer build path retained in the Tox-linked loader
        $build_path     = "C:\\Users\\dev\\Desktop\\c-toxcore" ascii wide

        // Process-hiding DLL exported functions
        $hook_start     = "HMN_HideStart" ascii
        $hook_status    = "HMN_HideStatus" ascii
        $hook_stop      = "HMN_HideStop" ascii

        // Hooked API for process hiding
        $ntquery        = "NtQuerySystemInformation" ascii

        // VBScript persistence launcher
        $vlc_assistant  = "VLCAssistant" ascii wide nocase

        // UAC bypass via ICMLuaUtil COM interface (UACME method 41)
        $icmluautil     = "ICMLuaUtil" ascii wide
        $com_clsid      = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide nocase

        // Operator panel branding
        $panel_brand    = "AvisLoader Command Center" ascii wide

        // Fake packer section names used for confusion
        $sec_themida    = ".themida" ascii
        $sec_vmprotect  = ".vmp" ascii
        $sec_enigma     = ".enigma" ascii
        $sec_upx        = "UPX0" ascii

    condition:
        (
            // Path 1: build path + any campaign artifact
            ($build_path and any of ($hook_start, $hook_status, $hook_stop,
                                     $vlc_assistant, $panel_brand,
                                     $icmluautil, $com_clsid)) or

            // Path 2: process-hiding exports co-occurring (all three)
            ($hook_start and $hook_status and $hook_stop and $ntquery) or

            // Path 3: VLCAssistant + UAC bypass combo
            ($vlc_assistant and ($icmluautil or $com_clsid)) or

            // Path 4: panel branding + any operational indicator
            ($panel_brand and any of ($build_path, $hook_start, $vlc_assistant,
                                      $icmluautil)) or

            // Path 5: fake packer sections + c-toxcore build path
            // (3+ packer-named strings in a PE with the build path is
            // structurally distinctive)
            ($build_path and 3 of ($sec_themida, $sec_vmprotect,
                                   $sec_enigma, $sec_upx))
        )
        and filesize < 20MB
}

rule AvisLoader_IOC : ioc loader
{
    meta:
        description = "Static IOC sweep — globally unique tokens from the AvisLoader campaign: c-toxcore build path, process-hiding DLL exports, VLCAssistant launcher, ICMLuaUtil CLSID"
        author      = "synthetic-detections"
        date        = "2026-10-13"
        severity    = "high"
        family      = "avisloader"
        reference   = "https://www.bleepingcomputer.com/news/security/inside-avisloader-a-windows-malware-loader-built-to-resist-disruption/"

    strings:
        // Globally unique — the developer build path is campaign-specific
        $unique_build   = "C:\\Users\\dev\\Desktop\\c-toxcore" ascii wide

        // Panel branding — globally unique
        $unique_panel   = "AvisLoader Command Center" ascii wide

        // DLL export triplet — individually common-ish names, but the
        // HMN_ prefix triplet is campaign-specific
        $hmn_start      = "HMN_HideStart" ascii
        $hmn_status     = "HMN_HideStatus" ascii
        $hmn_stop       = "HMN_HideStop" ascii

        // Campaign anchors for co-occurrence
        $anchor_vlc     = "VLCAssistant" ascii wide nocase
        $anchor_clsid   = "3E5FC7F9-9A51-4367-9063-A120244FBEC7" ascii wide nocase
        $anchor_icm     = "ICMLuaUtil" ascii wide

    condition:
        (
            // Globally unique tokens fire standalone
            $unique_build or
            $unique_panel or

            // All three HMN_ exports together
            ($hmn_start and $hmn_status and $hmn_stop) or

            // CLSID + campaign anchor
            ($anchor_clsid and any of ($anchor_vlc, $anchor_icm, $hmn_start))
        )
        and filesize < 50MB
}

rule AvisLoader_Specimen : loader specimen
{
    meta:
        description = "Specimen pin — exact SHA-256 hashes of 3 known AvisLoader samples (78324.exe loader, auto.exe UAC bypass, hmn_hook.dll process hider)"
        author      = "synthetic-detections"
        date        = "2026-10-13"
        severity    = "critical"
        family      = "avisloader"
        reference   = "https://www.bleepingcomputer.com/news/security/inside-avisloader-a-windows-malware-loader-built-to-resist-disruption/"

    condition:
        filesize < 50MB
        and (
            hash.sha256(0, filesize) == "35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc" or
            hash.sha256(0, filesize) == "f0a6870cb774a55775eda15fd39e8a17eb3169d5b9365186dae8edff07ff3975" or
            hash.sha256(0, filesize) == "cd1e835f52e5f55279dcdf3857e11bc9298ea6caa88eb214ea2d40ff5d38b5f5"
        )
}
