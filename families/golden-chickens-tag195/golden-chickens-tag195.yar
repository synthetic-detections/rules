/*
   Golden Chickens MaaS reboot — TAG-195 / TAG-127
   (disclosed 2026-07-24; Recorded Future Insikt Group — financially motivated MaaS)
   -----------------------------------------------------------------------
   The long-running Golden Chickens malware-as-a-service ecosystem (historically
   more_eggs / VenomLNK / TerraLoader) re-tooled with four families, developed
   under the TAG-195 cluster and deployed by affiliate TAG-127 via ClickFix
   fake-CAPTCHA lures:
     - TinyEgg          — lightweight WebSocket backdoor (host profiling,
                          interactive shell, persistence); hands off downstream.
     - ChonkyChicken    — fuller implant; browser credential theft + live
                          browser-session control over the Chrome DevTools
                          Protocol (CDP).
     - Modular ChonkyChicken — controller/plugin architecture, 14 on-demand
                          capability modules (process mgmt, screen capture,
                          keylog, clipboard, audio, browser theft).
     - ChromEggscalator — successor to TerraStealerV2; a modified build of the
                          public Chrome encryption-bypass tool "ChromElevator".

   Host artifacts (all four ship as .ocx COM-server DLLs):
     - Payload filenames: updater.ocx (TinyEgg), mscomctl.ocx / mscom.ocx
       (ChonkyChicken staging), chromelevator.ocx (ChromEggscalator),
       koki.ocx / agent.ocx (modular controller), wpad_capture.ocx (WPAD helper).
     - Persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinComCtl.
     - Staging under %LOCALAPPDATA%\Packages\ ; debug logs %TEMP%\lg.txt
       (ChonkyChicken) and C:\ProgramData\xlog.txt (ChromEggscalator).
     - CDP session theft: launches a hidden Chrome with
       --remote-debugging-port=9222 --user-data-dir=<profile>
       --window-position=-32000,-32000 and drives 127.0.0.1:9222.
     - Modular C2 over WebSocket path /ws/agent (dev listener ws://localhost:3000/ws/agent).

   NOTE on FP-safety: mscomctl.ocx and mscom.ocx are ALSO legitimate Microsoft
   Common Controls filenames, and --remote-debugging-port=9222 is used by many
   benign automation tools. Those weak strings are NEVER matched alone here —
   every path requires co-occurrence with a campaign-unique anchor (the
   Run\WinComCtl value under an .ocx staging name, the chromelevator.ocx /
   koki.ocx / wpad_capture.ocx names, the /ws/agent controller path, the
   -32000 hidden-window offset, or the tracked C2 set).

   Rule 1 — Behavioral: implant host-artifact combination (persistence + CDP
            session-theft + .ocx staging).
   Rule 2 — Structural: modular controller / WebSocket-agent + .ocx family shape.
   Rule 3 — IOC: C2 domains, IPs, and SHA-256 sample hashes.

   Sources:
     https://www.recordedfuture.com/research/tag-195-evolves-maas-ecosystem
     https://thehackernews.com/2026/07/golden-chickens-resurfaces-with-four.html

   Related: [[whatsapp-vbs-rmm-campaign]] (ClickFix delivery sibling)
*/

import "hash"

rule GoldenChickens_TAG195_Implant_Behavior
{
    meta:
        description = "Golden Chickens TAG-195 implant host artifacts — WinComCtl Run persistence, hidden-Chrome CDP session theft, and .ocx staging filenames co-occurring"
        author      = "synthetic-detections"
        date        = "2026-07-26"
        severity    = "critical"
        family      = "golden-chickens-tag195"
        reference   = "https://www.recordedfuture.com/research/tag-195-evolves-maas-ecosystem"

    strings:
        // Persistence: Run value name is campaign-specific
        $run_key   = "CurrentVersion\\Run" ascii wide nocase
        $run_val   = "WinComCtl" ascii wide

        // Campaign-distinctive .ocx staging filenames
        $ocx_chrom = "chromelevator.ocx" ascii wide nocase
        $ocx_koki  = "koki.ocx" ascii wide nocase
        $ocx_wpad  = "wpad_capture.ocx" ascii wide nocase
        $ocx_upd   = "updater.ocx" ascii wide nocase
        $ocx_agent = "agent.ocx" ascii wide nocase

        // CDP session-theft launch of a hidden Chrome
        $cdp_port  = "--remote-debugging-port=9222" ascii wide
        $cdp_hide  = "--window-position=-32000,-32000" ascii wide
        $cdp_udd   = "--user-data-dir=" ascii wide

        // Debug/log artifacts
        $log_lg    = "lg.txt" ascii wide nocase
        $log_xlog  = "xlog.txt" ascii wide nocase

    condition:
        filesize < 30MB
        and (
            // Path 1: persistence value name + a distinctive .ocx staging name
            ( $run_key and $run_val
              and any of ($ocx_chrom, $ocx_koki, $ocx_wpad, $ocx_upd, $ocx_agent) )
            or
            // Path 2: hidden-Chrome CDP theft (the -32000 offset is the anchor)
            // plus the debugging port, co-occurring with a family filename
            ( $cdp_hide and $cdp_port
              and any of ($ocx_chrom, $ocx_koki, $ocx_wpad, $run_val, $log_xlog, $log_lg, $cdp_udd) )
            or
            // Path 3: two or more distinctive .ocx staging names together
            ( 2 of ($ocx_chrom, $ocx_koki, $ocx_wpad, $ocx_upd, $ocx_agent) )
        )
}

rule GoldenChickens_TAG195_Modular_Shape
{
    meta:
        description = "Golden Chickens TAG-195 modular controller / WebSocket-agent shape — /ws/agent channel plus controller .ocx filenames"
        author      = "synthetic-detections"
        date        = "2026-07-26"
        severity    = "high"
        family      = "golden-chickens-tag195"
        reference   = "https://www.recordedfuture.com/research/tag-195-evolves-maas-ecosystem"

    strings:
        // Modular controller WebSocket path / dev listener
        $ws_path   = "/ws/agent" ascii wide nocase
        $ws_dev    = "ws://localhost:3000/ws/agent" ascii wide nocase

        // Controller filenames
        $ocx_koki  = "koki.ocx" ascii wide nocase
        $ocx_agent = "agent.ocx" ascii wide nocase
        $ocx_chrom = "chromelevator.ocx" ascii wide nocase
        $ocx_wpad  = "wpad_capture.ocx" ascii wide nocase

        // ChromElevator provenance (ChromEggscalator base tool)
        $chromelev = "ChromElevator" ascii wide nocase

    condition:
        filesize < 30MB
        and (
            // Modular C2 path co-occurring with a controller filename or
            // ChromElevator provenance — /ws/agent alone is too generic.
            ( any of ($ws_path, $ws_dev)
              and any of ($ocx_koki, $ocx_agent, $ocx_chrom, $ocx_wpad, $chromelev) )
            or
            // Dev-listener string is campaign-specific on its own
            $ws_dev
            or
            // ChromElevator base tool renamed to the campaign .ocx
            ( $chromelev and $ocx_chrom )
        )
}

rule GoldenChickens_TAG195_IOC
{
    meta:
        description = "Golden Chickens TAG-195 network + sample IOCs — C2/lure domains, IPs, and SHA-256 hashes for TinyEgg/ChonkyChicken/ChromEggscalator"
        author      = "synthetic-detections"
        date        = "2026-07-26"
        severity    = "high"
        family      = "golden-chickens-tag195"
        reference   = "https://www.recordedfuture.com/research/tag-195-evolves-maas-ecosystem"

    strings:
        // C2 / lure / staging domains
        $d1 = "aurekh.com" ascii wide nocase
        $d2 = "ahdaratlegalservices.com" ascii wide nocase
        $d3 = "screenly.cam" ascii wide nocase
        $d4 = "paysolutions.ink" ascii wide nocase
        $d5 = "xtrafftrck.net" ascii wide nocase
        $d6 = "thessa.trackgrid.net" ascii wide nocase

        // C2 IPs
        $i1 = "70.34.205.43" ascii wide
        $i2 = "65.20.102.161" ascii wide
        $i3 = "65.20.105.177" ascii wide
        $i4 = "108.61.209.100" ascii wide

    condition:
        filesize < 30MB and any of them
}

rule GoldenChickens_TAG195_SampleHash
{
    meta:
        description = "Golden Chickens TAG-195 pinned SHA-256 sample hashes (TinyEgg, ChonkyChicken, modular ChonkyChicken, ChromEggscalator) — Recorded Future Insikt Group"
        author      = "synthetic-detections"
        date        = "2026-07-26"
        severity    = "critical"
        family      = "golden-chickens-tag195"
        reference   = "https://www.recordedfuture.com/research/tag-195-evolves-maas-ecosystem"

    condition:
        // ChromEggscalator
        hash.sha256(0, filesize) == "b7b322f4638ead5c39031ffc7ca8c791c8d47211b09449f7ceb49f0c32a19b45" or
        hash.sha256(0, filesize) == "33a12c2328db22429c4a515400a57ffeaf7aec48a2a3c299ab6f1ce2d2b0e87d" or
        hash.sha256(0, filesize) == "7ee371ff1a13a3bbd26c925a9beedb1aa0d0c03fe6f63d3803a3a55aaccd0a5b" or
        hash.sha256(0, filesize) == "6922b319dc96d020738bcf466c4d6d9233e4767b68592e1fd9258a232f166ce1" or
        // TinyEgg
        hash.sha256(0, filesize) == "086273cd91f3d6556ed2af915df310e4b184b3db84c3903aa09830d49d1fbb62" or
        hash.sha256(0, filesize) == "652346c05123b4c9556c27f5c5efc4bcd941dd66957e3797c6751246a2bff9c6" or
        hash.sha256(0, filesize) == "f3f4de7eb30c01044ad3c7f2c22376d0ab6f6dc60ef6aee3cde75fd33fbddacc" or
        hash.sha256(0, filesize) == "6c23b7723a9f69ea48f02c8fe13fd60ecbfc2fb28e32e481c46ec968a66c66cd" or
        hash.sha256(0, filesize) == "c455c02ca6b3844027e05d941830de97753c3966dd57c5fa9f1938d8cd1cca3b" or
        hash.sha256(0, filesize) == "d2e1ab10d5a0c16a724aeda8acb46b38f551ade58137969c3bc3c9cdc0a12425" or
        hash.sha256(0, filesize) == "3250adbca0a0bfeab8bd88ee93b603be31fc86b341fd77a152b4843416560d53" or
        hash.sha256(0, filesize) == "5cae5202ddcc29f19f954d81ba138f11b8a4080d05fef63c05a00b9242c06967" or
        hash.sha256(0, filesize) == "ccb6be9211b3946d290e8b23497b8f0e6ac045d1dcde4aaae424680e9029e4eb" or
        // ChonkyChicken
        hash.sha256(0, filesize) == "5d585f2b24503a96011bbe928f42b1b663946e822b309f8496573c66b5ee834c" or
        hash.sha256(0, filesize) == "9a2d714ddd5c48722c35df8a70e97f12d46bcde05dc79b7242a7e692bd346826" or
        hash.sha256(0, filesize) == "d5dea9a51b984be9d7fa76e3e8ff89cfb97c335927331e8e348b9ee269070c1b" or
        hash.sha256(0, filesize) == "c4e2af286ee2ed12375bb66a5bff1a9d3bb5a6579842bc3a28ac00dfae195adc" or
        hash.sha256(0, filesize) == "a3a0aced0f3c13b0b9890ec74802a1cb4936bccfaf5e8a6a52f555c82e09d92f" or
        hash.sha256(0, filesize) == "f3d2ad7440a6f985846710d2dcf0dd2db268dc690837bdf19e4e4e6684483527" or
        hash.sha256(0, filesize) == "6c7619c34497f430c4f7618cfefe07d1defacfae48f6730c20f52e7a7344faa9" or
        hash.sha256(0, filesize) == "41aa04782e436345ef45dc159321d5c0e0e5cba300e55a4d1d3194e5c7c5fd97" or
        hash.sha256(0, filesize) == "337e92c233edc38842c6122fa38e0e84a478f5aa5af2a95ca6be3ca056d925b8" or
        hash.sha256(0, filesize) == "c4e55e9e6837de01f0dadc7db299abd48630bf115a442f09ea0c6a593c559e6f" or
        hash.sha256(0, filesize) == "6adf68448b8541e3cbe4a471845cb6c2ac07613f08698567e5ed76dc2a921834" or
        hash.sha256(0, filesize) == "be7b80f42b0d859b7afaeefca04e46dc10fb5c0a532692bbbfef2924254d1175" or
        hash.sha256(0, filesize) == "45c8cbaeb5c7708e7b8030e701747c65203958e82eddc41f39e0ca93bd36c114" or
        hash.sha256(0, filesize) == "e481d16e51f90c4cc0e7096284b53eef06f7ee8b37a03d92734521d8bca24409" or
        hash.sha256(0, filesize) == "e3153ced59bb0376186b0eee0ec68f0b5aa9ae5820ef8508ae4e67625e1a3581" or
        // Modular ChonkyChicken
        hash.sha256(0, filesize) == "16735cb80d796865b2430aa11d21a539fcb00b027932f2c63e4b5c098d26585b"
}
