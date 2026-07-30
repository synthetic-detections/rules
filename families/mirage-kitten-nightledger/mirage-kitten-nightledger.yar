/*
   Mirage Kitten - NightLedger backdoor + BridgeHead/ArcBridge tunnelers
   (Kaspersky GReAT, disclosed 2026-07-28; Iran, IRGC-linked)
   -----------------------------------------------------------------------
   NightLedger is a Windows backdoor that masquerades as the Windows auth
   library SspiCli.dll and loads via a delay-load hijack chain
   (AppVShNotify.exe -> RPCRT4.dll -> delay-load SspiCli.dll). It does recon,
   command execution, file ops, process discovery and screenshots. BridgeHead
   and ArcBridge are WebSocket SOCKS5 tunnelers dropped under legitimate DLL
   names (unbcl.dll, libwinpthread-1.dll, IPHLPAPI.dll); BridgeHead gates on a
   lowercased Windows username substring and silently exits on mismatch.

   IMPORTANT: sspicli.dll, libwinpthread-1.dll, iphlpapi.dll and unbcl.dll are
   all LEGITIMATE Windows/MinGW filenames. These rules must NOT key on the
   filename. They anchor on the malware's own unique constants (mutex GUIDs,
   custom C2 delimiters, the unique API endpoint paths, the ArcBridge embedded
   config markers) which do not appear in the real DLLs.

   Rule 1 - NightLedger: mutex GUID + custom C2 delimiter + unique API paths.
   Rule 2 - BridgeHead/ArcBridge: ArcBridge config markers + mutex + tunneler
            WebSocket/SOCKS5 constants.
   Rule 3 - IOC: MD5 pins + C2 domains.

   Related in-repo (Iran-nexus / tunneling): [[cavern-manticore-net-c2]]

   Sources:
     https://securelist.com/mirage-kitten-new-tools/120811/
*/

rule MirageKitten_NightLedger_Backdoor
{
    meta:
        description = "Mirage Kitten NightLedger backdoor - unique mutex GUID, '#%%#' C2 response delimiter, and the campaign's random-looking API endpoint paths (masquerades as SspiCli.dll via AppVShNotify delay-load hijack)"
        author      = "synthetic-detections"
        date        = "2026-07-30"
        severity    = "critical"
        family      = "mirage-kitten-nightledger"
        reference   = "https://securelist.com/mirage-kitten-new-tools/120811/"

    strings:
        $mutex = "A8215357-F99A-44FE-BC65-D8F0434B0C03" ascii wide nocase
        $delim = "#%%#" ascii wide
        // Unique campaign API endpoint paths (random alpha strings, not in real SspiCli)
        $ep1 = "/edfcvfgbhnjmkqwasderfgg" ascii wide
        $ep2 = "/wsdefvvbnhyuijkplmbgfrtt" ascii wide
        $ep3 = "/qasxcdfvgbhnmyuioplkhnj" ascii wide
        // DLL-hijack chain artefact
        $chain = "AppVShNotify" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and filesize < 20MB
        and (
            $mutex
            or any of ($ep*)
            or ( $delim and $chain )
        )
}

rule MirageKitten_Tunnelers_BridgeHead_ArcBridge
{
    meta:
        description = "Mirage Kitten BridgeHead/ArcBridge WebSocket SOCKS5 tunnelers - ArcBridge embedded config markers + mutex, or the tunneler WebSocket/username-gate constants (dropped under legit DLL names unbcl/libwinpthread-1/IPHLPAPI)"
        author      = "synthetic-detections"
        date        = "2026-07-30"
        severity    = "critical"
        family      = "mirage-kitten-nightledger"
        reference   = "https://securelist.com/mirage-kitten-new-tools/120811/"

    strings:
        // ArcBridge embedded config markers + its mutex
        $cfg_start = "<<STARTXX>>" ascii wide
        $cfg_end   = "<<ENDXX>>" ascii wide
        $arc_mutex = "F56E68DA-4A89-46B4-9AC8-7290A7651000" ascii wide nocase
        $arc_cfg_guid = "4B8CC395-A26F-41F1-A1DC-8B993D9D41D2" ascii wide nocase

        // Tunneler WebSocket / SOCKS5 wire constants (require co-occurrence)
        $ws_connect = "GET /connect HTTP/1.1" ascii
        $ws_tok = "token" ascii
        $cmd_open = "OPEN:" ascii wide
        $cmd_dns  = "DNS:" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 20MB
        and (
            ( $cfg_start and $cfg_end )
            or $arc_mutex or $arc_cfg_guid
            or ( $ws_connect and $ws_tok )
            or ( all of ($cmd_open, $cmd_dns) and $ws_tok )
        )
}

rule MirageKitten_IOC
{
    meta:
        description = "Mirage Kitten hard IOCs - NightLedger/BridgeHead/ArcBridge MD5 pins and C2 domains"
        author      = "synthetic-detections"
        date        = "2026-07-30"
        severity    = "high"
        family      = "mirage-kitten-nightledger"
        reference   = "https://securelist.com/mirage-kitten-new-tools/120811/"

    strings:
        $m1 = "A239E655709A2518DD0B7BDBED163679" ascii nocase
        $m2 = "6038D42AF0AFFD1FB263F470C0956F6B" ascii nocase
        $m3 = "AE628EFA305387B633DCE82F9364875B" ascii nocase
        $m4 = "F7D36CC5904A53252D2BB3D21615134F" ascii nocase
        $m5 = "C90F0EFADBF322E5EB1C4103A38C30E6" ascii nocase
        $m6 = "D09B14A2FE01C7363ECC56F5D046162C" ascii nocase
        $m7 = "C832ECD135781B11F59E3FFFB3D2B6AC" ascii nocase
        $m8 = "5FA15EF96808EA82F0A6176F0BB4B386" ascii nocase
        $m9 = "42F847597109DA2A220391BB09D00676" ascii nocase
        $m10 = "AFB1C1583606599C7272CFB33CC6F498" ascii nocase

        $d1 = "realhealthshop.com" ascii wide nocase
        $d2 = "tjconsultingservices.com" ascii wide nocase
        $d3 = "buisness-centeral-transportation.com" ascii wide nocase
        $d4 = "neexportfolio.com" ascii wide nocase

    condition:
        any of them
}
