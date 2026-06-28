/*
   Turla STOCKSTAY — .NET multi-component espionage backdoor
   =========================================================
   Disclosed 2026-06-26 by Google GTIG. Attributed to Turla (Russia /
   FSB). Targets Ukrainian government/military and Italian diplomatic
   entities. Built on .NET Windows Forms framework, communicates over
   secure WebSocket (wss://…/ws), shares K1MORPHER obfuscation with
   the Kazuar implant lineage.

   Four-component architecture:
     STOCKMARKET  — orchestrator, config, IPC, SQLite task store
     STOCKBROKER  — WebSocket C2 tunneler
     STOCKTRADER  — backdoor command handler (FNV1a dispatch)
     MARKETMAKER  — downloader, extracts ZIP, sets persistence

   String deobfuscation uses K1MORPHER (Squirrel3 PRNG), first seen in
   STOCKSTAY April 2025, then in KAZUAR June 2025.

   Three rules:
     1. Turla_STOCKSTAY_Component_Strings
        Behavioural — co-occurrence of component-specific class/method
        names, SQL schema strings, and window names found across the
        four STOCKSTAY modules. High fidelity; these strings survive
        K1MORPHER only in unobfuscated or dumped samples.

     2. Turla_STOCKSTAY_IOCs
        IOC-based — C2 WebSocket endpoints, compromised staging URLs,
        actor GitHub accounts, delivery filenames, persistence artifacts.
        Broader; will match threat-intel documents containing these.

     3. Turla_STOCKSTAY_K1Morpher
        Structural — K1MORPHER obfuscation namespace and Squirrel3
        method names, plus the three Squirrel3 PRNG constants in
        little-endian form. Fires on both STOCKSTAY and KAZUAR samples
        using this shared obfuscation layer.

   Author: synthetic-detections, 2026-06-28
   Sources:
     GTIG: https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering
     The Hacker News: https://thehackernews.com/2026/06/google-details-turlas-new-stockstay.html
     The Record: https://therecord.media/russia-turla-espionage-ukraine-stockstay-malware
   Sample hashes:
     e6d8192960a89d5480868b94088cccdaa1560f9c8a0b0282ced2b7c1f72341b6 (DriversPrinterGraphic.rar)
     9164054d0bf0b7c8820da4f742860940998984555e65820e4fa8dd07b6bd67ec (StockMarketView.exe)
     34fcbe7e90fc87a4f3766469c19a64f24672d7adb99e0198f5ba10d58911368b (StockMarketNet.exe)
     da8a96bc74e265f945f1cc6992c6dc0f9ea36ed1991f7b8d312db79d9bf78c40 (MicrosoftUpdateOneDrive.exe)
     a40bf9c75d1bfa6d66f1179f2321de6589f80d3089d992797a9cb0e84f6196ce (MSViewer.exe)
     b287347a5bff8af360ce0e6500c336b6fe6d97920abc26202c9d843ffebc5f89 (ms-lib-math-core.dll)
*/

rule Turla_STOCKSTAY_Component_Strings
{
    meta:
        description = "STOCKSTAY component class/method names, SQL schema, and window names"
        author      = "synthetic-detections"
        date        = "2026-06-28"
        severity    = "critical"
        family      = "STOCKSTAY"
        reference   = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"

    strings:
        // STOCKMARKET orchestrator -- protocol methods
        $sm_connect  = "ProtocolMessageConnect" wide ascii
        $sm_task     = "ProtocolMessageTask" wide ascii
        $sm_sysinfo  = "ProtocolMessageTaskSysinfo" wide ascii
        $sm_tmr_eng  = "TMR_Engine_Tick" wide ascii
        $sm_tmr_ka   = "TMR_KeepAlive_Tick" wide ascii
        $sm_trade    = "GetDataTrade" wide ascii
        $sm_news     = "InsertDataNews" wide ascii

        // STOCKMARKET SQL schema strings
        $sql_news    = "CREATE TABLE IF NOT EXISTS News (" wide ascii
        $sql_trade   = "CREATE TABLE IF NOT EXISTS Trade (" wide ascii
        $sql_market  = "INSERT INTO Market ( Guid, Version, Config, Status, Launch, Type )" wide ascii

        // STOCKBROKER tunneler
        $sb_status   = "ProtocolMessageStatusConnection" wide ascii
        $sb_server   = "OnGetDataFromServer" wide ascii
        $sb_wm       = "wmCopyData" wide ascii
        $sb_temp     = "tempStorage" wide ascii

        // STOCKTRADER backdoor commands
        $st_del      = "AppDeleteRegistryValue" wide ascii
        $st_unreg    = "AppRegistryKeyExists" wide ascii
        $st_unpack   = "AppUnpackArchive" wide ascii
        $st_sysinfo  = "Sysinfo" wide ascii

        // MARKETMAKER downloader
        $mm_autorun  = "CheckAutoRun" wide ascii
        $mm_setup    = "SetupAutoRun" wide ascii
        $mm_dlzip    = "DownloadAndExtractZip" wide ascii

        // Window/form names
        $wn_editor   = "SMEditorPage" wide
        $wn_net      = "SMNetPage" wide
        $wn_view     = "StockMarketViewPage" wide
        $wn_x128     = "window_system32_x128" wide
        $wn_x64      = "window_system32_x64" wide

        // Crypto container
        $crypto_build = "BuildCryptoContainer" wide ascii
        $crypto_parse = "ParseCryptoContainer" wide ascii

        // Codepage marker
        $codepage    = "Windows-1251" wide

    condition:
        filesize < 15MB
        and (
            // STOCKMARKET: orchestrator protocol + SQL
            (2 of ($sm_*) and 1 of ($sql_*))
            // STOCKBROKER: tunneler strings
            or (2 of ($sb_*))
            // STOCKTRADER: backdoor commands
            or (2 of ($st_*))
            // MARKETMAKER: downloader
            or ($mm_autorun and ($mm_setup or $mm_dlzip))
            // Window names (any two is high-signal)
            or (2 of ($wn_*))
            // Crypto container builders + codepage
            or ($crypto_build and $crypto_parse and $codepage)
        )
}

rule Turla_STOCKSTAY_IOCs
{
    meta:
        description = "STOCKSTAY IOCs — C2 WebSocket endpoints, staging URLs, delivery artifacts, persistence"
        author      = "synthetic-detections"
        date        = "2026-06-28"
        severity    = "high"
        family      = "STOCKSTAY"
        hash1       = "9164054d0bf0b7c8820da4f742860940998984555e65820e4fa8dd07b6bd67ec"
        hash2       = "da8a96bc74e265f945f1cc6992c6dc0f9ea36ed1991f7b8d312db79d9bf78c40"
        hash3       = "a40bf9c75d1bfa6d66f1179f2321de6589f80d3089d992797a9cb0e84f6196ce"

    strings:
        // C2 WebSocket endpoints
        $c2_glitch   = "wool-basalt-clock.glitch.me" ascii nocase
        $c2_workpc   = "weatherdataai.theworkpc.com" ascii nocase
        $c2_canal    = "canal1zac1a.onrender.com" ascii nocase
        $c2_driver   = "driverx86-adobe.onrender.com" ascii nocase
        $c2_google   = "google-ai-labs-it.onrender.com" ascii nocase

        // Compromised staging URLs (Ukrainian government / .ua sites)
        $stage_drs   = "drs.gov.ua/wp-content/themes/twentytwentyfive/docs.zip" ascii nocase
        $stage_zp    = "online.zp.ua/wp-content/uploads/Tools/EditorToolsPdf.zip" ascii nocase
        $stage_base  = "basecon.com.ua/calculator.rar" ascii nocase
        $stage_it    = "circoloesteri.elezioni.idnet.it/admin-election/riepilogo.php" ascii nocase

        // Actor GitHub accounts
        $gh_roberto  = "Roberto1983-ai" ascii
        $gh_chiken   = "ChikenFresh" ascii

        // Delivery filenames
        $fn_msi1     = "Copia.msi" ascii nocase
        $fn_msi2     = "DiplomacyEduAI.msi" ascii nocase
        $fn_drivers  = "DriversPrinterGraphic.rar" ascii nocase
        $fn_viewer   = "MSViewer.exe" ascii nocase
        $fn_driver   = "MSDriver.exe" ascii nocase
        $fn_render   = "MSRender.exe" ascii nocase
        $fn_onedrive = "MicrosoftUpdateOneDrive.exe" ascii nocase

        // Component DLLs (November 2025 variant)
        $dll_math    = "ms-lib-math-core.dll" ascii nocase
        $dll_wmcpdt  = "ms-api-wmcpdt.dll" ascii nocase
        $dll_render  = "ms-api-win-render.dll" ascii nocase

        // Config directory
        $cfg_dir     = "Programs\\SMN\\" ascii nocase

        // Config description (unique fake app description in JSON config)
        $cfg_desc    = "An application for getting information about current events on trading platforms" ascii

    condition:
        filesize < 50MB
        and any of them
}

rule Turla_STOCKSTAY_K1Morpher
{
    meta:
        description = "K1MORPHER Squirrel3 string obfuscation — shared between STOCKSTAY and KAZUAR"
        author      = "synthetic-detections"
        date        = "2026-06-28"
        severity    = "critical"
        family      = "STOCKSTAY"
        reference   = "https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering"

    strings:
        // K1MORPHER namespace/class (wide for .NET metadata)
        $ns_k1       = "K1" wide
        $cls_morpher = "Morpher" wide

        // Squirrel3 PRNG method names
        $fn_sq3      = "Squirrel3" wide ascii
        $fn_dec_str  = "DecryptStringSimple" wide ascii
        $fn_dec_arr  = "DecryptArraySimple" wide ascii
        $fn_dec_int  = "DecryptIntSimple" wide ascii
        $fn_dec_lng  = "DecryptLongSimple" wide ascii
        $fn_dec_flt  = "DecryptFloatSimple" wide ascii
        $fn_dec_dbl  = "DecryptDoubleSimple" wide ascii
        $fn_inject   = "InjectedSeedCipher" wide ascii
        $fn_squ1     = "_squ_ui1" wide ascii
        $fn_squ2     = "_squ_ui2" wide ascii
        $fn_squ3     = "_squ_ui3" wide ascii

        // Squirrel3 constants (little-endian 32-bit)
        $noise1      = { 4d 7a 29 b5 }
        $noise2      = { a4 1d e3 68 }
        $noise3      = { e9 c4 56 1b }

    condition:
        filesize < 15MB
        and (
            // Method-name based: Squirrel3 + any decrypt method
            ($fn_sq3 and 2 of ($fn_dec_*))
            // Namespace + methods
            or ($ns_k1 and $cls_morpher and 1 of ($fn_*))
            // Constant-based: all three Squirrel3 PRNG noise constants
            or (all of ($noise*) and 1 of ($fn_sq3, $fn_inject, $fn_squ*))
        )
}
