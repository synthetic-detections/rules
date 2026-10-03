/*
   Rokarolla Android banking trojan (disclosed 2026-06-17, Zimperium zLabs)
   -----------------------------------------------------------------------
   Mobile banking trojan targeting 217 banking and cryptocurrency apps
   with 137 remote commands enabling full device takeover. Distributed
   via fake TikTok and Chrome download sites (infocontablidades[.]it[.]com);
   dropper masquerades as Google Play Protect. Named after its C2
   infrastructure (beralisvc[.]info, blestorians[.]cfd, abiorime[.]cfd,
   morevoms[.]cfd).

   Capabilities: overlay attacks (fake login screens pulled from C2 and
   cached in local SQLite), lock-screen PIN/pattern/password theft,
   clipboard hijacking (crypto wallet address swap), keylogger via
   accessibility node parsing, SMS interception and sending, VNC-based
   remote control, screenshot surveillance (PNG compression), Google
   Play Protect disablement, call blocking via CallScreeningService,
   and dynamic C2 domain updates.

   The command set contains at least 8 distinctive misspellings
   ("distrub_mode", "disabe_calls", "stop_keyloger", "notification_clian",
   "noitificationp", "unlocktraker") and the Russian loanword "domen"
   (домен = domain) in "update_config_domen", indicating a non-native
   English, likely Russian-speaking developer. These typos persist
   across all known samples and are the strongest behavioral anchors.

   First Android/APK family in this repository. Rules scan DEX string
   tables; in standard APKs classes.dex is stored uncompressed (STORED
   method) so YARA matches raw APK bytes directly.

   IMPORTANT: distributed APKs are heavily packed — command strings are
   encrypted inside Cyrillic-obfuscated asset paths, AndroidManifest.xml
   uses non-standard ZIP compression (method 61923), and DEX classes are
   stubs for a runtime unpacker. Rules 1-2 fire on unpacked DEX only.
   Rule 1 includes packed-variant paths using component names visible
   in the UTF-16LE string pool (MyOverlayActivity, SmsChangeReceiver)
   that persist across both observed variants (com.fav.qca, com.oel.myx).

   Rule 1 — Behavioral: developer typos and unique compound command
            names (unpacked DEX), plus packed-variant component names.
   Rule 2 — Structural: command protocol density — clusters of
            capability-specific strings across credential theft, VNC,
            keylogger, SMS, overlay, and device control subsystems.
            Fires on unpacked DEX only.
   Rule 3 — IOC: C2 domains, distribution URL, sample SHA-256 hashes,
            observed package names.

   Sources:
     https://zimperium.com/blog/rokarolla-android-banker-with-complete-device-takeover-capabilities
     https://www.bleepingcomputer.com/news/security/new-rokarolla-android-malware-targets-217-banking-crypto-apps/
     https://github.com/Zimperium/IOC/tree/master/2026-06-Rokarolla/
*/

rule Rokarolla_Banker_Behavior
{
    meta:
        description = "Rokarolla banking trojan — developer typos and unique compound command names in DEX bytecode"
        author      = "synthetic-detections"
        date        = "2026-06-19"
        severity    = "critical"
        family      = "rokarolla-android-banker"
        reference   = "https://zimperium.com/blog/rokarolla-android-banker-with-complete-device-takeover-capabilities"
    strings:
        // Misspelled command strings — developer typos, strongest anchors
        $typo_distrub1  = "distrub_mode"
        $typo_distrub2  = "distrub_mode_enabled"
        $typo_disabe    = "disabe_calls"
        $typo_keyloger1 = "stop_keyloger"
        $typo_keyloger2 = "start_keyloger"
        $typo_clian     = "notification_clian"
        $typo_noiti     = "noitificationp"
        $typo_traker    = "unlocktraker"
        // Russian loanword — "domen" = domain
        $ru_domen       = "update_config_domen"
        // Unique compound command names (no legitimate app uses these)
        $uniq_liveblock = "liveoverlayblock"
        $uniq_protector = "protectorgoogle_disable"
        $uniq_pinlock   = "showpinlockoverlay"
        $uniq_patlock   = "showpatternlockoverlay"
        $uniq_keepon    = "keepscreenonforever"
        $uniq_dontstop  = "dontstoploadingoverlay"
        $uniq_redalert  = "disable_red_alert_for_default"
        $uniq_editext   = "editextnow"
        // Overlay subsystem markers
        $ovl_live16     = "liveoverlay16"
        $ovl_sms16      = "sms_overlay_16"
        $ovl_call16     = "call_overlay_16"
        $ovl_wake       = "overlaywake_true"
        // Play Protect manipulation
        $gplay_open     = "open_google_play_protect"
        $gplay_full     = "gplay_full_disable"
        // Packed-variant component names — visible in UTF-16LE string
        // pool even when command strings are encrypted. Observed in
        // com.fav.qca (be8573...) and com.oel.myx (fe41e6...).
        $comp_overlay   = "MyOverlayActivity" ascii wide
        $comp_smsrecv   = "SmsChangeReceiver" ascii wide
        $comp_webview   = "WebViewActivity" ascii wide
        $comp_install   = "INSTALL_RESULT" ascii wide
        // Root detection — common in banking trojans, adds signal
        $root_cloak     = "rootcloak" ascii wide
        $root_superuser = "com.koushikdutta.superuser" ascii wide
        $root_noshufou  = "com.noshufou.android" ascii wide
    condition:
        // Path 1: any 2 typo strings — near-zero false positive rate
        // Path 2: Russian "domen" + any unique compound
        // Path 3: 1 typo + 2 unique compounds
        // Path 4: lock-screen overlay pair
        // Path 5: Play Protect targeting + overlay subsystem
        // Path 6: 3+ unique compounds — even without typos
        // Path 7: packed variant — overlay + SMS component names
        // together are distinctive even without unpacking
        // Path 8: overlay activity + WebView + root detection
        // Path 9: 3+ packed-variant markers together
        (
            2 of ($typo_*) or
            $ru_domen and any of ($uniq_*) or
            any of ($typo_*) and 2 of ($uniq_*) or
            $uniq_pinlock and $uniq_patlock or
            any of ($gplay_*) and $uniq_protector and any of ($ovl_*) or
            3 of ($uniq_*) or
            $comp_overlay and $comp_smsrecv or
            $comp_overlay and $comp_webview and any of ($root_*) or
            3 of ($comp_overlay, $comp_smsrecv, $comp_webview, $comp_install)
        ) and
        filesize < 100MB
}

rule Rokarolla_Command_Protocol
{
    meta:
        description = "Rokarolla 137-command C2 protocol — credential theft, VNC, keylogger, SMS, overlay, and device control subsystems"
        author      = "synthetic-detections"
        date        = "2026-06-19"
        severity    = "critical"
        family      = "rokarolla-android-banker"
        reference   = "https://github.com/Zimperium/IOC/tree/master/2026-06-Rokarolla/commands.md"
    strings:
        // Credential theft commands
        $cred_pin        = "request_pin"
        $cred_pattern    = "request_pattern"
        $cred_password   = "request_password"
        // VNC remote control
        $vnc_start       = "start_vnc"
        $vnc_stop        = "stop_vnc"
        // Keylogger / UI logger subsystem
        $key_startui     = "startuilogger"
        $key_stopui      = "stopuilogger"
        $key_textextr    = "clicktextextract"
        $key_descextr    = "clickdescextract"
        $key_loop        = "start_uilogger_loop"
        // SMS interception and manipulation
        $sms_send        = "send_sms"
        $sms_change      = "change_sms"
        $sms_change_auto = "change_sms_auto"
        $sms_get_last    = "get_last_sms"
        // Device control
        $dev_unlock      = "unlock_phone"
        $dev_keepon      = "keepscreenonforever"
        $dev_keepoff     = "keepscreenoff"
        $dev_mute        = "mutevolume"
        // Overlay injection management
        $ovl_injects     = "update_config_injects"
        $ovl_block       = "inject_block"
        $ovl_unlock      = "inject_unlock"
        $ovl_black_show  = "show_black_overlay"
        $ovl_black_hide  = "hide_black_overlay"
        $ovl_touchable   = "make_overlay_not_touchable"
        $ovl_hardstop    = "hard_stop_overlay_now"
        // App and permission management
        $app_hide        = "hide_app"
        $app_reset       = "reset_app_list"
        $app_permall     = "permission_all_files"
        $app_permlist    = "btn_permission_list"
        // Navigation / UI automation
        $nav_launch      = "btn_launchapp"
        $nav_power       = "btn_power_dialog"
        $nav_settings    = "btn_settings"
        // Configuration updates
        $cfg_domen       = "update_config_domen"
        $cfg_slots       = "update_slots"
        $cfg_prefix      = "update_prefix"
        $cfg_time        = "update_time"
        // Notification control
        $notif_listen    = "notification_listen_disable"
        $notif_setting   = "notification_setting"
        // Clipboard hijacking
        $clip_copy       = "copyclipboard"
        // Screenshot / grabber
        $grab_stop       = "stop_start_grabber"
        $grab_screenshot = "loading_screenshot"
    condition:
        // Path 1: protocol density — 15+ command strings from the
        // 137-command set strongly indicate Rokarolla's dispatcher
        // Path 2: credential theft triad + any control mechanism
        // Path 3: full surveillance suite — VNC + keylogger +
        // SMS + overlay subsystems all present
        // Path 4: overlay hardening commands — unique to RATs that
        // need overlays to survive user interaction
        (
            15 of them or
            $cred_pin and $cred_pattern and $cred_password and (any of ($vnc_*) or any of ($key_*) or any of ($sms_*)) or
            any of ($vnc_*) and any of ($key_*) and any of ($sms_*) and any of ($ovl_*) or
            $ovl_touchable and $ovl_hardstop and any of ($ovl_black_show, $ovl_black_hide)
        ) and
        filesize < 100MB
}

rule Rokarolla_IOC
{
    meta:
        description = "Static IOC sweep — C2 domains, distribution URL, APK sample hashes"
        author      = "synthetic-detections"
        date        = "2026-06-19"
        severity    = "high"
        family      = "rokarolla-android-banker"
        reference   = "https://github.com/Zimperium/IOC/tree/master/2026-06-Rokarolla/"
    strings:
        // C2 domains
        $c2_beralisvc   = "beralisvc.info" nocase
        $c2_blestorians = "blestorians.cfd" nocase
        $c2_abiorime    = "abiorime.cfd" nocase
        $c2_morevoms    = "morevoms.cfd" nocase
        // Distribution URL (fake TikTok / Chrome download site)
        $dist_url       = "infocontablidades.it.com" nocase
        // Observed APK package names (from MalwareBazaar samples)
        $pkg_fav        = "com.fav.qca" ascii wide
        $pkg_oel        = "com.oel.myx" ascii wide
        // APK sample hashes (15 of 40 from Zimperium IOC repository)
        $hash01         = "890ecea4ebe4fea692ad36adf02abeb37c181cb7bdb6122cd52d9aaafe7d6cf3" nocase
        $hash02         = "7aa389f25997610a96f014977eecd6d69142bdc63841e0d84976e3e621831303" nocase
        $hash03         = "4e2cbefc6bdbfdb6e885057ce47d460e3d3355a5e97db51b22e9c5a14e14302b" nocase
        $hash04         = "d7d960ef10b08c472ad397b6fd9e9481338b2077c7c2f44d3dc2c65b19345ae0" nocase
        $hash05         = "57307ee8a3cda10730eacecaf789fab6f8771f9d29397e07c31a6bd4551bba10" nocase
        $hash06         = "43888be8debbbd74012484d4e4f9a1c70c2ff3970e0bf499c9aebba9776930a1" nocase
        $hash07         = "1d3270a9141f8f16047799f1132633d72fd421b6c8f1878b5ef04ced6add4db8" nocase
        $hash08         = "696ef29f77a91aa91279c83088a07ab137d5049dc096ef862a35f9d890a552b3" nocase
        $hash09         = "c734a665f04eb9ab17047e65940fc35bad0221d59c2fc4fd0d170f2181514034" nocase
        $hash10         = "f0c18f045e3bb0193ef1169f5fa1abff7aa47e9a23da35cf67bbb9548a5e32c0" nocase
        $hash11         = "1f4c70cb317ffd25adc828fbac3bb8f07739e23111f7b7905926489fe35f8973" nocase
        $hash12         = "be8573971b85fda81a2fac27adb7a3a9b2cf7e1d9bdf713361a725324d378d34" nocase
        $hash13         = "a5e6763b09553691c8b42deefb725fa3b8c133a03a34cea87740b1f13d08bac3" nocase
        $hash14         = "c3cfe522d2da15b033f65eb5377bf9e99be598dc4c21729e6f168dbc8f19540b" nocase
        $hash15         = "8ddbcebe1014a645855986e85b2c54ee167baf1e9a0d74179faf81a5ee6878f4" nocase
    condition:
        // Any C2 domain
        // Distribution URL
        // Observed package names
        // Any known sample hash
        (
            any of ($c2_*) or
            $dist_url or
            any of ($pkg_*) or
            any of ($hash*)
        ) and
        filesize < 200MB
}
