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
        $typo_distrub1   = "distrub_mode" ascii
        $typo_distrub2   = "distrub_mode_enabled" ascii
        $typo_disabe     = "disabe_calls" ascii
        $typo_keyloger1  = "stop_keyloger" ascii
        $typo_keyloger2  = "start_keyloger" ascii
        $typo_clian      = "notification_clian" ascii
        $typo_noiti      = "noitificationp" ascii
        $typo_traker     = "unlocktraker" ascii

        // Russian loanword — "domen" = domain
        $ru_domen        = "update_config_domen" ascii

        // Unique compound command names (no legitimate app uses these)
        $uniq_liveblock  = "liveoverlayblock" ascii
        $uniq_protector  = "protectorgoogle_disable" ascii
        $uniq_pinlock    = "showpinlockoverlay" ascii
        $uniq_patlock    = "showpatternlockoverlay" ascii
        $uniq_keepon     = "keepscreenonforever" ascii
        $uniq_dontstop   = "dontstoploadingoverlay" ascii
        $uniq_redalert   = "disable_red_alert_for_default" ascii
        $uniq_editext    = "editextnow" ascii

        // Overlay subsystem markers
        $ovl_live16      = "liveoverlay16" ascii
        $ovl_sms16       = "sms_overlay_16" ascii
        $ovl_call16      = "call_overlay_16" ascii
        $ovl_wake        = "overlaywake_true" ascii

        // Play Protect manipulation
        $gplay_open      = "open_google_play_protect" ascii
        $gplay_full      = "gplay_full_disable" ascii

        // Packed-variant component names — visible in UTF-16LE string
        // pool even when command strings are encrypted. Observed in
        // com.fav.qca (be8573...) and com.oel.myx (fe41e6...).
        $comp_overlay    = "MyOverlayActivity" ascii wide
        $comp_smsrecv    = "SmsChangeReceiver" ascii wide
        $comp_webview    = "WebViewActivity" ascii wide
        $comp_install    = "INSTALL_RESULT" ascii wide

        // Root detection — common in banking trojans, adds signal
        $root_cloak      = "rootcloak" ascii wide
        $root_superuser  = "com.koushikdutta.superuser" ascii wide
        $root_noshufou   = "com.noshufou.android" ascii wide

    condition:
        filesize < 100MB
        and (
            // Path 1: any 2 typo strings — near-zero false positive rate
            2 of ($typo_*)
            or
            // Path 2: Russian "domen" + any unique compound
            ($ru_domen and any of ($uniq_*))
            or
            // Path 3: 1 typo + 2 unique compounds
            (1 of ($typo_*) and 2 of ($uniq_*))
            or
            // Path 4: lock-screen overlay pair
            ($uniq_pinlock and $uniq_patlock)
            or
            // Path 5: Play Protect targeting + overlay subsystem
            (any of ($gplay_*) and $uniq_protector and any of ($ovl_*))
            or
            // Path 6: 3+ unique compounds — even without typos
            3 of ($uniq_*)
            or
            // Path 7: packed variant — overlay + SMS component names
            // together are distinctive even without unpacking
            ($comp_overlay and $comp_smsrecv)
            or
            // Path 8: overlay activity + WebView + root detection
            ($comp_overlay and $comp_webview and any of ($root_*))
            or
            // Path 9: 3+ packed-variant markers together
            (3 of ($comp_overlay, $comp_smsrecv, $comp_webview, $comp_install))
        )
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
        $cred_pin        = "request_pin" ascii
        $cred_pattern    = "request_pattern" ascii
        $cred_password   = "request_password" ascii

        // VNC remote control
        $vnc_start       = "start_vnc" ascii
        $vnc_stop        = "stop_vnc" ascii

        // Keylogger / UI logger subsystem
        $key_startui     = "startuilogger" ascii
        $key_stopui      = "stopuilogger" ascii
        $key_textextr    = "clicktextextract" ascii
        $key_descextr    = "clickdescextract" ascii
        $key_loop        = "start_uilogger_loop" ascii

        // SMS interception and manipulation
        $sms_send        = "send_sms" ascii
        $sms_change      = "change_sms" ascii
        $sms_change_auto = "change_sms_auto" ascii
        $sms_get_last    = "get_last_sms" ascii

        // Device control
        $dev_unlock      = "unlock_phone" ascii
        $dev_keepon      = "keepscreenonforever" ascii
        $dev_keepoff     = "keepscreenoff" ascii
        $dev_mute        = "mutevolume" ascii

        // Overlay injection management
        $ovl_injects     = "update_config_injects" ascii
        $ovl_block       = "inject_block" ascii
        $ovl_unlock      = "inject_unlock" ascii
        $ovl_black_show  = "show_black_overlay" ascii
        $ovl_black_hide  = "hide_black_overlay" ascii
        $ovl_touchable   = "make_overlay_not_touchable" ascii
        $ovl_hardstop    = "hard_stop_overlay_now" ascii

        // App and permission management
        $app_hide        = "hide_app" ascii
        $app_reset       = "reset_app_list" ascii
        $app_permall     = "permission_all_files" ascii
        $app_permlist    = "btn_permission_list" ascii

        // Navigation / UI automation
        $nav_launch      = "btn_launchapp" ascii
        $nav_power       = "btn_power_dialog" ascii
        $nav_settings    = "btn_settings" ascii

        // Configuration updates
        $cfg_domen       = "update_config_domen" ascii
        $cfg_slots       = "update_slots" ascii
        $cfg_prefix      = "update_prefix" ascii
        $cfg_time        = "update_time" ascii

        // Notification control
        $notif_listen    = "notification_listen_disable" ascii
        $notif_setting   = "notification_setting" ascii

        // Clipboard hijacking
        $clip_copy       = "copyclipboard" ascii

        // Screenshot / grabber
        $grab_stop       = "stop_start_grabber" ascii
        $grab_screenshot = "loading_screenshot" ascii

    condition:
        filesize < 100MB
        and (
            // Path 1: protocol density — 15+ command strings from the
            // 137-command set strongly indicate Rokarolla's dispatcher
            15 of them
            or
            // Path 2: credential theft triad + any control mechanism
            ($cred_pin and $cred_pattern and $cred_password
             and (any of ($vnc_*) or any of ($key_*) or any of ($sms_*)))
            or
            // Path 3: full surveillance suite — VNC + keylogger +
            // SMS + overlay subsystems all present
            (any of ($vnc_*) and any of ($key_*) and any of ($sms_*)
             and any of ($ovl_*))
            or
            // Path 4: overlay hardening commands — unique to RATs that
            // need overlays to survive user interaction
            ($ovl_touchable and $ovl_hardstop and any of ($ovl_black_show, $ovl_black_hide))
        )
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
        $c2_beralisvc    = "beralisvc.info" ascii nocase
        $c2_blestorians  = "blestorians.cfd" ascii nocase
        $c2_abiorime     = "abiorime.cfd" ascii nocase
        $c2_morevoms     = "morevoms.cfd" ascii nocase

        // Distribution URL (fake TikTok / Chrome download site)
        $dist_url        = "infocontablidades.it.com" ascii nocase

        // Observed APK package names (from MalwareBazaar samples)
        $pkg_fav         = "com.fav.qca" ascii wide
        $pkg_oel         = "com.oel.myx" ascii wide

        // APK sample hashes (15 of 40 from Zimperium IOC repository)
        $hash01 = "890ecea4ebe4fea692ad36adf02abeb37c181cb7bdb6122cd52d9aaafe7d6cf3" ascii nocase
        $hash02 = "7aa389f25997610a96f014977eecd6d69142bdc63841e0d84976e3e621831303" ascii nocase
        $hash03 = "4e2cbefc6bdbfdb6e885057ce47d460e3d3355a5e97db51b22e9c5a14e14302b" ascii nocase
        $hash04 = "d7d960ef10b08c472ad397b6fd9e9481338b2077c7c2f44d3dc2c65b19345ae0" ascii nocase
        $hash05 = "57307ee8a3cda10730eacecaf789fab6f8771f9d29397e07c31a6bd4551bba10" ascii nocase
        $hash06 = "43888be8debbbd74012484d4e4f9a1c70c2ff3970e0bf499c9aebba9776930a1" ascii nocase
        $hash07 = "1d3270a9141f8f16047799f1132633d72fd421b6c8f1878b5ef04ced6add4db8" ascii nocase
        $hash08 = "696ef29f77a91aa91279c83088a07ab137d5049dc096ef862a35f9d890a552b3" ascii nocase
        $hash09 = "c734a665f04eb9ab17047e65940fc35bad0221d59c2fc4fd0d170f2181514034" ascii nocase
        $hash10 = "f0c18f045e3bb0193ef1169f5fa1abff7aa47e9a23da35cf67bbb9548a5e32c0" ascii nocase
        $hash11 = "1f4c70cb317ffd25adc828fbac3bb8f07739e23111f7b7905926489fe35f8973" ascii nocase
        $hash12 = "be8573971b85fda81a2fac27adb7a3a9b2cf7e1d9bdf713361a725324d378d34" ascii nocase
        $hash13 = "a5e6763b09553691c8b42deefb725fa3b8c133a03a34cea87740b1f13d08bac3" ascii nocase
        $hash14 = "c3cfe522d2da15b033f65eb5377bf9e99be598dc4c21729e6f168dbc8f19540b" ascii nocase
        $hash15 = "8ddbcebe1014a645855986e85b2c54ee167baf1e9a0d74179faf81a5ee6878f4" ascii nocase

    condition:
        filesize < 200MB
        and (
            // Any C2 domain
            any of ($c2_*)
            or
            // Distribution URL
            $dist_url
            or
            // Observed package names
            any of ($pkg_*)
            or
            // Any known sample hash
            any of ($hash*)
        )
}
