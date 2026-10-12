/*
   Midnight Mimosa — firmware supply-chain ad-fraud / residential-proxy, 2026-10-08
   ---------------------------------------------------------------------------------
   Supply-chain campaign embedding ad-fraud and residential-proxy malware in
   firmware of budget MediaTek Android phones. The enabler component
   (com.android.system.lite and variants) loads a native library (libeasy.so
   or libunionprt.so) that RC4-decrypts a hidden framework APK
   (cn.kw.lib.hex), which then downloads remote DEX updates (kwlib.jar/
   kwlib.next) for RCE. Partner dropper packages (com.mobile.applock.*,
   com.mb.applock.*) deploy in parallel. The campaign disables and re-enables
   the Play Store (com.android.vending) to bypass protections.

   Related families: [[badbox-headunit-moyu]], [[wallpaper-chrome-adfraud]].

   Rule 1 — behavioural: enabler package + native RC4 loader + C2 domain,
            OR Play Store disable/enable with system-privilege package names.
   Rule 2 — IOC sweep: C2 domains, enabler and dropper package names,
            native libraries, framework files (co-occurrence guarded).
   Rule 3 — specimen pin: DEX/ELF/APK with enabler package name strings +
            native loader reference, bounded by filesize.

   Sources:
     https://www.bitdefender.com/en-us/blog/labs/midnight-mimosa-malware
*/

rule MidnightMimosa_FirmwareBackdoor_Behavioral : backdoor behavioral adfraud
{
    meta:
        description = "Midnight Mimosa behavioural — enabler package with native RC4 loader and C2, or Play Store disable/enable with system-privilege packages"
        author      = "synthetic-detections"
        date        = "2026-10-08"
        severity    = "critical"
        family      = "midnight-mimosa"
        reference   = "https://www.bitdefender.com/en-us/blog/labs/midnight-mimosa-malware"
    strings:
        // Enabler package names — system-privilege components baked into firmware
        $pkg_lite    = "com.android.system.lite" ascii wide
        $pkg_prot    = "com.android.sys.prot" ascii wide
        $pkg_gmsprot = "com.android.sys.gmsprot" ascii wide
        $pkg_bcprot  = "com.android.sys.bcprot" ascii wide
        $pkg_dts     = "com.android.sys.dts" ascii wide
        $pkg_weiapps = "com.android.weiapps" ascii wide
        $pkg_weapps  = "com.android.weapps" ascii wide
        $pkg_szcz    = "com.android.non.szcz" ascii wide

        // Native loader that RC4-decrypts the hidden framework
        $native1 = "libeasy.so" ascii wide
        $native2 = "libunionprt.so" ascii wide

        // C2 domains
        $c2_weather = "api.weatherlive.world" ascii wide
        $c2_showtime = "oss.showtimetool.com" ascii wide
        $c2_cgb     = "cgb.jingongbuxiao.com" ascii wide

        // Play Store manipulation pattern
        $pm_disable = "pm disable com.android.vending" ascii wide
        $pm_enable  = "pm enable com.android.vending" ascii wide

    condition:
        (
            (
                // Pattern A: enabler package + native loader + any C2 domain
                any of ($pkg_*) and any of ($native*) and any of ($c2_*)
            )
            or
            (
                // Pattern B: Play Store disable/enable pair with enabler package
                ($pm_disable or $pm_enable) and any of ($pkg_*)
            )
        )
        and filesize < 20MB
}

rule MidnightMimosa_IOC : adfraud proxy ioc
{
    meta:
        description = "Midnight Mimosa IOC sweep — C2 domains, enabler/dropper packages, native libraries, framework files"
        author      = "synthetic-detections"
        date        = "2026-10-08"
        severity    = "high"
        family      = "midnight-mimosa"
        reference   = "https://www.bitdefender.com/en-us/blog/labs/midnight-mimosa-malware"
    strings:
        // C2 domains — globally unique, fire standalone
        $c2_weather  = "api.weatherlive.world" ascii wide
        $c2_showtime = "oss.showtimetool.com" ascii wide
        $c2_cgb      = "cgb.jingongbuxiao.com" ascii wide

        // Enabler packages
        $pkg_lite    = "com.android.system.lite" ascii wide
        $pkg_prot    = "com.android.sys.prot" ascii wide
        $pkg_gmsprot = "com.android.sys.gmsprot" ascii wide
        $pkg_bcprot  = "com.android.sys.bcprot" ascii wide
        $pkg_dts     = "com.android.sys.dts" ascii wide
        $pkg_weiapps = "com.android.weiapps" ascii wide
        $pkg_weapps  = "com.android.weapps" ascii wide
        $pkg_szcz    = "com.android.non.szcz" ascii wide

        // Partner dropper packages
        $drp_en  = "com.mobile.applock.en" ascii wide
        $drp_wt  = "com.mobile.applock.wt" ascii wide
        $drp_wg  = "com.mobile.applock.wg" ascii wide
        $drp_tg  = "com.mobile.applock.tg" ascii wide
        $drp_a02 = "com.mb.applock.a02" ascii wide
        $drp_ea  = "com.mb.applock.ea" ascii wide

        // Campaign markers — build strings, RC4 key, SDK name
        $marker_enloader = "EnLoaderLib" ascii wide
        $marker_rc4key   = "rc4@sec.com" ascii wide
        $marker_intent   = "com.media.am.intent.action.BIND_SERVICE" ascii wide
        $marker_vdgtjy   = "vdgtjy" ascii wide
        $marker_sdk      = "com.gogo.bb.sdk" ascii wide

        // Native loader libraries
        $native1 = "libeasy.so" ascii wide
        $native2 = "libunionprt.so" ascii wide

        // Framework / payload filenames
        $fw_hex     = "cn.kw.lib.hex" ascii wide
        $fw_kwlib   = "kwlib.jar" ascii wide
        $fw_next    = "kwlib.next" ascii wide
        $fw_magic   = "magic.o" ascii wide
        $fw_release = "mediaapp-release.apk" ascii wide

    condition:
        (
            // Unique C2 domains fire standalone
            any of ($c2_*)
            or
            // Two or more enabler packages together
            2 of ($pkg_*)
            or
            // Any enabler package + any campaign marker
            (any of ($pkg_*) and any of ($marker_*))
            or
            // Any enabler package + native loader
            (any of ($pkg_*) and any of ($native*))
            or
            // Any dropper package + any campaign marker or native loader
            (any of ($drp_*) and (any of ($marker_*) or any of ($native*)))
            or
            // Framework files co-occurring with native loader or enabler
            (any of ($fw_*) and (any of ($native*) or any of ($pkg_*)))
        )
        and filesize < 50MB
}

rule MidnightMimosa_Specimen : adfraud proxy specimen
{
    meta:
        description = "Midnight Mimosa specimen — Android DEX/ELF/APK with enabler package strings and native RC4 loader reference"
        author      = "synthetic-detections"
        date        = "2026-10-08"
        severity    = "critical"
        family      = "midnight-mimosa"
        reference   = "https://www.bitdefender.com/en-us/blog/labs/midnight-mimosa-malware"
    strings:
        // Android binary magic bytes
        $dex_magic = "dex\n03" ascii
        $elf_magic = { 7F 45 4C 46 }
        $apk_magic = { 50 4B 03 04 }

        // Enabler package names
        $pkg_lite    = "com.android.system.lite" ascii wide
        $pkg_prot    = "com.android.sys.prot" ascii wide
        $pkg_gmsprot = "com.android.sys.gmsprot" ascii wide
        $pkg_bcprot  = "com.android.sys.bcprot" ascii wide
        $pkg_dts     = "com.android.sys.dts" ascii wide
        $pkg_weiapps = "com.android.weiapps" ascii wide
        $pkg_weapps  = "com.android.weapps" ascii wide
        $pkg_szcz    = "com.android.non.szcz" ascii wide

        // Native loader reference
        $native1 = "libeasy.so" ascii wide
        $native2 = "libunionprt.so" ascii wide

        // Campaign-unique operational strings
        $marker_enloader = "EnLoaderLib" ascii wide
        $marker_rc4key   = "rc4@sec.com" ascii wide
        $marker_intent   = "com.media.am.intent.action.BIND_SERVICE" ascii wide

    condition:
        // Must be a recognized Android binary format
        (
            $dex_magic at 0
            or $elf_magic at 0
            or $apk_magic at 0
        )
        // Enabler package + native loader
        and any of ($pkg_*)
        and any of ($native*)
        // At least one campaign marker for structural uniqueness
        and any of ($marker_*)
        and filesize < 15MB
}
