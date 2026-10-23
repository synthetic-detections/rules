/*
   Stadia RAT — StealC developer's new remote access trojan
   =========================================================
   Disclosed 2026-10-22 by Varonis. The developer behind StealC
   (infrastructure seized by Europol in Operation EndStealer, June 2026)
   has returned with Stadia, a full-featured RAT marketed on Russian
   cybercrime forums.

   Native MSVC PE32 (no .NET, no packer), 560 KB. Imports only
   KERNEL32.dll; all other APIs resolved at runtime. Embeds a 26 KB
   App-Bound Encryption helper blob shared with StealC v3.5. Uses RC4
   over JSON over HTTP for C2 communication. Checks five CIS locale IDs
   and exits on match. Installs to C:\ProgramData\<12-char>\<legit-name>.exe
   with a COM-registered hidden scheduled task (PT15M interval, P3650D
   duration). Modules: Remote CMD, File Explorer, Process Manager,
   Hidden VNC (HVNC), Loader, Grabber/Stealer.

   Three rules:
     1. StealC_Stadia_RAT_Strings
        Behavioural — build marker, VNC object name, RC4 key, locale
        check constants, and protocol vocabulary.

     2. StealC_Stadia_RAT_IOCs
        IOC-based — C2 addresses, operator panel domain, sample hashes,
        imphash, App-Bound helper blob hash.

     3. StealC_Stadia_RAT_Structural
        Structural — PE32 with single KERNEL32 import, specific filesize
        band, and characteristic string/constant combination.

   Author: synthetic-detections, 2026-10-23
   Sources:
     Varonis: https://www.varonis.com/blog/stealc-returns
   Sample hashes:
     ea928494fd30d88b98141d39a502a4324889fb732e74b44bfee12c72137dd73e (stadia_x32.exe)
     0e5337a4cc8ebc772bc50f6e79befd1e8efad3410022e050d08d5269733c4ea4 (App-Bound helper blob)
*/

import "pe"

rule StealC_Stadia_RAT_Strings : malware rat
{
    meta:
        description = "Stadia RAT — build marker, HVNC object, RC4 key, locale checks, and protocol strings"
        author      = "synthetic-detections"
        date        = "2026-10-23"
        severity    = "critical"
        family      = "Stadia"
        reference   = "https://www.varonis.com/blog/stealc-returns"
        hash        = "ea928494fd30d88b98141d39a502a4324889fb732e74b44bfee12c72137dd73e"
    strings:
        // Build marker (decrypted form)
        $build_marker = "STADIA_BETA" ascii wide
        // HVNC desktop object name pattern
        $hvnc_obj     = "StadiaVnc%d" ascii wide
        // RC4 string key (build-specific but high-signal)
        $rc4_key      = "eepkTOgSwdNCgrhITR"
        // C2 protocol vocabulary
        $proto_online = "set_online"
        $proto_token  = "host_token"
        // CIS locale check constants (little-endian DWORDs)
        // 0x0419=Russian, 0x0422=Ukrainian, 0x0423=Belarusian,
        // 0x043F=Kazakh, 0x0443=Uzbek
        $locale_ru    = { 19 04 00 00 }
        $locale_ua    = { 22 04 00 00 }
        $locale_by    = { 23 04 00 00 }
        $locale_kz    = { 3F 04 00 00 }
        $locale_uz    = { 43 04 00 00 }
        // Module capability strings
        $mod_hvnc     = "Remote Desktop" ascii wide
        $mod_cmd      = "Remote CMD" ascii wide
        $mod_fexp     = "File Explorer" ascii wide
        $mod_procmgr  = "Process Manager" ascii wide
    condition:
        // Build marker + any capability
        // HVNC object + protocol (no build marker needed)
        // RC4 key + protocol + locale checks
        // Build marker + 3+ locale constants
        (
            ($build_marker and ($hvnc_obj or $rc4_key or $proto_online)) or
            ($hvnc_obj and ($proto_online or $proto_token)) or
            ($rc4_key and ($proto_online or $proto_token) and 3 of ($locale_*)) or
            ($build_marker and 3 of ($locale_*)) or
            (2 of ($mod_*) and ($build_marker or $hvnc_obj))
        )
        and filesize < 10MB
}

rule StealC_Stadia_RAT_IOCs : c2 ioc
{
    meta:
        description = "Stadia RAT IOCs — C2 infrastructure, operator panel, sample and helper blob hashes"
        author      = "synthetic-detections"
        date        = "2026-10-23"
        severity    = "high"
        family      = "Stadia"
        reference   = "https://www.varonis.com/blog/stealc-returns"
        hash        = "ea928494fd30d88b98141d39a502a4324889fb732e74b44bfee12c72137dd73e"
    strings:
        // C2 IP addresses
        $c2_ip1      = "93.152.213.215"
        $c2_ip2      = "91.92.43.45"
        $c2_ip3      = "193.148.56.97"
        // Operator panel domain
        $panel       = "stadiadev.cc"
        // Sample SHA-256
        $hash_main   = "ea928494fd30d88b98141d39a502a4324889fb732e74b44bfee12c72137dd73e"
        $hash_helper = "0e5337a4cc8ebc772bc50f6e79befd1e8efad3410022e050d08d5269733c4ea4"
        // Seller handle
        $seller      = "plymouth"
        // Defender exclusion command pattern
        $excl_cmd    = "Add-MpPreference -ExclusionPath"
    condition:
        any of them and filesize < 50MB
}

rule StealC_Stadia_RAT_Structural : malware rat
{
    meta:
        description = "Stadia RAT — PE32 with single KERNEL32 import, HVNC strings, and runtime API resolution"
        author      = "synthetic-detections"
        date        = "2026-10-23"
        severity    = "critical"
        family      = "Stadia"
        reference   = "https://www.varonis.com/blog/stealc-returns"
        hash        = "ea928494fd30d88b98141d39a502a4324889fb732e74b44bfee12c72137dd73e"
    strings:
        // Build marker or HVNC object (at least one)
        $stadia        = "STADIA_BETA" ascii wide
        $hvnc          = "StadiaVnc%d" ascii wide
        $rc4_key       = "eepkTOgSwdNCgrhITR"
        // Scheduled task XML fragments (COM-registered hidden task)
        $task_interval = "<Interval>PT15M</Interval>" ascii wide nocase
        $task_duration = "<Duration>P3650D</Duration>" ascii wide nocase
        $task_hidden   = "<Hidden>true</Hidden>" ascii wide nocase
    condition:
        // PE32 file
        // Single import: KERNEL32 only (pe.number_of_imports == 1)
        // Stadia-specific string + task persistence
        uint16(0) == 0x5a4d
        and uint32(uint32(60)) == 0x4550
        and pe.number_of_imports == 1
        and any of ($stadia, $hvnc, $rc4_key)
        and any of ($task_interval, $task_duration, $task_hidden)
        and filesize > 100KB
        and filesize < 2MB
}
