/*
 * Mimbrob — espionage campaign targeting Russian defence/aerospace and IT
 *
 * Source: F6, "Baba-Yaga on the hook: new Mimbrob activity targets Russian
 *         defence industry and IT companies", 2026-09-29
 *         https://habr.com/ru/companies/F6/articles/1087974/
 *
 * Malware families:
 *   FBULoader  — DLL sideloading via legitimate Yandex Browser; browser.dll
 *                loads next-stage from checker[.]yandex-update[.]ru
 *   RAT-Go     — Go-based RAT with cmd.exe exec, file transfer, AES-GCM C2
 *                comms; sideloaded via MSASN1.dll; drops diskmanager.exe
 *   Dronner    — fake drone-tracker app ("Baba Yaga"); browser_elf.dll with
 *                language/region checks; RC4-variant encryption; C2 at
 *                browser[.]ydx-stat[.]ru
 *
 * Active since April 22, 2026. Phishing domains: klirnov[.]ru, npkarns[.]ru,
 * vniirn[.]ru. Distribution site: dronner[.]ru.
 *
 * [[sibling]] — none yet
 */
/* -----------------------------------------------------------------------
 * Rule 1: Behavioural — detect FBULoader, RAT-Go, and Dronner tradecraft
 * ----------------------------------------------------------------------- */

import "hash"

rule Mimbrob_Behavioural
{
    meta:
        description = "Mimbrob espionage campaign — FBULoader DLL sideloading, RAT-Go cmd.exe patterns, Dronner language checks and C2 domain patterns"
        author      = "synthetic-detections"
        date        = "2026-10-01"
        severity    = "critical"
        family      = "mimbrob"
        reference   = "https://habr.com/ru/companies/F6/articles/1087974/"
    strings:
        /* --- FBULoader indicators --- */
        $fbu_task      = "Browser Update Checker" ascii wide
        $fbu_path      = "Yandex\\YaBrowser\\browser.exe" ascii wide nocase
        $fbu_dir       = "25.0.1364.13754" ascii wide
        $fbu_c2_path   = "/api/verify/" ascii wide
        /* --- RAT-Go indicators --- */
        $ratgo_id      = "rat_go_common" ascii wide
        $ratgo_drop    = "diskmanager.exe" ascii wide nocase
        $ratgo_task    = "DiskManager" ascii wide
        $ratgo_svc     = "yandex_service.exe" ascii wide nocase
        $ratgo_task2   = "YandexUpdate" ascii wide
        $ratgo_debug   = "rat-go/" ascii wide
        // UTF-8 bytes for Russian placeholder string found in MSASN1.dll
        $ratgo_stub    = { D0 A2 D0 A3 D0 A2 5F D0 92 D0 A1 D0 A2 D0 90 D0 92 D0 AC 5F D0 A1 D0 92 D0 9E D0 99 5F 42 41 53 45 36 34 }
        /* --- Dronner indicators --- */
        $drn_task      = "CocCoc Browser Update" ascii wide
        $drn_edge      = "Edge Browser Dev" ascii wide nocase
        $drn_signal    = "SignalChromeElf" ascii wide
        $drn_installer = "DronnerInstaller" ascii wide nocase
        $drn_msi       = "dronner.msi" ascii wide nocase
        $drn_c2_path   = "/api/r/" ascii wide
        /* --- C2 domain substrings (campaign-specific impersonation) --- */
        $c2_yandex_upd = "yandex-update" ascii wide nocase
        $c2_ydx_stat   = "ydx-stat" ascii wide nocase
        /* --- DLL sideloading filenames --- */
        $dll_browser   = "browser.dll" ascii wide nocase
        $dll_msasn1    = "MSASN1.dll" ascii wide nocase
        $dll_belf      = "browser_elf.dll" ascii wide nocase
    condition:
        /* FBULoader: Yandex Browser sideloading path + C2 domain impersonation */
        /* RAT-Go: any two RAT-Go indicators together */
        /* Dronner: any two Dronner indicators, or the ydx-stat C2 with a sideloading DLL */
        /* Cross-family: campaign C2 domain pattern + DLL sideloading filename */
        /* Strong standalone: the RAT-Go placeholder string is highly specific */
        any of ($fbu_*) and $c2_yandex_upd or 2 of ($ratgo_*) or 2 of ($drn_*) or $c2_ydx_stat and any of ($dll_*) or $c2_yandex_upd and any of ($dll_*) or $ratgo_stub
}

rule Mimbrob_IOC
{
    meta:
        description = "Mimbrob C2 and phishing infrastructure IOCs (domains + IPs, >=2 co-occurrence)"
        author      = "synthetic-detections"
        date        = "2026-10-01"
        severity    = "high"
        family      = "mimbrob"
        reference   = "https://habr.com/ru/companies/F6/articles/1087974/"
    strings:
        /* C2 domains */
        $c2_d1 = "checker.yandex-update.ru" ascii wide nocase
        $c2_d2 = "browser.ydx-stat.ru" ascii wide nocase
        /* C2 IPs */
        $c2_i1 = "82.38.63.88" ascii wide fullword
        $c2_i2 = "194.87.37.14" ascii wide fullword
        /* Phishing / distribution domains */
        $ph_d1 = "klirnov.ru" ascii wide nocase
        $ph_d2 = "npkarns.ru" ascii wide nocase
        $ph_d3 = "vniirn.ru" ascii wide nocase
        $ph_d4 = "dronner.ru" ascii wide nocase
        /* Phishing sender addresses */
        $ph_e1 = "v.kichenko@klirnov.ru" ascii wide nocase
        $ph_e2 = "admin@npkarns.ru" ascii wide nocase
    condition:
        2 of them
}

rule Mimbrob_Specimen
{
    meta:
        description = "Pins known Mimbrob campaign samples by MD5"
        author      = "synthetic-detections"
        date        = "2026-10-01"
        severity    = "critical"
        family      = "mimbrob"
        reference   = "https://habr.com/ru/companies/F6/articles/1087974/"
    condition:
        // Dogovor_01.04.rar
        // Yandex Browser legitimate exe
        // browser.dll (FBULoader)
        // browser.dll payload
        // Novye.rar
        // Zarplaty.rar
        // Notepad++ legitimate
        // MSASN1.dll (RAT-Go loader)
        hash.md5(0, filesize) == "4a1c0fe99341908b2930de2ad2ec2522" or hash.md5(0, filesize) == "900ce1d4bcd1510276c4263d4aa3d78d" or hash.md5(0, filesize) == "4ca176d7f26664fc0f03c8289762f1c4" or hash.md5(0, filesize) == "0426d58893826924324fd95ad76f4c97" or hash.md5(0, filesize) == "25334e01a65c5bb07048ad6d74592d8a" or hash.md5(0, filesize) == "9282c4a105f1b6d32212f836debf21b2" or hash.md5(0, filesize) == "512f4350aee7eb50adf509008a3ad3ce" or hash.md5(0, filesize) == "9a0901dc40fb4695672cb21681c94bf6"
}
