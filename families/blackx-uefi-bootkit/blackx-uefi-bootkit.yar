/*
   BlackX UEFI bootkit — APT41-attributed, 2026-10-24
   ---------------------------------------------------
   UEFI bootkit derived from BlackLotus, exploiting CVE-2022-21894
   (Baton Drop) to bypass Secure Boot. Deploys a kernel driver that
   disables security callbacks + ETW, a cloud-C2 RAT (Google Drive /
   OneDrive / Yandex.Disk), and OxiDLLRunner — an OLLVM-obfuscated
   DLL sideloaded via googleupdate.exe that decrypts v8_context_snapshot.bin
   into a Rust payload fetching plugin DLLs from archivetj[.]com.

   Targets: diplomatic agencies in Tajikistan, Uzbekistan, Turkmenistan.

   Rule 1 — Behavioural: OxiDLLRunner sideloading + Rust plugin loader.
   Rule 2 — IOC: campaign-specific strings, paths, and C2 domain.
   Rule 3 — Specimen pin: MD5 hash of the sideloading host binary.

   Sources:
     https://securelist.com/uefi-bootkit-blackx/121539/
     https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/
*/

import "hash"
import "pe"

rule BlackX_OxiDLLRunner_Behavioural : apt41 bootkit sideloading
{
    meta:
        description = "BlackX UEFI bootkit — behavioural detection of the OxiDLLRunner sideloading and plugin loader pattern"
        author      = "synthetic-detections"
        date        = "2026-10-25"
        severity    = "critical"
        family      = "blackx-uefi-bootkit"
        reference   = "https://securelist.com/uefi-bootkit-blackx/121539/"
    strings:
        $payload_file  = "v8_context_snapshot.bin" ascii wide
        $export_plugin = "create_plugin"
        $marker_sssr   = "SSSR"
        $task_01       = "0X01"
        $task_02       = "0X02"
        $task_03       = "0X03"
        $task_04       = "0X04"
        $task_05       = "0X05"
        $task_06       = "0X06"
        $dotnet_method = "TEST.Class1.RunCMD" ascii wide
    condition:
        (uint16(0) == 23117 or uint32(0) == 9460301)
        and $payload_file
        and (
            ($export_plugin and 2 of ($task_*)) or
            ($marker_sssr and $dotnet_method) or
            ($export_plugin and $marker_sssr)
        )
        and filesize < 10MB
}

rule BlackX_IOC : apt41 bootkit sideloading
{
    meta:
        description = "BlackX UEFI bootkit — campaign IOCs: C2 domain, certificate serial, RC4 key, installer path, and tool strings"
        author      = "synthetic-detections"
        date        = "2026-10-25"
        severity    = "high"
        family      = "blackx-uefi-bootkit"
        reference   = "https://securelist.com/uefi-bootkit-blackx/121539/"
    strings:
        $c2_domain    = "archivetj.com" ascii wide nocase
        $cert_serial  = { 0B CD F5 E0 DA 32 D6 89 00 B8 B7 63 84 59 D0 72 }
        $rc4_key      = "Q46F6MDLI3RX2KV1" ascii wide
        $inst_path    = "\\ProgramData\\Intel\\inst.exe" ascii wide nocase
        $pdb_fragment = "\\Users\\xdd\\Desktop" ascii wide
        $sched_task   = "Secure-Boot-Update" ascii wide
        $orig_name    = "jcef_helper.exe" ascii wide nocase
        $dotnet_run   = "TEST.Class1.RunCMD" ascii wide
    condition:
        2 of them and filesize < 10MB
}

rule BlackX_Specimen : apt41 bootkit sideloading
{
    meta:
        description = "BlackX UEFI bootkit — specimen pin on the known OxiDLLRunner sideloading host (googleupdate.exe / jcef_helper.exe)"
        author      = "synthetic-detections"
        date        = "2026-10-25"
        severity    = "critical"
        family      = "blackx-uefi-bootkit"
        reference   = "https://securelist.com/uefi-bootkit-blackx/121539/"
    condition:
        filesize < 5MB and hash.md5(0, filesize) == "af8a983b9ada07eae1259bf2953abd40"
}
