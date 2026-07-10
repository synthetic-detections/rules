/*
   GigaWiper — destructive Windows backdoor assembled from multiple malware
   --------------------------------------------------------------------------
   Detailed 2026-07-09 (Microsoft Security; also The Hacker News, SC Media,
   hackread). A Go (Golang) Windows implant that fuses three roles behind
   numbered operator commands delivered over RabbitMQ:

     (1) a RAW DISK WIPER that overwrites the physical drive in 0xA00000-byte
         chunks and destroys the partition table (IOCTL_DISK_CREATE_DISK)
         before rebooting — no recoverable file-by-file deletion;
     (2) FAKE RANSOMWARE built on the older Crucio code — encrypts files with a
         ".candy" extension and sets an alarming wallpaper (image_danger.jpg),
         but drops NO ransom note and saves NO key, so it is pure destruction
         masquerading as extortion (nothing to pay, nothing to decrypt);
     (3) SPYWARE — multi-monitor screenshots, screen recording, hidden VNC.

   Persistence via a scheduled task "OneDrive Update" and an execution-tracking
   key HKCU\SOFTWARE\OneDrive\Environment. Binary Defense, citing Google's
   Threat Intelligence Group, ties GigaWiper to a likely IRAN-NEXUS actor
   targeting Israeli organizations; the Crucio component was listed as suspected
   ransomware in the December 2023 CISA advisory on CyberAv3ngers (IRGC-linked).
   The wiper lineage traces to FlockWiper/GRAT (CWipe/CWipeNew PDB paths).

   The three rules key on: (1) the distinctive assembled Go tool/package
   symbols (near-unique), (2) the wiper+fake-ransom artifact cluster gated on a
   PE, and (3) hard network/host IOCs. SHA256 of known samples are listed for
   reference; the string rules also catch unpacked memory images and reports.

   Siblings (destructive / BYOVD / ransomware):
     [[prinz-eugen-ransomware]], [[goddamn-poisonx-ransomware]],
     [[gentlekiller-edr-killer]]

   Sources:
     https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/
     https://thehackernews.com/2026/07/new-gigawiper-windows-backdoor-bundles.html

   Known samples (SHA256):
     633d4cbd496b1094495da89a64f5e6c31a0f6d4d1488411db5b0cba1cfe42001
     ce9ad5f6c12019f4aae5b189bd8ddf5bb09e75b06a0a587b25a855c65948c913
     f622ed85ef31ad4ab973f4e74524866fe1bb44f0965ad2b2ad796cd657a05bfd
     9706a192e2c1a1faaf0a521daf31c2af60ff4590e3f47bbb4abc227f42af0683
     3c30deb6556a94cfb84ae51798f4aecfae8c7358e55fdb321c5f2376579631cd  (standalone wiper)
*/

rule GigaWiper_Go_ToolSymbols
{
    meta:
        description = "GigaWiper assembled Go tool/package symbols (rabbit_tools wipe/wipec/ran/extort + RunOnce registry) — near-unique to the implant"
        author      = "synthetic-detections"
        date        = "2026-07-10"
        severity    = "critical"
        family      = "gigawiper-destructive-backdoor"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"

    strings:
        $g1 = "rabbit_tools_tool_wipe_main.WipeMain" ascii
        $g2 = "rabbit_tools_tool_wipec_main.WipeCMain" ascii
        $g3 = "rabbit_tools_tool_ran_main_cmd_extort.RanMain" ascii
        $g4 = "rabbit_tools_tool_ran_main_bin.BigBangExtortMain" ascii
        $g5 = "rabbit_bin.RunOnceRegistryMain" ascii
        // shorter supporting symbols — require a distinctive one alongside
        $s1 = "rabbit_tools_tool_" ascii
        $s2 = "BigBangExtort" ascii

    condition:
        filesize < 80MB and (
            any of ($g*)
            or ($s1 and $s2)
        )
}

rule GigaWiper_Wiper_FakeRansom_Artifacts
{
    meta:
        description = "GigaWiper wiper + fake-ransomware artifact cluster (.candy extension, image_danger.jpg wallpaper, OneDrive-masquerade persistence, GRAT/CWipe PDB) in a PE"
        author      = "synthetic-detections"
        date        = "2026-07-10"
        severity    = "critical"
        family      = "gigawiper-destructive-backdoor"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"

    strings:
        // fake-ransomware markers
        $candy   = ".candy" ascii wide
        $img     = "image_danger.jpg" ascii wide nocase

        // persistence masquerade
        $task    = "OneDrive Update" ascii wide
        $regkey  = "SOFTWARE\\OneDrive\\Environment" ascii wide nocase

        // FlockWiper / GRAT wiper lineage PDB paths (highly distinctive)
        $pdb1    = "GRAT\\CWipeNew\\Release\\CWipeNew.pdb" ascii nocase
        $pdb2    = "GRAT\\CWipe\\Release\\CWipe.pdb" ascii nocase

        // RabbitMQ command plumbing symbols
        $mq1     = "cmd.Task" ascii
        $mq2     = "cmd.Result" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 80MB and (
            any of ($pdb*)                       // PDB path alone is specific
            or ($candy and ($img or $task or $regkey or any of ($mq*)))
            or ($img and ($task or $regkey))
            or (any of ($mq*) and ($candy or $img or $task))
        )
}

rule GigaWiper_IOC
{
    meta:
        description = "GigaWiper hard network IOCs — RabbitMQ/Redis C2 and secondary C2 host"
        author      = "synthetic-detections"
        date        = "2026-07-10"
        severity    = "high"
        family      = "gigawiper-destructive-backdoor"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/"

    strings:
        $c2_rabbit = "185.182.193.21" ascii wide      // RabbitMQ :5544 / Redis :7542
        $c2_second = "212.8.248.104" ascii wide
        $port_rmq  = "185.182.193.21:5544" ascii wide
        $port_rds  = "185.182.193.21:7542" ascii wide

    condition:
        filesize < 80MB and any of them
}
