/*
   Steam forum ClickFix -> XMRig cryptominer
   (first reported 2026-07-25; BleepingComputer — unattributed, financially
   motivated cryptojacking)
   -----------------------------------------------------------------------
   Attackers create throwaway Steam accounts and reply to discussion-forum
   threads about game crashes / lost inventory, offering a fake "fix." The
   victim is told to open PowerShell as Administrator and paste a supplied
   command. The delivered script masquerades as an "msf utility \ PC Opt"
   optimisation tool, printing fake maintenance steps with random 1.5-8s
   delays, while it:
     - adds a Microsoft Defender exclusion for C:\Windows\Background
     - creates a temporary outbound Windows Firewall rule on TCP/443
     - downloads the miner from hxxps://msfconfig[.]icu:443/tmp/system.txt
       to C:\Windows\Background\system.exe (config C:\Windows\Background\config.json)
     - registers a scheduled task "XMRig-<computer name>" to run system.exe
       as SYSTEM at every startup
     - launches XMRig (legitimate miner, abused)

   NOTE: XMRig, PowerShell, Add-MpPreference and schtasks are all legitimate.
   These rules anchor on campaign-specific artefacts (the C:\Windows\Background
   install path, the msfconfig[.]icu C2, the system.txt payload path, the
   "msf utility" / "PC Opt" lure label, and the XMRig-<host> task name) and
   require co-occurrence, so a normal XMRig deployment or a legitimate debloat
   script does not match.

   Rule 1 — Behavioral: the ClickFix PowerShell dropper (lure label + Defender
            exclusion on Background + payload fetch/persistence).
   Rule 2 — Structural: XMRig config.json pinned to the Background install dir.
   Rule 3 — IOC: C2 domain, payload URL, install path, task-name pattern.

   Related ClickFix families in this repo:
     [[golden-chickens-maas]] [[uac0145-sandworm-clickfix]]

   Sources:
     https://www.bleepingcomputer.com/news/security/steam-forum-clickfix-attacks-infect-gamers-with-xmrig-cryptominers/
     https://www.techechelon.com/post/steam-forums-weaponized-in-clickfix-campaign-distributing-xmrig-cryptominers
*/

rule Steam_ClickFix_XMRig_Dropper
{
    meta:
        description = "Steam-forum ClickFix PowerShell dropper for XMRig — 'msf utility/PC Opt' lure that adds a Defender exclusion for C:\\Windows\\Background, fetches system.exe from msfconfig[.]icu, and installs an XMRig-<host> scheduled task as SYSTEM"
        author      = "synthetic-detections"
        date        = "2026-07-27"
        severity    = "critical"
        family      = "steam-clickfix-xmrig"
        reference   = "https://www.bleepingcomputer.com/news/security/steam-forum-clickfix-attacks-infect-gamers-with-xmrig-cryptominers/"

    strings:
        // Lure / masquerade labels printed by the fake optimizer
        $lure1 = "msf utility" ascii wide nocase
        $lure2 = "PC Opt" ascii wide nocase

        // Campaign-unique install directory
        $dir = "C:\\Windows\\Background" ascii wide nocase

        // C2 / payload
        $c2   = "msfconfig.icu" ascii wide nocase
        $url  = "/tmp/system.txt" ascii wide nocase

        // Defense evasion (Defender exclusion)
        $mp1  = "Add-MpPreference" ascii wide nocase
        $mp2  = "-ExclusionPath" ascii wide nocase

        // Persistence (scheduled task naming pattern)
        $task = "XMRig-" ascii wide nocase
        $sch  = "schtasks" ascii wide nocase

    condition:
        filesize < 2MB
        and (
            // Path 1: the lure label plus the campaign install dir or C2
            (all of ($lure*) and ($dir or $c2))
            or
            // Path 2: Defender exclusion aimed specifically at the Background dir
            ($mp1 and $mp2 and $dir)
            or
            // Path 3: payload fetch from the tracked C2 to the install dir
            ($c2 and $url)
            or
            // Path 4: XMRig-named scheduled task installed into Background
            ($task and $sch and $dir)
        )
}

rule Steam_ClickFix_XMRig_Config
{
    meta:
        description = "XMRig config.json pinned to the Steam-ClickFix install dir — miner config referencing C:\\Windows\\Background\\system.exe / the msfconfig[.]icu pool"
        author      = "synthetic-detections"
        date        = "2026-07-27"
        severity    = "high"
        family      = "steam-clickfix-xmrig"
        reference   = "https://www.bleepingcomputer.com/news/security/steam-forum-clickfix-attacks-infect-gamers-with-xmrig-cryptominers/"

    strings:
        // XMRig config markers (generic to the miner)
        $x1 = "\"cpu\"" ascii
        $x2 = "\"randomx\"" ascii nocase
        $x3 = "\"pools\"" ascii
        $x4 = "\"rig-id\"" ascii nocase

        // Campaign-specific anchors
        $dir  = "C:\\\\Windows\\\\Background" ascii nocase
        $exe  = "system.exe" ascii wide nocase
        $c2   = "msfconfig.icu" ascii wide nocase

    condition:
        filesize < 256KB
        and 2 of ($x*)
        // config must reference a campaign anchor, not just be any XMRig config
        and any of ($dir, $exe, $c2)
}

rule Steam_ClickFix_XMRig_IOC
{
    meta:
        description = "Steam-ClickFix XMRig hard IOCs — C2 domain msfconfig[.]icu, payload URL, install path, and XMRig-<host> task name"
        author      = "synthetic-detections"
        date        = "2026-07-27"
        severity    = "critical"
        family      = "steam-clickfix-xmrig"
        reference   = "https://www.techechelon.com/post/steam-forums-weaponized-in-clickfix-campaign-distributing-xmrig-cryptominers"

    strings:
        $c2      = "msfconfig.icu" ascii wide nocase
        $payload = "msfconfig.icu:443/tmp/system.txt" ascii wide nocase
        $dir_exe = "C:\\Windows\\Background\\system.exe" ascii wide nocase
        $dir_cfg = "C:\\Windows\\Background\\config.json" ascii wide nocase

    condition:
        filesize < 5MB and any of them
}
