/*
   ENDLESSDOORS -- root backdoor in Zbtlink / Wiflyer router firmware
   (disclosed 2026-08-06; VulnCheck; CVE-2026-66747)
   -----------------------------------------------------------------------
   A firmware-resident Linux implant found across ~20 Zbtlink router models
   (also sold as Wiflyer and white-label), est. 100,000+ devices. It is a
   modified build of "rctl" (Remote Control Linux, an abandoned 2015 GitHub
   tool). It starts at boot, disguises itself as a kworker kernel thread, and
   runs as a userland root process.

   Behaviour (VulnCheck):
     - Beacons out from inside the network to an external C2 about every 35s.
     - Listens on port 7000 (C2) and 7001 (interactive shell).
     - No authentication / encryption / server verification: any command the
       server returns is executed as root via popen. The "run this as root" /
       rctlbash sequence spawns a reverse root shell.

   Static artifacts (filesystem):
     /etc/init.d/skworker   (boot persistence, masquerades as kworker)
     /usr/lib/librctl.so    (the rctl-derived implant library)
     /etc/kworker.cfg       (config)
     /usr/sbin/kworker      (userland process posing as the kernel thread)

   NOTE: "kworker" alone is a legitimate Linux kernel thread name; these rules
   require the implant-specific PATHS and rctl protocol strings to co-occur so a
   normal system referencing kworker in ps/logs does not match.

   Rule 1 -- Behavior: rctl protocol + kworker-masquerade paths + popen shell.
   Rule 2 -- IOC: C2 domains and IPs (VulnCheck).
   Rule 3 -- Artifacts: the implant filesystem-path constellation (specimen pin).

   Sources:
     https://thehackernews.com/2026/08/chinese-made-zbtlink-routers-ship-with.html
     https://blog.gridinsoft.com/endlessdoors-zbtlink-router-backdoor/
*/

rule ENDLESSDOORS_Implant_Behavior
{
    meta:
        description = "ENDLESSDOORS Zbtlink router backdoor -- rctl-derived implant: rctlbash reverse-root-shell protocol, kworker masquerade (skworker/librctl.so/kworker.cfg), popen root command exec on ports 7000/7001"
        author      = "synthetic-detections"
        date        = "2026-08-07"
        severity    = "critical"
        family      = "endlessdoors-zbtlink-backdoor"
        reference   = "https://thehackernews.com/2026/08/chinese-made-zbtlink-routers-ship-with.html"

    strings:
        // rctl-derived protocol vocabulary (implant-specific)
        $p1 = "rctlbash" ascii
        $p2 = "run this as root" ascii
        $lib = "librctl.so" ascii

        // kworker-masquerade filesystem artifacts
        $a1 = "/etc/init.d/skworker" ascii
        $a2 = "/etc/kworker.cfg" ascii
        $a3 = "/usr/sbin/kworker" ascii
        $a4 = "/usr/lib/librctl.so" ascii

        // command execution
        $exec = "popen" ascii

    condition:
        // ELF, with the rctl protocol OR two masquerade paths, plus a corroborator
        uint32(0) == 0x464c457f
        and (
            1 of ($p1, $p2)
            or ( $lib and 1 of ($a*) )
            or ( 2 of ($a*) and $exec )
        )
}

rule ENDLESSDOORS_IOC
{
    meta:
        description = "ENDLESSDOORS Zbtlink backdoor C2 -- domains and IPs (VulnCheck, 2026-08-06)"
        author      = "synthetic-detections"
        date        = "2026-08-07"
        severity    = "high"
        family      = "endlessdoors-zbtlink-backdoor"
        reference   = "https://thehackernews.com/2026/08/chinese-made-zbtlink-routers-ship-with.html"

    strings:
        // C2 domains
        $d1 = "zbtctl.epplink.net" ascii nocase
        $d2 = "online-string.com" ascii nocase
        $d3 = "rbdg4nzqadui.wikaba.com" ascii nocase

        // C2 IPs
        $ip1 = "47.100.190.96" ascii
        $ip2 = "47.107.224.89" ascii
        $ip3 = "45.32.81.152" ascii
        $ip4 = "43.248.136.125" ascii

    condition:
        any of ($d*) or 2 of ($ip*)
}

rule ENDLESSDOORS_Artifacts
{
    meta:
        description = "ENDLESSDOORS Zbtlink backdoor -- implant filesystem-path constellation (skworker init + librctl.so + kworker.cfg); pins a firmware image or unpacked rootfs containing the implant"
        author      = "synthetic-detections"
        date        = "2026-08-07"
        severity    = "critical"
        family      = "endlessdoors-zbtlink-backdoor"
        reference   = "https://blog.gridinsoft.com/endlessdoors-zbtlink-router-backdoor/"

    strings:
        $init = "/etc/init.d/skworker" ascii
        $lib  = "/usr/lib/librctl.so" ascii
        $cfg  = "/etc/kworker.cfg" ascii
        $sbin = "/usr/sbin/kworker" ascii

    condition:
        3 of them
}
