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

rule ENDLESSDOORS_Implant_Behavior {
  meta:
    description = "ENDLESSDOORS Zbtlink router backdoor -- rctl-derived implant: rctlbash reverse-root-shell protocol, kworker masquerade (skworker/librctl.so/kworker.cfg), popen root command exec on ports 7000/7001"
    author = "synthetic-detections"
    date = "2026-08-07"
    severity = "critical"
    family = "endlessdoors-zbtlink-backdoor"
    reference = "https://thehackernews.com/2026/08/chinese-made-zbtlink-routers-ship-with.html"
  strings:
    $p1 = "rctlbash"
    $p2 = "run this as root"
    $lib = "librctl.so"
    $a1 = "/etc/init.d/skworker"
    $a2 = "/etc/kworker.cfg"
    $a3 = "/usr/sbin/kworker"
    $a4 = "/usr/lib/librctl.so"
    $exec = "popen"
  condition:
    uint32(0) == 1179403647 and (any of ($p1, $p2) or $lib and any of ($a*) or 2 of ($a*) and $exec)
}

rule ENDLESSDOORS_IOC {
  meta:
    description = "ENDLESSDOORS Zbtlink backdoor C2 -- domains and IPs (VulnCheck, 2026-08-06)"
    author = "synthetic-detections"
    date = "2026-08-07"
    severity = "high"
    family = "endlessdoors-zbtlink-backdoor"
    reference = "https://thehackernews.com/2026/08/chinese-made-zbtlink-routers-ship-with.html"
  strings:
    $d1 = "zbtctl.epplink.net" nocase
    $d2 = "online-string.com" nocase
    $d3 = "rbdg4nzqadui.wikaba.com" nocase
    $ip1 = "47.100.190.96"
    $ip2 = "47.107.224.89"
    $ip3 = "45.32.81.152"
    $ip4 = "43.248.136.125"
  condition:
    any of ($d*) or 2 of ($ip*)
}

rule ENDLESSDOORS_Artifacts {
  meta:
    description = "ENDLESSDOORS Zbtlink backdoor -- implant filesystem-path constellation (skworker init + librctl.so + kworker.cfg); pins a firmware image or unpacked rootfs containing the implant"
    author = "synthetic-detections"
    date = "2026-08-07"
    severity = "critical"
    family = "endlessdoors-zbtlink-backdoor"
    reference = "https://blog.gridinsoft.com/endlessdoors-zbtlink-router-backdoor/"
  strings:
    $init = "/etc/init.d/skworker"
    $lib = "/usr/lib/librctl.so"
    $cfg = "/etc/kworker.cfg"
    $sbin = "/usr/sbin/kworker"
  condition:
    3 of them
}
