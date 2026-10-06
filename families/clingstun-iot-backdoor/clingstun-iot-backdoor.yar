/*
 * ClingSTUN IoT Backdoor
 *
 * Linux back-connect proxy backdoor targeting IoT devices. Abuses public STUN
 * servers for C2 channel, embeds commands in STUN transaction IDs. Contains
 * self-propagation exploits for Realtek, KGUARD, MVPower, and others.
 *
 * Sources:
 *   - https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure
 *   - https://www.securityweek.com/linux-backdoor-abuses-stun-protocol-exploits-dozens-of-flaws/
 *   - https://cybersecuritynews.com/cling-malware/
 *
 * [[clingstun-iot-backdoor-suricata]]
 */

import "hash"

rule ClingSTUN_Backdoor_Behavior
{
    meta:
        description = "ClingSTUN IoT backdoor — behavioural strings and persistence indicators"
        author      = "synthetic-detections"
        date        = "2026-10-06"
        severity    = "critical"
        family      = "ClingSTUN"
        reference   = "https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure"
    strings:
        // persistence paths
        $path_cling1  = "/root/.cling"
        $path_cling2  = "/usr/local/bin/.cling"
        // init script targets for persistence
        $init_inittab = "/etc/inittab"
        $init_rcs     = "/etc/init.d/rcS"
        $init_rcboot  = "/etc/rc.d/rc.boot"
        // wget replacement (backs up original, replaces with self)
        $wget_backup  = "wget.r"
        $wget_track   = "wget.p"
        // self-rep infection tags
        $tag_realtek  = "realtek.selfrep"
        $tag_router   = "selfrep.router"
        // user-agent marker
        $ua_cling     = "clingwashere"
        // proc hiding
        $proc_mount   = "mount --bind /tmp /proc/"
        $proc_cmdline = "/proc/%d/cmdline"
        $proc_exe     = "/proc/%d/exe"
        // watchdog disarm
        $watchdog1    = "/dev/watchdog"
        $watchdog2    = "/dev/misc/watchdog"
        // single-instance mutex port
        // 33957 big-endian
        $mutex_port   = { 84 9D }
        // STUN binding request magic (0x0001) + zero-padded length
        $stun_magic   = { 00 01 00 00 }
    condition:
        uint32(0) == 0x464c457f
        and (
            (($path_cling1 or $path_cling2) and ($tag_realtek or $tag_router or $ua_cling)) or
            (($path_cling1 or $path_cling2) and ($init_inittab or $init_rcs or $init_rcboot) and ($proc_mount or $proc_cmdline)) or
            ($ua_cling and ($tag_realtek or $tag_router) and any of ($wget_*)) or
            (3 of ($path_cling*, $tag_*, $ua_cling) and 2 of ($init_*, $proc_*, $watchdog*, $mutex_port, $stun_magic))
        )
        and filesize < 5MB
}

rule ClingSTUN_IOC_Infrastructure
{
    meta:
        description = "ClingSTUN IoT backdoor — hardcoded STUN servers and C2 infrastructure"
        author      = "synthetic-detections"
        date        = "2026-10-06"
        severity    = "high"
        family      = "ClingSTUN"
        reference   = "https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure"
    strings:
        // operator-controlled STUN server
        $stun_op          = "145.249.115.184"
        // hardcoded STUN endpoints (distinctive subset — not Google/Cloudflare)
        $stun_1           = "5.39.72.109"
        $stun_2           = "81.187.30.115"
        $stun_3           = "207.38.82.134"
        $stun_4           = "83.211.9.232"
        $stun_5           = "212.53.40.43"
        $stun_6           = "85.17.88.164"
        $stun_7           = "216.93.246.18"
        $stun_8           = "77.72.169.213"
        $stun_9           = "77.72.169.211"
        $stun_10          = "212.227.67.34"
        $stun_11          = "212.227.67.33"
        $stun_12          = "154.73.34.8"
        $stun_13          = "64.131.63.217"
        $stun_14          = "82.113.193.63"
        $stun_15          = "185.125.180.70"
        $stun_16          = "66.51.128.1"
        $stun_17          = "139.162.62.29"
        $stun_18          = "85.93.219.114"
        $stun_19          = "77.72.169.210"
        $stun_20          = "77.72.169.212"
        $stun_21          = "217.0.0.249"
        // download servers
        $dl_1             = "124.163.212.119"
        $dl_2             = "222.223.152.97"
        $dl_3             = "118.45.196.225"
        $dl_4             = "120.193.219.210"
        $dl_5             = "58.211.144.243"
        $dl_6             = "121.32.243.81"
        // exploit target paths
        $exploit_picsdesc = "POST /picsdesc.xml"
        // self-propagation marker
        $selfrep          = ".selfrep"
    condition:
        uint32(0) == 0x464c457f
        and (
            ($stun_op and 2 of ($stun_*)) or
            4 of ($stun_*) or
            (2 of ($dl_*) and any of ($stun_*)) or
            ($selfrep and 2 of ($stun_*) and any of ($dl_*)) or
            ($exploit_picsdesc and any of ($dl_*))
        )
        and filesize < 5MB
}

rule ClingSTUN_Specimen_Pin
{
    meta:
        description = "ClingSTUN IoT backdoor — specimen hash pins from Fortinet report"
        author      = "synthetic-detections"
        date        = "2026-10-06"
        severity    = "critical"
        family      = "ClingSTUN"
        reference   = "https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure"
    condition:
        uint32(0) == 0x464c457f
        and filesize < 5MB
        and (
            hash.sha256(0, filesize) == "dc892f5013edb0aa1e61e808511387373d8d120348b5be0929621d21e6e9946a" or
            hash.sha256(0, filesize) == "a297eddfa7abea8d411afc0f150f8f6f30e470a77204de87e3b0815fa9bb8a84" or
            hash.sha256(0, filesize) == "4fbd61cb9181ebbc4fe9a6e59d3c346dc00001da48d66bd890556fc6fad22b07" or
            hash.sha256(0, filesize) == "121f2050e3c891b29565fd73451fff7ae60199c86eb8d79ec1eb1d9844578487" or
            hash.sha256(0, filesize) == "48f9b72ce72ab7087794650d6eef10135345088384fbde1482f1c74a02b80302" or
            hash.sha256(0, filesize) == "e6e113783356446aef66e5296db45b244f318292af7cebc2a9bd76f095a95c4c" or
            hash.sha256(0, filesize) == "c1d8e2829ea63b9dc1cf2c3421a5093406adad4d6622e238376e78e908e0e6e8" or
            hash.sha256(0, filesize) == "48962b3893f2c8261e32e6b95ea7d463d145a529a8b2a6c987dd979454405c73" or
            hash.sha256(0, filesize) == "76692a23abe718b93e63edefd743971ec627c0cdf3778f856bd5ec88003deaa2" or
            hash.sha256(0, filesize) == "ec199c78c11040fd3127887222fd75a85e5797bf96aa691a117fdd83dd663d81" or
            hash.sha256(0, filesize) == "c0d8ffebfba969b1c1ca76bd9623bb623e9f95155c8ceca77d8fcc521435a497" or
            hash.sha256(0, filesize) == "f49f45303cbfccee14ff193ac9608f860e6d616f08c0ecbef1ec44f7c863d7ec" or
            hash.sha256(0, filesize) == "9391c6ad17aced1142607c0c623b18d86a7697cc483d204ffac94093e26b8068" or
            hash.sha256(0, filesize) == "e4d12208789f36efc5a1ff765088fed95d6bb5972d1a804a4536fd42366797d4" or
            hash.sha256(0, filesize) == "284e5ec8748f99fd1b8c331b699a5fe5fd4448bbaae0347a940f427f931c4d14" or
            hash.sha256(0, filesize) == "6581bf37184bb2db899b9893064d39dd314ea691adf3281cc0aa7e0a31e5138a" or
            hash.sha256(0, filesize) == "10d83c1748895361e07320f68d44d427b43cadd2cbffe0ab5e607ab03aec83da" or
            hash.sha256(0, filesize) == "2ed54e0f988a62039abed88f6394eb1e3d5ed931f0183556055417fb08844ecf" or
            hash.sha256(0, filesize) == "b90640b392827b4f2d280f6cf67860862953331917d42df23e1653a92f2f98ad" or
            hash.sha256(0, filesize) == "dfba6008a2c828a9cb62342aec53006ae05a60cb8d4c41c3fa216fd727e8c6a3" or
            hash.sha256(0, filesize) == "5c4e263546fb21f8fe8732789a5b6583eaa8ae11ebeef099462a7c9bf50e022d"
        )
}
