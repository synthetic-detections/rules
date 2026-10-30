/*
   KEYDRIFT -- UAT-11473 SD-WAN encryption key theft framework
   (disclosed 2026-10-28; Cisco Talos "Inside KeyDrift")
   -----------------------------------------------------------------------
   Multi-component Linux framework targeting Cisco Catalyst SD-WAN
   controllers (via CVE-2026-20127). Goal is persistent access and
   exfiltration of IPsec keying material from the SD-WAN control plane.

   Components:
     conf_sshd    -- shell launcher; enumerates vdaemon PIDs
     rsshd        -- ptrace-based injector; injects libdssl.so into vdaemon
     libdssl.so   -- PolyFlame backdoor; hooks recvfrom/sendto in vdaemon;
                     acts as TinyShell-style shell and intermediate C2
     libcommon.so -- LittleFilch key harvester; hooks SSL_read in vdaemon,
                     extracts AES-256 IPsec key material, RSA-encrypts it
                     to /var/tmp/vdaemon.bin
     aaamgrd      -- packed PolyFlame variant; ELF64, RC4-encrypted payload,
                     anti-debug via TracerPid, masquerades as aaamgr service

   Persistence: modified runit service scripts under /etc/sv/sshd/ and
   /etc/sv/aaamgr/.

   Rule 1 -- Behaviour: ELF + KeyDrift-specific path/string constellation.
   Rule 2 -- IOC: protocol markers, staging paths, component file names.
   Rule 3 -- Structural pin: packed ELF64 with no section headers (aaamgrd).

   Sources:
     https://blog.talosintelligence.com/uat-11473-keydrift/
     https://www.bleepingcomputer.com/news/security/hackers-exploit-cisco-sd-wan-flaw-to-deploy-custom-keydrift-malware/
   Related families in this repo:
     (none yet)
*/

rule KeyDrift_SDWan_Behaviour : backdoor behavioral
{
    meta:
        description = "KeyDrift SD-WAN implant -- ELF with vdaemon injection paths, key-harvesting staging files, or runit service hijack indicators"
        author      = "synthetic-detections"
        date        = "2026-10-30"
        severity    = "critical"
        family      = "keydrift-sdwan"
        reference   = "https://blog.talosintelligence.com/uat-11473-keydrift/"
    strings:
        // staging and config paths
        $path1   = "/tmp/system-vdaemon"
        $path2   = "/var/tmp/vdaemon.bin"
        $path3   = "/var/tmp/vdaemon.conf"
        // component names as loaded/referenced
        $comp1   = "libdssl.so"
        $comp2   = "libcommon.so"
        $comp3   = "conf_sshd"
        // injection target process
        $proc1   = "vdaemon"
        // runit service hijack paths
        $runit1  = "/etc/sv/sshd/"
        $runit2  = "/etc/sv/aaamgr/"
        // rootfs remount for exec (persistence step)
        $remount = "/rootfs.rw"
    condition:
        uint32(0) == 1179403647
        and (any of ($path*) or 2 of ($comp*) or ($proc1 and (any of ($runit*) or $remount)))
        and filesize < 5MB
}

rule KeyDrift_SDWan_IOC : backdoor ioc
{
    meta:
        description = "KeyDrift SD-WAN implant -- protocol byte markers from PolyFlame/LittleFilch control-plane interception, TinyShell-like command vocabulary, or component triad"
        author      = "synthetic-detections"
        date        = "2026-10-30"
        severity    = "high"
        family      = "keydrift-sdwan"
        reference   = "https://blog.talosintelligence.com/uat-11473-keydrift/"
    strings:
        // LittleFilch buffer markers for key extraction
        $marker1   = { 40 03 06 }
        $marker2   = { 40 0C 04 }
        $marker3   = { 05 01 0C 06 40 }
        // PolyFlame/aaamgrd distinctive binary names
        $name1     = "aaamgrd"
        $name2     = "rsshd"
        $name3     = "libdssl.so"
        $name4     = "libcommon.so"
        // vdaemon staging paths
        $stage1    = "/tmp/system-vdaemon"
        $stage2    = "/var/tmp/vdaemon.bin"
        // timestomping pattern
        $timestomp = "touch --reference="
    condition:
        uint32(0) == 1179403647
        and (
            (#marker1 > 0 and #marker2 > 0 and #marker3 > 0) or
            (2 of ($name*) and any of ($stage*)) or
            (any of ($name*) and $timestomp and any of ($stage*))
        )
        and filesize < 5MB
}

rule KeyDrift_SDWan_Packed_Loader : backdoor structural
{
    meta:
        description = "KeyDrift aaamgrd packed loader -- ELF64 with no section headers, single RWE load segment, and anti-debug TracerPid check; structural anchor for the RC4-encrypted PolyFlame payload carrier"
        author      = "synthetic-detections"
        date        = "2026-10-30"
        severity    = "critical"
        family      = "keydrift-sdwan"
        reference   = "https://blog.talosintelligence.com/uat-11473-keydrift/"
    strings:
        $tracerpid = "TracerPid:"
        $aaamgr    = "aaamgr"
        $binsh     = "/bin/sh"
    condition:
        uint32(0) == 1179403647
        and uint8(4) == 2
        and uint16(58) == 0
        and $tracerpid
        and ($aaamgr or $binsh)
        and filesize < 3MB
        and filesize > 50KB
}
