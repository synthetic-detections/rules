/*
   RustDuck IoT/server DDoS botnet
   (tracked since February 2026, XLab / Qianxin)
   -----------------------------------------------
   Two-stage botnet (Loader + Core) actively migrating from C to Rust.
   Targets home routers, IP cameras, Android TV boxes, and exposed
   servers via Telnet/SSH brute-force and multi-vendor RCE exploits
   (TP-Link CVE-2017-17215, ZTE CVE-2024-1781, Android ADB,
   Jenkins CVE-2018-8007, CVE-2025-29635).

   Architecture: ELF loader decrypts a compressed payload (LZ4) with
   variant-specific encryption (LCG+XOR, standard XOR, or ChaCha20),
   then hands execution to a heavier core module. Loader variants
   identified by distinct magic bytes at overlay boundary:
     Variant 3: "ASHPCK\x01\x00"
     Variant 4: "iEMPK\x02\x00\x00"

   Crypto stack: HKDF-SHA256 key derivation, Curve25519 ECDH (Noise_IK
   pattern) for forward secrecy, Ascon128 or ChaCha20-Poly1305 for
   handshake, AES-GCM for command loop. Some variants rotate keys every
   10 minutes using time-based derivation. Network protocol mimics
   SSL record headers (0x17 0x03 0x03) with 12-byte nonce + 16-byte
   authentication tag.

   Anti-analysis: enumerates running processes for debuggers/sniffers,
   checks /proc entries and honeypot markers (/etc/cowrie/), detects
   VMs via MAC OUI and keywords, filters environment variables for
   sandbox indicators.

   Rule 1 — Behavioral: anti-analysis process list, VM/sandbox
            detection, /proc introspection, crypto algorithm markers.
   Rule 2 — Structural: ELF magic + loader variant magic bytes at
            overlay boundary, LZ4 decompression markers.
   Rule 3 — IOC: C2 domains (DDNS + custom), spreading IP, sample
            hashes.

   Sources:
     https://blog.xlab.qianxin.com/rustduck-en/
     https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html
     https://securityaffairs.com/194556/malware/rustduck-the-botnet-thats-still-small-but-engineering-like-it-plans-to-grow.html
*/

import "elf"

rule RustDuck_Botnet_Behavior
{
    meta:
        description = "RustDuck botnet — anti-analysis enumeration, honeypot detection, VM/sandbox evasion, crypto protocol markers"
        author      = "synthetic-detections"
        date        = "2026-07-01"
        severity    = "critical"
        family      = "rustduck-botnet"
        reference   = "https://blog.xlab.qianxin.com/rustduck-en/"
        hash        = "8315f650e9e4f67c00277b076ab304eed23db47d"

    strings:
        // Anti-analysis — debugger/sniffer process names
        $dbg_wireshark = "wireshark" ascii nocase
        $dbg_tcpdump   = "tcpdump" ascii
        $dbg_frida     = "frida" ascii
        $dbg_x64dbg    = "x64dbg" ascii nocase
        $dbg_strace    = "strace" ascii

        // /proc introspection for debugging/tracing detection
        $proc_status = "/proc/self/status" ascii
        $proc_maps   = "/proc/self/maps" ascii

        // Honeypot detection — cowrie SSH honeypot marker
        $hp_cowrie   = "/etc/cowrie/" ascii

        // VM detection — hypervisor keywords
        $vm_vbox1    = "virtualbox" ascii nocase
        $vm_vbox2    = "vbox" ascii nocase
        $vm_bochs    = "bochs" ascii nocase
        $vm_vmware   = "08:00:27" ascii

        // Sandbox environment variable filtering
        $env_sandbox = "sandbox" ascii nocase
        $env_malware = "malware" ascii nocase
        $env_virus   = "virus" ascii nocase
        $env_sample  = "sample" ascii nocase

        // Crypto algorithm identifiers embedded in binary
        $cry_hkdf    = "HKDF" ascii
        $cry_ascon   = "Ascon128" ascii
        $cry_chacha  = "ChaCha20" ascii
        $cry_noise   = "Noise_IK" ascii

    condition:
        filesize < 10MB
        and uint32(0) == 0x464C457F  // ELF magic
        and (
            // Path 1: anti-analysis process list (3+) + /proc introspection
            (3 of ($dbg_*) and any of ($proc_*))
            or
            // Path 2: honeypot detection + VM detection + sandbox env filtering
            ($hp_cowrie and any of ($vm_*) and any of ($env_*))
            or
            // Path 3: anti-analysis + crypto protocol markers
            (2 of ($dbg_*) and any of ($cry_*))
            or
            // Path 4: VM + sandbox evasion suite (both categories)
            (2 of ($vm_*) and 2 of ($env_*) and any of ($proc_*))
            or
            // Path 5: crypto stack co-occurrence — HKDF + symmetric cipher
            ($cry_hkdf and any of ($cry_ascon, $cry_chacha))
            or
            // Path 6: Noise protocol + any anti-analysis
            ($cry_noise and (any of ($dbg_*) or any of ($vm_*)))
            or
            // Path 7: honeypot + debugger detection in an ELF
            ($hp_cowrie and 2 of ($dbg_*))
        )
}

rule RustDuck_ELF_Loader
{
    meta:
        description = "RustDuck loader — ELF with variant-specific overlay magic bytes, LZ4 decompression, two-stage architecture"
        author      = "synthetic-detections"
        date        = "2026-07-01"
        severity    = "critical"
        family      = "rustduck-botnet"
        reference   = "https://blog.xlab.qianxin.com/rustduck-en/"

    strings:
        // Loader variant 3 magic (at overlay/appended data boundary)
        $magic_v3 = "ASHPCK\x01\x00" ascii

        // Loader variant 4 magic (ChaCha20-encrypted payload)
        $magic_v4 = "iEMPK\x02\x00\x00" ascii

        // LZ4 decompression — function name reference
        $lz4_decomp1 = "LZ4_decompress" ascii

        // Loader config parsing — three-part structure markers
        $cfg_loader  = "loader" ascii
        $cfg_config  = "config" ascii

        // Xoshiro128 PRNG (variant 2 key generation)
        $prng_xoshi  = "xoshiro" ascii nocase

        // Curve25519 key exchange reference
        $kex_curve   = "curve25519" ascii nocase

    condition:
        filesize > 20KB and filesize < 10MB
        and uint32(0) == 0x464C457F  // ELF magic
        and (
            // Path 1: variant 3 or 4 magic anywhere in file (overlay)
            (any of ($magic_v3, $magic_v4))
            or
            // Path 2: LZ4 decompression + key exchange + config structure
            ($lz4_decomp1 and $kex_curve and any of ($cfg_*))
            or
            // Path 3: Xoshiro PRNG + LZ4 in an ELF (distinctive combo)
            ($prng_xoshi and $lz4_decomp1)
        )
}

rule RustDuck_IOC
{
    meta:
        description = "Static IOC sweep — RustDuck C2 domains, spreading infrastructure, sample hashes"
        author      = "synthetic-detections"
        date        = "2026-07-01"
        severity    = "high"
        family      = "rustduck-botnet"
        reference   = "https://blog.xlab.qianxin.com/rustduck-en/"
        hash1       = "8315f650e9e4f67c00277b076ab304eed23db47d"
        hash2       = "6aa791c76b3107fca9d57b7ecea8f46d97d83738"
        hash3       = "4d11bd496da82d15b3ed13050f414e44f5a892d4"
        hash4       = "d39a3ee96be6b8f5238cb1253514ab55c88f714c"

    strings:
        // DDNS C2 domains
        $c2_01 = "gayporn.twilightparadox.com" ascii nocase
        $c2_02 = "bigniggadick.ignorelist.com" ascii nocase
        $c2_03 = "ilovefemboy.mooo.com" ascii nocase
        $c2_04 = "igmc.duckdns.org" ascii nocase
        $c2_05 = "qewqewqewqtq.duckdns.org" ascii nocase
        $c2_06 = "qewqewqewqtqthree.duckdns.org" ascii nocase
        $c2_07 = "qewqewqewqtqtwo.duckdns.org" ascii nocase
        $c2_08 = "dhdsjsdjxc.duckdns.org" ascii nocase
        $c2_09 = "fcfrfxrfrsfs5f.duckdns.org" ascii nocase

        // Registered C2 domains
        $c2_10 = "disciplinenahidwin.st" ascii nocase
        $c2_11 = "criminalcloudflare.online" ascii nocase

        // Primary spreading IP (as string — appears in dropper scripts)
        $spread_ip = "176.65.139.204" ascii

    condition:
        filesize < 50MB
        and any of them
}
