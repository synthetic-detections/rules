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

rule RustDuck_Botnet_Behavior {
  meta:
    description = "RustDuck botnet — anti-analysis enumeration, honeypot detection, VM/sandbox evasion, crypto protocol markers"
    author = "synthetic-detections"
    date = "2026-07-01"
    severity = "critical"
    family = "rustduck-botnet"
    reference = "https://blog.xlab.qianxin.com/rustduck-en/"
    hash = "8315f650e9e4f67c00277b076ab304eed23db47d"
  strings:
    $dbg_wireshark = "wireshark" nocase
    $dbg_tcpdump = "tcpdump"
    $dbg_frida = "frida"
    $dbg_x64dbg = "x64dbg" nocase
    $dbg_strace = "strace"
    $proc_status = "/proc/self/status"
    $proc_maps = "/proc/self/maps"
    $hp_cowrie = "/etc/cowrie/"
    $vm_vbox1 = "virtualbox" nocase
    $vm_vbox2 = "vbox" nocase
    $vm_bochs = "bochs" nocase
    $vm_vmware = "08:00:27"
    $env_sandbox = "sandbox" nocase
    $env_malware = "malware" nocase
    $env_virus = "virus" nocase
    $env_sample = "sample" nocase
    $cry_hkdf = "HKDF"
    $cry_ascon = "Ascon128"
    $cry_chacha = "ChaCha20"
    $cry_noise = "Noise_IK"
  condition:
    uint32(0) == 1179403647 and (3 of ($dbg_*) and any of ($proc_*) or $hp_cowrie and any of ($vm_*) and any of ($env_*) or 2 of ($dbg_*) and any of ($cry_*) or 2 of ($vm_*) and 2 of ($env_*) and any of ($proc_*) or any of ($cry_ascon, $cry_noise) and any of ($cry_hkdf, $cry_chacha) or $cry_noise and (any of ($dbg_*) or any of ($vm_*)) or $hp_cowrie and 2 of ($dbg_*)) and filesize < 10MB
}

rule RustDuck_ELF_Loader {
  meta:
    description = "RustDuck loader — ELF with variant-specific overlay magic bytes, LZ4 decompression, two-stage architecture"
    author = "synthetic-detections"
    date = "2026-07-01"
    severity = "critical"
    family = "rustduck-botnet"
    reference = "https://blog.xlab.qianxin.com/rustduck-en/"
  strings:
    $magic_v3 = "ASHPCK\x01\x00"
    $magic_v4 = "iEMPK\x02\x00\x00"
    $lz4_decomp1 = "LZ4_decompress"
    $cfg_loader = "loader"
    $cfg_config = "config"
    $prng_xoshi = "xoshiro" nocase
    $kex_curve = "curve25519" nocase
  condition:
    uint32(0) == 1179403647 and (any of ($magic_v3, $magic_v4) or $lz4_decomp1 and $kex_curve and any of ($cfg_*) or $prng_xoshi and $lz4_decomp1) and filesize > 20KB and filesize < 10MB
}

rule RustDuck_IOC {
  meta:
    description = "Static IOC sweep — RustDuck C2 domains, spreading infrastructure, sample hashes"
    author = "synthetic-detections"
    date = "2026-07-01"
    severity = "high"
    family = "rustduck-botnet"
    reference = "https://blog.xlab.qianxin.com/rustduck-en/"
    hash1 = "8315f650e9e4f67c00277b076ab304eed23db47d"
    hash2 = "6aa791c76b3107fca9d57b7ecea8f46d97d83738"
    hash3 = "4d11bd496da82d15b3ed13050f414e44f5a892d4"
    hash4 = "d39a3ee96be6b8f5238cb1253514ab55c88f714c"
  strings:
    $c2_01 = "gayporn.twilightparadox.com" nocase
    $c2_02 = "bigniggadick.ignorelist.com" nocase
    $c2_03 = "ilovefemboy.mooo.com" nocase
    $c2_04 = "igmc.duckdns.org" nocase
    $c2_05 = "qewqewqewqtq.duckdns.org" nocase
    $c2_06 = "qewqewqewqtqthree.duckdns.org" nocase
    $c2_07 = "qewqewqewqtqtwo.duckdns.org" nocase
    $c2_08 = "dhdsjsdjxc.duckdns.org" nocase
    $c2_09 = "fcfrfxrfrsfs5f.duckdns.org" nocase
    $c2_10 = "disciplinenahidwin.st" nocase
    $c2_11 = "criminalcloudflare.online" nocase
    $spread_ip = "176.65.139.204"
  condition:
    any of them and filesize < 50MB
}
