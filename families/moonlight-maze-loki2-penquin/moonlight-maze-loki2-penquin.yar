/*
   Operation Moonlight Maze — LOKI2 + Penquin Turla detection
   ----------------------------------------------------------
   Moonlight Maze (1996-1999) was one of the earliest documented
   state-sponsored cyber-espionage campaigns: NASA, the Pentagon, DOE,
   Los Alamos, Sandia, and contractor / academic networks were breached
   from Sun Solaris pivots tunnelling data out via the open-source LOKI2
   covert-channel backdoor (Phrack 51 #6, Sep 1997).

   In 2017, Thomas Rid + Daniel Moore (King's College London) and
   Costin Raiu + Juan Andres Guerrero-Saade (Kaspersky) connected the
   1998 server logs (HRTest, admin: David Hedges) to **Penquin Turla** —
   a Linux backdoor in the modern Turla toolkit. The connecting tissue
   is direct code reuse of LOKI2 inside Penquin's covert-channel layer.
   Penquin samples have continued to appear: Penquin Turla (2014,
   Kaspersky), Penquin_x64 (2020, Leonardo S.p.A. + Securelist), with
   tens of European and US hosts still compromised at disclosure time.

   Six rules:
     1. MoonlightMaze_LOKI2 — original Phrack 51 LOKI2 implementation
        strings, structural names, and constants. Catches both the
        historical Moonlight Maze binaries and any modern derivative
        that reuses the verbatim code, including some Penquin Turla
        samples per the Kaspersky/KCL paper.
     2. Penquin_Turla_LinuxBackdoor — ELF gate + Penquin_x64-era
        strings (Leonardo S.p.A. April 2020 disclosure). Detects the
        modern Linux Turla backdoor proper.
     3. MoonlightMaze_Penquin_IOC — sweep over the eight SHA-256
        Penquin Turla samples and the campaign-anchor strings, for
        historical hunts and IOC dumps.
     4. Penquin_Turla_2014Era — 2014-era anchors: news-bbc.podzone C2,
        80.248.65.183 IP, three MD5 hashes, and the statically-linked
        glibc 2.3.2 / OpenSSL 0.9.6 / libpcap build fingerprint
        (Kaspersky Securelist, December 2014).
     5. Penquin_Turla_MagicPacket — Penquin's covert-channel
        authentication anchors: the verbatim libpcap BPF filter
        expressions for the 2014 samples (IDs 123 and 321) and the
        2020 Penquin_x64 first-stage mask 0xbdbd0560, plus a
        co-occurrence branch for cd00r-style pcap_setfilter on eth0.
     6. Penquin_Turla_Opcode_Leonardo — verbatim republication of
        Leonardo S.p.A.'s seven opcode byte sequences with explicit
        attribution; catches Penquin samples that have had their
        strings stripped.

   Sources:
     https://securelist.com/penquins-moonlit-maze/  (Kaspersky + KCL paper)
     https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180251/Penquins_Moonlit_Maze_PDF_eng.pdf
     https://securelist.com/the-penquin-turla-2/67962/
     https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+%E2%80%9CPenquin_x64%E2%80%9D.pdf
     https://phrack.org/issues/51/6.html  (LOKI2 source — Phrack 51 #6, daemon9/route, 1997)
     https://en.wikipedia.org/wiki/Moonlight_Maze

   Acknowledgements:
     - The Penquin-x64 string anchors (rule 2) and the seven opcode
       sequences (rule 6) trace to Leonardo S.p.A.'s public YARA
       (2026-04-24); Neo23x0/signature-base also republishes them.
       Reproduced here under fair-use for defensive purposes with
       attribution preserved in the rule meta.
     - The 2014-era Penquin C2/IP/MD5 anchors and the BPF magic-packet
       filter expressions (rules 4 and 5) trace to the 2014 Kaspersky
       Securelist write-up by Stefan Tanase et al.
     - The LOKI2 source-code lineage anchors (rule 1) trace to
       Phrack 51 #6 by daemon9/route (Sept 1997).
   This file bundles all of the above into a single family so the
   historical Moonlight Maze provenance and the modern Penquin
   detection sit in one place.
*/

rule MoonlightMaze_LOKI2 {
  meta:
    description = "LOKI2 covert-channel backdoor (Phrack 51 #6, 1997) — original tool used in Moonlight Maze, still appearing in modern derivatives via code reuse"
    author = "synthetic-detections"
    date = "2026-06-07"
    severity = "critical"
    family = "moonlight-maze-loki2-penquin"
    reference = "https://phrack.org/issues/51/6.html"
  strings:
    $s_inactive_client = "lokid: inactive client <%d> expired from list [%d]"
    $s_super_fatal = "[SUPER fatal] control should NEVER fall here"
    $s_db_full = "lokid: Client database full"
    $s_submit_typo = "loki: submiting our public key to server"
    $s_dh_fail = "[fatal] Diffie-Hellman key generation failure"
    $s_all_kill = "lokid: client <%d> requested an all kill"
    $src_loki_c = "loki.c"
    $src_lokid_c = "lokid.c"
    $src_client_db = "client_db.c"
    $src_swap_t = "swap_t("
    $src_lokid_xmit = "lokid_xmit"
    $src_loki_xmit = "loki_xmit"
    $src_extract_bf = "extract_bf_key"
    $src_generate_dh = "generate_dh_keypair"
    $hdr_l_tag_def = /L_TAG\s+0xf001/
  condition:
    (any of ($s_*) or 2 of ($src_loki_c, $src_lokid_c, $src_client_db) and any of ($src_swap_t, $src_lokid_xmit, $src_loki_xmit, $src_extract_bf, $src_generate_dh) or $hdr_l_tag_def) and filesize < 50MB
}

rule Penquin_Turla_LinuxBackdoor {
  meta:
    description = "Penquin Turla Linux backdoor (Penquin_x64 era, 2020 Leonardo disclosure) — modern descendant of Moonlight Maze toolchain"
    author = "synthetic-detections"
    date = "2026-06-07"
    severity = "critical"
    family = "moonlight-maze-loki2-penquin"
    reference = "https://securelist.com/the-penquin-turla-2/67962/"
  strings:
    $p_hsperf = "/root/.hsperfdata"
    $p_desc_hdr = "Desc| Filename | size |state|"
    $p_vsfs = "VS filesystem: %s"
    $p_exists = "File already exist on remote filesystem !"
    $p_sync_pid = "/tmp/.sync.pid"
    $p_rem_fd = "rem_fd: ssl "
    $p_trex = "TREX_PID=%u"
    $p_xdfg = "/tmp/.xdfg"
    $p_happy = "__we_are_happy__"
    $p_sess = "/root/.sess"
  condition:
    uint16(0) == 17791 and 4 of them and filesize < 5MB
}

rule MoonlightMaze_Penquin_IOC {
  meta:
    description = "Static IOC sweep — campaign markers and known SHA-256 of Penquin Turla samples from the Moonlight Maze code-lineage chain"
    author = "synthetic-detections"
    date = "2026-06-07"
    severity = "high"
    family = "moonlight-maze-loki2-penquin"
    reference = "https://securelist.com/penquins-moonlit-maze/"
  strings:
    $c_moonlight_maze = "Moonlight Maze" nocase
    $c_penquin = "Penquin Turla" nocase
    $c_loki2 = "LOKI2" fullword
    $c_lokid = "lokid" fullword
    $c_hrtest = "HRTest"
    $h1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502" nocase
    $h2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc" nocase
    $h3 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" nocase
    $h4 = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905" nocase
    $h5 = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08" nocase
    $h6 = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4" nocase
    $h7 = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8" nocase
    $h8 = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0" nocase
    $op_vartmp = "/var/tmp/"
  condition:
    ($c_moonlight_maze or $c_penquin or $c_hrtest or any of ($h*) or ($c_loki2 or $c_lokid) and $op_vartmp) and filesize < 50MB
}

rule Penquin_Turla_2014Era {
  meta:
    description = "2014-era Penquin Turla Linux backdoor — C2 hostname, IP, MD5 sample hashes, statically-linked-glibc/openssl/libpcap fingerprint (Kaspersky Securelist 2014)"
    author = "synthetic-detections"
    date = "2026-06-07"
    severity = "high"
    family = "moonlight-maze-loki2-penquin"
    reference = "https://securelist.com/the-penquin-turla-2/67962/"
  strings:
    $c2_dom = "news-bbc.podzone" nocase
    $c2_ip = "80.248.65.183"
    $md5_1 = "0994d9deb50352e76b0322f48ee576c6" nocase
    $md5_2 = "14ecd5e6fc8e501037b54ca263896a11" nocase
    $md5_3 = "19fbd8cbfb12482e8020a887d6427315" nocase
    $glibc_old = "glibc2.3.2"
    $openssl_old = "OpenSSL 0.9.6" nocase
    $libpcap_old = "libpcap" nocase
    $sh_wrapper = "/bin/sh -c "
  condition:
    ($c2_dom or $c2_ip or any of ($md5_*) or uint16(0) == 17791 and 2 of ($glibc_old, $openssl_old, $libpcap_old) and $sh_wrapper) and filesize < 5MB
}

rule Penquin_Turla_MagicPacket {
  meta:
    description = "Penquin Turla BPF magic-packet authentication anchors — verbatim libpcap filter expressions (2014 IDs 123/321) and the 2020 Penquin_x64 0xbdbd0560 mask"
    author = "synthetic-detections"
    date = "2026-06-07"
    severity = "critical"
    family = "moonlight-maze-loki2-penquin"
    reference = "https://lab52.io/blog/looking-for-penquins-in-the-wild/"
  strings:
    $bpf_id123_tcp = "tcp[8:4] & 0xe007ffff = 0xe003bebe"
    $bpf_id321_tcp = "tcp[8:4] & 0xe007ffff = 0x1bebe"
    $bpf_udp_12 = "udp[12:4] & 0xe007ffff"
    $mask_2020_str = "0xbdbd0560" nocase
    $mask_2020_le = { 60 05 BD BD }
    $mask_2020_be = { BD BD 05 60 }
    $pcap_setfilter = "pcap_setfilter"
    $pcap_open_live = "pcap_open_live"
    $eth0_iface = "eth0" fullword
  condition:
    (any of ($bpf_id123_tcp, $bpf_id321_tcp, $bpf_udp_12) or $mask_2020_str or $mask_2020_le or $mask_2020_be or uint16(0) == 17791 and $pcap_setfilter and $pcap_open_live and $eth0_iface) and filesize < 5MB
}

rule Penquin_Turla_Opcode_Leonardo {
  meta:
    description = "Penquin_x64 opcode patterns republished verbatim from Leonardo S.p.A. 2026-04-24 (also in Neo23x0/signature-base apt_turla_penquin.yar). Catches Penquin samples that have had their strings stripped"
    author = "Leonardo S.p.A. (anchors) + synthetic-detections (packaging)"
    date = "2026-06-07"
    severity = "critical"
    family = "moonlight-maze-loki2-penquin"
    reference = "https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+%E2%80%9CPenquin_x64%E2%80%9D.pdf"
    attribution = "Anchor byte sequences are Leonardo S.p.A.'s original work; published 2026-04-24 under their public threat-research output and adopted by Neo23x0/signature-base as apt_turla_penquin.yar. Reproduced here under fair-use for defensive purposes with attribution preserved."
  strings:
    $op0 = { 8D 41 05 32 06 48 FF C6 88 81 E0 80 69 00 }
    $op1 = { 48 FF C1 48 83 F9 49 75 E9 }
    $op2 = { C7 05 9B 7D 29 00 1D 00 00 00 C7 05 2D 7B 29 00 65 74 68 30 C6 05 2A 7B 29 00 00 E8 }
    $op3 = { BF FF FF FF FF E8 96 9D 0A 00 90 90 90 90 90 90 90 90 90 90 89 F0 }
    $op4 = { 88 D3 80 C3 05 32 9A C1 D6 0C 08 88 9A 60 A1 0F 08 42 83 FA 08 76 E9 }
    $op5 = { 8B 8D 50 DF FF FF B8 09 00 00 00 89 44 24 04 89 0C 24 E8 DD E5 02 00 }
    $op6 = { 8D 5A 05 32 9A 60 26 0C 08 88 9A 20 F4 0E 08 42 83 FA 48 76 EB }
    $op7 = { 8D 4A 05 32 8A 25 26 0C 08 88 8A 20 F4 0E 08 42 83 FA 08 76 EB }
  condition:
    uint16(0) == 17791 and 2 of them and filesize < 5MB
}
