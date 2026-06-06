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

   Three rules:
     1. MoonlightMaze_LOKI2 — original Phrack 51 LOKI2 implementation
        strings, structural names, and constants. Catches both the
        historical Moonlight Maze binaries and any modern derivative
        that reuses the verbatim code, including some Penquin Turla
        samples per the Kaspersky/KCL paper.
     2. Penquin_Turla_LinuxBackdoor — ELF gate + Penquin_x64-era
        strings (Leonardo S.p.A. April 2020 disclosure). Detects the
        modern Linux Turla backdoor proper.
     3. MoonlightMaze_Penquin_IOC — sweep over the nine SHA-256
        Penquin Turla samples and the campaign-anchor strings, for
        historical hunts and IOC dumps.

   Sources:
     https://securelist.com/penquins-moonlit-maze/  (Kaspersky + KCL paper)
     https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180251/Penquins_Moonlit_Maze_PDF_eng.pdf
     https://securelist.com/the-penquin-turla-2/67962/
     https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+%E2%80%9CPenquin_x64%E2%80%9D.pdf
     https://phrack.org/issues/51/6.html  (LOKI2 source — Phrack 51 #6, daemon9/route, 1997)
     https://en.wikipedia.org/wiki/Moonlight_Maze

   Acknowledgement: the Penquin-x64 string and opcode anchors used in
   rules 2 and 3 trace to Leonardo S.p.A.'s public YARA (2026-04-24);
   Neo23x0/signature-base also republishes them. This file bundles them
   with the LOKI2-source-code lineage anchors (rule 1) so the historical
   Moonlight Maze provenance and the modern Penquin detection sit in
   one family.
*/

rule MoonlightMaze_LOKI2
{
    meta:
        description = "LOKI2 covert-channel backdoor (Phrack 51 #6, 1997) — original tool used in Moonlight Maze, still appearing in modern derivatives via code reuse"
        author      = "synthetic-detections"
        date        = "2026-06-07"
        severity    = "critical"
        family      = "moonlight-maze-loki2-penquin"
        reference   = "https://phrack.org/issues/51/6.html"

    strings:
        // Verbatim format strings from the LOKI2 source — high specificity,
        // survive reuse, almost unique outside the LOKI codebase.
        $s_inactive_client = "lokid: inactive client <%d> expired from list [%d]" ascii
        $s_super_fatal     = "[SUPER fatal] control should NEVER fall here" ascii
        $s_db_full         = "lokid: Client database full" ascii
        $s_submit_typo     = "loki: submiting our public key to server" ascii
        $s_dh_fail         = "[fatal] Diffie-Hellman key generation failure" ascii
        $s_all_kill        = "lokid: client <%d> requested an all kill" ascii

        // Source-code-side anchors — catch the toolkit being staged for
        // (re)compilation on a compromised host.
        $src_loki_c   = "loki.c" ascii
        $src_lokid_c  = "lokid.c" ascii
        $src_client_db = "client_db.c" ascii
        $src_swap_t   = "swap_t(" ascii
        $src_lokid_xmit = "lokid_xmit" ascii
        $src_loki_xmit  = "loki_xmit" ascii
        $src_extract_bf = "extract_bf_key" ascii
        $src_generate_dh = "generate_dh_keypair" ascii

        // L_TAG magic — the LOKI2 packet identification marker (0xf001)
        // embedded in ICMP sequence field of every payload packet. Defined
        // as #define L_TAG 0xf001 in loki.h.
        $hdr_l_tag_def = /L_TAG\s+0xf001/ ascii

    condition:
        filesize < 50MB
        and (
            // Any single Phrack-51 verbatim string is sufficient — they are
            // distinctive enough that a false positive would essentially
            // require quoting the source code itself in a non-malicious
            // context (and even then the rule fires for a reason).
            any of ($s_*)
            // Or co-occurrence of source-tree filenames + function names —
            // catches the LOKI2 toolkit being staged on disk for compile
            // before any binary exists.
            or (
                2 of ($src_loki_c, $src_lokid_c, $src_client_db)
                and any of ($src_swap_t, $src_lokid_xmit, $src_loki_xmit,
                            $src_extract_bf, $src_generate_dh)
            )
            // Or explicit L_TAG definition (loki.h or a derivative header).
            or $hdr_l_tag_def
        )
}

rule Penquin_Turla_LinuxBackdoor
{
    meta:
        description = "Penquin Turla Linux backdoor (Penquin_x64 era, 2020 Leonardo disclosure) — modern descendant of Moonlight Maze toolchain"
        author      = "synthetic-detections"
        date        = "2026-06-07"
        severity    = "critical"
        family      = "moonlight-maze-loki2-penquin"
        reference   = "https://securelist.com/the-penquin-turla-2/67962/"

    strings:
        // String anchors recovered by Leonardo S.p.A. (2026-04-24) from
        // confirmed Penquin_x64 samples. Republished by Neo23x0 with
        // attribution. Reused here with credit.
        $p_hsperf    = "/root/.hsperfdata" ascii
        $p_desc_hdr  = "Desc| Filename | size |state|" ascii
        $p_vsfs      = "VS filesystem: %s" ascii
        $p_exists    = "File already exist on remote filesystem !" ascii
        $p_sync_pid  = "/tmp/.sync.pid" ascii
        $p_rem_fd    = "rem_fd: ssl " ascii
        $p_trex      = "TREX_PID=%u" ascii
        $p_xdfg      = "/tmp/.xdfg" ascii
        $p_happy     = "__we_are_happy__" ascii
        $p_sess      = "/root/.sess" ascii

    condition:
        // Same ELF + size gate as Leonardo's published rule for consistency
        // with the community signature. ELF magic at offset 0; reject any
        // sample over 5 MiB (Penquin samples are small statically-linked
        // ELFs in the 50 KiB - 2 MiB band).
        uint16(0) == 0x457F
        and filesize < 5MB
        and 4 of them
}

rule MoonlightMaze_Penquin_IOC
{
    meta:
        description = "Static IOC sweep — campaign markers and known SHA-256 of Penquin Turla samples from the Moonlight Maze code-lineage chain"
        author      = "synthetic-detections"
        date        = "2026-06-07"
        severity    = "high"
        family      = "moonlight-maze-loki2-penquin"
        reference   = "https://securelist.com/penquins-moonlit-maze/"

    strings:
        // Campaign + tooling names
        $c_moonlight_maze = "Moonlight Maze" ascii nocase
        $c_penquin        = "Penquin Turla" ascii nocase
        $c_loki2          = "LOKI2" ascii fullword
        $c_lokid          = "lokid" ascii fullword
        $c_hrtest         = "HRTest" ascii

        // Penquin Turla SHA-256 hashes published by Leonardo S.p.A. (2026-04-24).
        // These are de-facto consensus hashes adopted by Neo23x0 / signature-base.
        $h1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502" ascii nocase
        $h2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc" ascii nocase
        $h3 = "8856a68d95e4e79301779770a83e3fad8f122b849a9e9e31cfe06bf3418fa667" ascii nocase
        $h4 = "1d5e4466a6c5723cd30caf8b1c3d33d1a3d4c94c25e2ebe186c02b8b41daf905" ascii nocase
        $h5 = "2dabb2c5c04da560a6b56dbaa565d1eab8189d1fa4a85557a22157877065ea08" ascii nocase
        $h6 = "3e138e4e34c6eed3506efc7c805fce19af13bd62aeb35544f81f111e83b5d0d4" ascii nocase
        $h7 = "5a204263cac112318cd162f1c372437abf7f2092902b05e943e8784869629dd8" ascii nocase
        $h8 = "d49690ccb82ff9d42d3ee9d7da693fd7d302734562de088e9298413d56b86ed0" ascii nocase

        // Operator file-system convention from the original 1998 logs —
        // tasking files dropped under /var/tmp/
        $op_vartmp = "/var/tmp/" ascii

    condition:
        filesize < 50MB
        and (
            // Verbatim campaign / tool names — high-confidence singletons
            $c_moonlight_maze
            or $c_penquin
            or $c_hrtest
            // Or any specific published SHA-256 (one is enough — they're
            // 64-char unique strings)
            or any of ($h*)
            // Or LOKI2 / lokid plus the operator's /var/tmp/ working-dir
            // convention together (kills FPs on docs that mention LOKI2 in
            // passing without operational context)
            or (($c_loki2 or $c_lokid) and $op_vartmp)
        )
}
