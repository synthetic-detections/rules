/*
   rust-proc-macro1-crate-dropper — crates.io build-script dropper
   (crates.io / Rust Security Response WG, disclosed 2026-08-20)
   ---------------------------------------------------------------------
   Supply-chain compromise of the crates.io ecosystem. On 2026-08-20 the
   account behind the widely-used `arrayref` (245M downloads), `internment`
   and `append-only-vec` crates was used to publish poisoned releases
   (arrayref 0.3.10 / internment 0.8.7 / append-only-vec 0.1.9) that silently
   added a dependency on `proc-macro1` — a typosquat of `proc-macro2`
   impersonating maintainer dtolnay. `proc-macro1 1.0.107` carried a weaponised
   build.rs that runs AT BUILD TIME: it reassembles a payload host and C2
   address from base64 fragments, opens a TLS connection with certificate
   validation disabled (an AcceptAll ServerCertVerifier that returns
   Ok(assertion) unconditionally), fetches an OS/arch-specific binary
   (rust-crate_0.1.0..0.4.0), and executes it detached from the Cargo build.
   On Unix/macOS the payload lands at /tmp/rust-setup (chmod +x, spawned with
   nulled stdio); on Windows it is dropped as %TEMP%\rust-setup.ps1 with a
   rust-setup-launch.vbs launcher started hidden via wscript.exe, the handle
   leaked with std::mem::forget to escape Cargo's job object. The stage-2
   implant is an infostealer (Chromium logins SQLite, wallet data) with
   persistence via ~/.config/AzureKits + ~/.config/ServiceKit and MonoService /
   MonoXpc binaries (Linux systemd user service; macOS LaunchAgent; Windows Run
   key). Payload host 23.254.165.112:9089, C2 23.254.165.112:443, additional
   stage-2 C2 23.254.167.216 / 23.254.167.107 / hwsrv-798836.hostwindsdns.com
   (all Hostwinds). Lure: arrayref 0.3.5–0.3.9 were yanked so cargo's "consider
   a version that is not yanked" nudged resolution to the malicious 0.3.10.
   Attacker crates: proc-macro1, proc-macro-en, aovine, arone, aronenao,
   tinymember.

   Related build/install-time supply-chain droppers in this repo:
   npm — [[chaindrop-npm-worm]], [[ironworm-npm-worm]], [[miasma-redhat-npm]],
   [[miasma-v2-phantom-gyp]], [[quickfox-fdmtp-supply-chain]],
   [[bdthemes-biggopti-supply-chain]]; RubyGems — [[sleepergem-rubygems]];
   Packagist — [[famous-chollima-packagist]].

   Rule 1 — Behavioral: proc-macro1 build.rs dropper shape (base64 URL
            reassembly + TLS-verify bypass + /tmp/rust-setup or wscript VBS
            drop), co-occurrence-guarded so no single generic token trips it.
   Rule 2 — IOC: infrastructure IPs/host/paths, dropper/persistence file names,
            attacker crate names, .crate SHA-256s.
   Rule 3 — Specimen-pin: tight, distinctive artifact combination.

   Sources:
     https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
     https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack
     https://www.aikido.dev/blog/two-popular-rust-crates-arrayref-and-append-only-vec-compromised-in-supply-chain-attack
     https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html
*/

rule Rust_ProcMacro1_Dropper_Behavior
{
    meta:
        description = "proc-macro1 crates.io build-script dropper — build.rs base64 URL reassembly + TLS-verify bypass + rust-setup payload drop/exec"
        author      = "synthetic-detections"
        date        = "2026-08-22"
        severity    = "critical"
        family      = "rust-proc-macro1-crate-dropper"
        reference   = "https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack"

    strings:
        // base64 URL fragments reassembled at build time (host 23.254.165.112:9089 / :443)
        $u_https  = "aHR0cHM6Ly8=" ascii   // "https://"
        $u_23254  = "MjMuMjU0Lg==" ascii   // "23.254."
        $u_165    = "MTY1Lg==" ascii       // "165."
        $u_112    = "MTEyOg==" ascii       // "112:"
        $u_9089   = "OTA4OS8=" ascii       // "9089/"
        $u_443    = "NDQz" ascii           // "443"

        // build.rs structural markers
        $s_srcparts = "SRC_URL_PARTS" ascii
        $s_endparts = "END_URL_PARTS" ascii
        $s_rununix  = "run_unix_payload" ascii
        $s_acceptall= "AcceptAll" ascii
        $s_certveri = "ServerCertVerifier" ascii
        $s_assert   = "ServerCertVerified::assertion" ascii

        // drop / execute
        $d_setup    = "/tmp/rust-setup" ascii
        $d_ps1      = "rust-setup.ps1" ascii
        $d_vbs      = "rust-setup-launch.vbs" ascii
        $d_forget   = "std::mem::forget(child)" ascii

        // OS/arch payload selector names
        $p_c010 = "rust-crate_0.1.0" ascii
        $p_c020 = "rust-crate_0.2.0" ascii
        $p_c030 = "rust-crate_0.3.0" ascii
        $p_c040 = "rust-crate_0.4.0" ascii

    condition:
        filesize < 2MB
        and (
            // the two build.rs URL-fragment array names together are pathognomonic
            ($s_srcparts and $s_endparts)
            // TLS-verify bypass helper co-occurring with a drop/exec sink
            or ((any of ($s_acceptall, $s_certveri, $s_assert)) and (any of ($d_setup, $d_ps1, $d_vbs, $d_forget)))
            // named dropper routine plus a drop artifact
            or ($s_rununix and (any of ($d_setup, $p_c010, $p_c020, $p_c030, $p_c040)))
            // three or more of the reassembly fragments together (host chain)
            or (3 of ($u_https, $u_23254, $u_165, $u_112, $u_9089, $u_443) and (any of ($d_setup, $d_ps1, $s_srcparts, $p_c010, $p_c020, $p_c030, $p_c040)))
            // two distinct rust-crate payload selectors plus a drop path
            or (2 of ($p_c010, $p_c020, $p_c030, $p_c040) and (any of ($d_setup, $d_ps1, $d_vbs)))
        )
}

rule Rust_ProcMacro1_Dropper_IOC
{
    meta:
        description = "proc-macro1 crates.io dropper — infra IPs/host/paths, dropper+persistence file names, attacker crate names, .crate SHA-256s"
        author      = "synthetic-detections"
        date        = "2026-08-22"
        severity    = "high"
        family      = "rust-proc-macro1-crate-dropper"
        reference   = "https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/"

    strings:
        // stage-1 payload host + C2, stage-2 C2 (Hostwinds)
        $i_host9089 = "23.254.165.112:9089" ascii
        $i_c2443    = "23.254.165.112:443" ascii
        $i_ip112    = "23.254.165.112" ascii
        $i_ip216    = "23.254.167.216" ascii
        $i_ip107    = "23.254.167.107" ascii
        $i_hwsrv    = "hwsrv-798836.hostwindsdns.com" ascii nocase

        // dropper + persistence artifacts
        $f_setup    = "/tmp/rust-setup" ascii
        $f_ps1      = "rust-setup.ps1" ascii
        $f_vbs      = "rust-setup-launch.vbs" ascii
        $f_azure    = ".config/AzureKits" ascii
        $f_service  = ".config/ServiceKit" ascii
        $f_monosvc  = "MonoService" ascii
        $f_monoxpc  = "MonoXpc" ascii

        // attacker-owned crate names (co-occurrence guarded — generic-ish)
        $c_pm1      = "proc-macro1" ascii
        $c_pmen     = "proc-macro-en" ascii
        $c_aovine   = "aovine" ascii
        $c_arone    = "arone" ascii fullword
        $c_aronenao = "aronenao" ascii
        $c_tiny     = "tinymember" ascii

        // .crate SHA-256s
        $h_arrayref = "25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae" ascii nocase
        $h_pm107    = "61198155da51b838772eecf5bfaac6cbc4dcc388dccc56658fc28a8e831b34d4" ascii nocase
        $h_pm106    = "b5c1b5b0763a8809a644a8f92224653f0aca623a98eecc714d27f74b80fbe436" ascii nocase

    condition:
        filesize < 5MB
        and (
            // exact sample hash — pinned, near-zero FP
            any of ($h_*)
            // distinctive infra literals
            or $i_host9089 or $i_c2443 or $i_ip216 or $i_ip107 or $i_hwsrv
            // bare payload IP guarded by a dropper/persistence artifact
            or ($i_ip112 and (any of ($f_setup, $f_ps1, $f_vbs, $f_azure, $f_service, $f_monosvc, $f_monoxpc)))
            // dropper file names co-occurring
            or ($f_ps1 and $f_vbs)
            or ($f_setup and (any of ($f_ps1, $f_vbs, $f_azure, $f_service)))
            // persistence dir + implant binary
            or ((any of ($f_azure, $f_service)) and (any of ($f_monosvc, $f_monoxpc)))
            // typosquat crate name plus an attacker sibling crate (guards proc-macro1 alone)
            or ($c_pm1 and (any of ($c_pmen, $c_aovine, $c_aronenao, $c_tiny)))
            or (2 of ($c_pmen, $c_aovine, $c_arone, $c_aronenao, $c_tiny))
        )
}

rule Rust_ProcMacro1_Dropper_Specimen
{
    meta:
        description = "proc-macro1 crates.io dropper — tight specimen pin (build.rs dropper shape + host reassembly)"
        author      = "synthetic-detections"
        date        = "2026-08-22"
        severity    = "critical"
        family      = "rust-proc-macro1-crate-dropper"
        reference   = "https://www.aikido.dev/blog/two-popular-rust-crates-arrayref-and-append-only-vec-compromised-in-supply-chain-attack"

    strings:
        $s_srcparts = "SRC_URL_PARTS" ascii
        $s_endparts = "END_URL_PARTS" ascii
        $s_rununix  = "run_unix_payload" ascii
        $s_acceptall= "AcceptAll" ascii
        $u_https    = "aHR0cHM6Ly8=" ascii
        $u_9089     = "OTA4OS8=" ascii
        $d_setup    = "/tmp/rust-setup" ascii
        $d_vbs      = "rust-setup-launch.vbs" ascii
        $i_host9089 = "23.254.165.112:9089" ascii

    condition:
        filesize < 2MB
        and ($s_srcparts and $s_endparts)
        and (
            $s_rununix or $s_acceptall
            or ($u_https and $u_9089)
            or (any of ($d_setup, $d_vbs, $i_host9089))
        )
}
