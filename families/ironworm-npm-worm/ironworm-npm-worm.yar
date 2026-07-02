/*
   IronWorm — Rust npm worm with eBPF rootkit and Tor C2 (disclosed 2026-06-04)
   ----------------------------------------------------------------------------
   Compromised npm packages republished by attacker-controlled publisher
   "asteroiddao" (real identity: "ocrybit"). Each package's package.json carries
   a "preinstall": "./tools/setup" hook pointing to a 976 KB UPX-packed Rust
   ELF binary. The binary loads an eBPF kernel rootkit for process and socket
   hiding, beacons to /api/agent over a Tor hidden service, sweeps 86 env vars
   + 20 credential files, and self-propagates by abusing stolen npm Trusted
   Publishing OIDC tokens.

   Operator wallet seed (from binary): "bench crane defense corn wheel trial
   news abuse finish better paddle slush"
   Derived address: 0x7e28D9889f414B06c19a22A9Bd316f0AC279a4d6

   First-wave packages target the Arweave / WeaveDB Web3 ecosystem (37
   coordinates). Linux-only payload; macOS / Windows installs fail at
   preinstall, but their CI runners and downstream consumers are still
   reachable via the propagation step.

   Rule 1 — package.json behavioural: preinstall invoking ./tools/setup
            (or equivalent) plus IronWorm-target package metadata.
   Rule 2 — ELF specimen: ELF64 + UPX!-packed + 976 KB size band.
   Rule 3 — IOC sweep: publisher, attacker handle, wallet seed/address,
            fake commit messages, all 37 affected package coordinates.

   Sources:
     https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
     https://www.ox.security/blog/ironworm-supply-chain-malware-hits-npm/
     https://www.bleepingcomputer.com/news/security/new-ironworm-malware-hits-36-packages-in-npm-supply-chain-attack/
     https://phoenix.security/ironworm-npm-supply-chain-worm-rust-ebpf-rootkit-tor/
*/

rule IronWorm_NpmPackageManifest
{
    meta:
        description = "npm package.json with IronWorm-style preinstall hook invoking a binary in tools/ — co-occurrence with scripts/credential targets"
        author      = "synthetic-detections"
        date        = "2026-06-05"
        severity    = "critical"
        family      = "ironworm-npm-worm"
        reference   = "https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/"

    strings:
        // package.json structural anchors
        $pkg_scripts  = "\"scripts\"" ascii
        $pkg_preinst  = "\"preinstall\"" ascii

        // The IronWorm preinstall command shape — bounded regex catches the
        // observed "./tools/setup" form plus near-variants reported by JFrog
        // (".github/scripts/precheck", "tools/<name>", etc.)
        $preinst_tools   = /"preinstall"\s*:\s*"[^"]{0,40}(tools\/[A-Za-z0-9._-]{1,40}|\.github\/scripts\/[A-Za-z0-9._-]{1,40})[^"]{0,40}"/ ascii

        // Spoofed-author tells reported by JFrog
        $spoof_author = "claude@users.noreply.github.com" ascii nocase
        $publisher    = "asteroiddao" ascii nocase
        $real_attacker = "ocrybit" ascii nocase

    condition:
        filesize < 256KB
        and $pkg_scripts
        and $pkg_preinst
        and (
            $preinst_tools
            or any of ($spoof_author, $publisher, $real_attacker)
        )
}

rule IronWorm_LinuxELF_Dropper
{
    meta:
        description = "UPX-packed Rust ELF dropper in the ~976 KB size band — IronWorm tools/setup specimen profile"
        author      = "synthetic-detections"
        date        = "2026-06-05"
        severity    = "critical"
        family      = "ironworm-npm-worm"
        reference   = "https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/"

    strings:
        $upx_magic   = "UPX!" ascii
        $c2_endpoint = "/api/agent" ascii
        // BIP-39 seed phrase of the operator's wallet (from JFrog analysis of
        // the unpacked binary; only visible post-unpack but worth pinning).
        $bip39 = "bench crane defense corn wheel trial news abuse finish better paddle slush" ascii

    condition:
        // ELF64 in the ~976 KB dropper size band. UPX packing ALONE matched any
        // packed ELF in this band (busybox, Go tools), so require a packed
        // sample to also carry the agent C2 path; the unique post-unpack BIP-39
        // operator seed fires on its own.
        uint32(0) == 0x464C457F
        and uint8(4) == 2          // EI_CLASS = ELFCLASS64
        and filesize > 700KB
        and filesize < 1500KB
        and ($bip39 or ($upx_magic and $c2_endpoint))
}

rule IronWorm_IOC
{
    meta:
        description = "Static IOC sweep — publisher, attacker handles, wallet seed/address, fake commit messages, 37 affected npm package coordinates"
        author      = "synthetic-detections"
        date        = "2026-06-05"
        severity    = "high"
        family      = "ironworm-npm-worm"
        reference   = "https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/"

    strings:
        // Attacker handles
        $publisher     = "asteroiddao" ascii nocase
        $real_attacker = "ocrybit" ascii nocase
        $spoof_author  = "claude@users.noreply.github.com" ascii nocase

        // Wallet seed phrase (12-word BIP-39) and derived address
        $bip39 = "bench crane defense corn wheel trial news abuse finish better paddle slush" ascii
        $wallet = "0x7e28D9889f414B06c19a22A9Bd316f0AC279a4d6" ascii nocase

        // Fake commit messages embedded in the binary
        $commit1 = "fix: resolve lint warnings" ascii
        $commit2 = "test: add missing edge case" ascii
        $commit3 = "ci: update workflow configuration" ascii
        $commit4 = "fix: address review feedback" ascii
        $commit5 = "docs: update contributing guide" ascii
        $commit6 = "chore: sync lockfile" ascii
        $commit7 = "fix: handle null pointer case" ascii
        $commit8 = "build: bump patch version" ascii
        $commit9 = "chore: update dependencies" ascii

        // Affected package coordinates (37 names, all WeaveDB / Arweave ecosystem).
        // A subset suffices — package names are PoC-specific and rotate per campaign.
        $pkg01 = "weavedb-sdk" ascii
        $pkg02 = "weavedb-sdk-base" ascii
        $pkg03 = "weavedb-sdk-node" ascii
        $pkg04 = "weavedb-client" ascii
        $pkg05 = "weavedb-base" ascii
        $pkg06 = "weavedb-contracts" ascii
        $pkg07 = "weavedb-node-client" ascii
        $pkg08 = "weavedb-offchain" ascii
        $pkg09 = "weavedb-console" ascii
        $pkg10 = "weavedb-exm-sdk" ascii
        $pkg11 = "weavedb-exm-sdk-web" ascii
        $pkg12 = "weavedb-lite" ascii
        $pkg13 = "weavedb-warp-contracts-plugin-deploy" ascii
        $pkg14 = "test-weavedb-sdk" ascii
        $pkg15 = "weavedb-tools" ascii
        $pkg16 = "wdb-core" ascii
        $pkg17 = "wdb-cli" ascii
        $pkg18 = "wdb-sdk" ascii
        $pkg19 = "arnext-arkb" ascii
        $pkg20 = "create-arnext-app" ascii
        $pkg21 = "atomic-notes" ascii
        $pkg22 = "fpjson-lang" ascii
        $pkg23 = "warp-contracts-plugin-deploy-test" ascii

        // Compromised GitHub organisations (JFrog list)
        $org1 = "asteroid-dao" ascii nocase
        $org2 = "ArweaveOasis" ascii nocase
        $org3 = "warashibe" ascii nocase
        $org4 = "kakedashi-hacker" ascii nocase

    condition:
        filesize < 50MB
        and (
            // Globally-unique campaign indicators — safe to fire standalone.
            any of ($publisher, $real_attacker, $spoof_author, $bip39, $wallet)
            or
            // The fake commit messages are ordinary conventional commits (they
            // match any CHANGELOG) and the package/org names are the LEGITIMATE
            // pre-compromise coordinates (they match any WeaveDB lockfile). They
            // only corroborate — require a cluster AND a unique indicator.
            (
                (4 of ($commit*) or 3 of ($pkg*) or 2 of ($org*))
                and any of ($publisher, $real_attacker, $spoof_author, $bip39, $wallet)
            )
        )
}
