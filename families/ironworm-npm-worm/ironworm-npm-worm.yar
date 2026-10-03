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
        $pkg_scripts   = "\"scripts\""
        $pkg_preinst   = "\"preinstall\""
        // The IronWorm preinstall command shape — bounded regex catches the
        // observed "./tools/setup" form plus near-variants reported by JFrog
        // (".github/scripts/precheck", "tools/<name>", etc.)
        $preinst_tools = /"preinstall"\s*:\s*"[^"]{0,40}(tools\/[A-Za-z0-9._-]{1,40}|\.github\/scripts\/[A-Za-z0-9._-]{1,40})[^"]{0,40}"/
        // Spoofed-author tells reported by JFrog
        $spoof_author  = "claude@users.noreply.github.com" nocase
        $publisher     = "asteroiddao" nocase
        $real_attacker = "ocrybit" nocase
    condition:
        $pkg_scripts
        and $pkg_preinst
        and (
            $preinst_tools or
            any of ($spoof_author, $publisher, $real_attacker)
        )
        and filesize < 256KB
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
        $upx_magic   = "UPX!"
        $c2_endpoint = "/api/agent"
        // BIP-39 seed phrase of the operator's wallet (from JFrog analysis of
        // the unpacked binary; only visible post-unpack but worth pinning).
        $bip39       = "bench crane defense corn wheel trial news abuse finish better paddle slush"
    condition:
        // ELF64 in the ~976 KB dropper size band. UPX packing ALONE matched any
        // packed ELF in this band (busybox, Go tools), so require a packed
        // sample to also carry the agent C2 path; the unique post-unpack BIP-39
        // operator seed fires on its own.
        // EI_CLASS = ELFCLASS64
        uint32(0) == 1179403647
        and uint8(4) == 2
        and (
            $bip39 or
            ($upx_magic and $c2_endpoint)
        )
        and filesize > 700KB
        and filesize < 1500KB
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
        $publisher     = "asteroiddao" nocase
        $real_attacker = "ocrybit" nocase
        $spoof_author  = "claude@users.noreply.github.com" nocase
        // Wallet seed phrase (12-word BIP-39) and derived address
        $bip39         = "bench crane defense corn wheel trial news abuse finish better paddle slush"
        $wallet        = "0x7e28D9889f414B06c19a22A9Bd316f0AC279a4d6" nocase
        // Fake commit messages embedded in the binary
        $commit1       = "fix: resolve lint warnings"
        $commit2       = "test: add missing edge case"
        $commit3       = "ci: update workflow configuration"
        $commit4       = "fix: address review feedback"
        $commit5       = "docs: update contributing guide"
        $commit6       = "chore: sync lockfile"
        $commit7       = "fix: handle null pointer case"
        $commit8       = "build: bump patch version"
        $commit9       = "chore: update dependencies"
        // Affected package coordinates (37 names, all WeaveDB / Arweave ecosystem).
        // A subset suffices — package names are PoC-specific and rotate per campaign.
        $pkg01         = "weavedb-sdk"
        $pkg02         = "weavedb-sdk-base"
        $pkg03         = "weavedb-sdk-node"
        $pkg04         = "weavedb-client"
        $pkg05         = "weavedb-base"
        $pkg06         = "weavedb-contracts"
        $pkg07         = "weavedb-node-client"
        $pkg08         = "weavedb-offchain"
        $pkg09         = "weavedb-console"
        $pkg10         = "weavedb-exm-sdk"
        $pkg11         = "weavedb-exm-sdk-web"
        $pkg12         = "weavedb-lite"
        $pkg13         = "weavedb-warp-contracts-plugin-deploy"
        $pkg14         = "test-weavedb-sdk"
        $pkg15         = "weavedb-tools"
        $pkg16         = "wdb-core"
        $pkg17         = "wdb-cli"
        $pkg18         = "wdb-sdk"
        $pkg19         = "arnext-arkb"
        $pkg20         = "create-arnext-app"
        $pkg21         = "atomic-notes"
        $pkg22         = "fpjson-lang"
        $pkg23         = "warp-contracts-plugin-deploy-test"
        // Compromised GitHub organisations (JFrog list)
        $org1          = "asteroid-dao" nocase
        $org2          = "ArweaveOasis" nocase
        $org3          = "warashibe" nocase
        $org4          = "kakedashi-hacker" nocase
    condition:
        // Globally-unique campaign indicators — safe to fire standalone.
        // The fake commit messages are ordinary conventional commits (they
        // match any CHANGELOG) and the package/org names are the LEGITIMATE
        // pre-compromise coordinates (they match any WeaveDB lockfile). They
        // only corroborate — require a cluster AND a unique indicator.
        (
            any of ($publisher, $real_attacker, $spoof_author, $bip39, $wallet) or
            ((4 of ($commit*) or 3 of ($pkg*) or 2 of ($org*)) and any of ($publisher, $real_attacker, $spoof_author, $bip39, $wallet))
        )
        and filesize < 50MB
}
