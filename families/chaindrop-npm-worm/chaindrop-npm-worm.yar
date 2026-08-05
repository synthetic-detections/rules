/*
   ChainDrop — self-propagating npm worm (Shai-Hulud descendant), 2026-08-04
   -------------------------------------------------------------------------
   Compromise of the GitHub account of Jared Wray (maintainer of keyv,
   cacheable, flat-cache, file-entry-cache, cacheable-request, cache-manager,
   ecto ...). Malicious releases were cut through the projects' OWN GitHub
   Actions pipelines, so poisoned versions shipped with VALID npm provenance
   (trusted-pipeline defeat, as in the 2026-07-14 AsyncAPI compromise). Earliest
   malicious release keyv@6.0.0 at 2026-08-04 09:35:00Z; StepSecurity attributes
   444 packages / 2,212 versions (11 primary carriers + 433 second-wave); Aikido
   counted up to 868 packages / 1,381 versions (>2B monthly installs, largely via
   the ESLint chain eslint -> file-entry-cache -> flat-cache -> keyv).

   Chain: package.json "preinstall": "node setup.mjs" -> setup.mjs drops a
   standalone Bun runtime and runs an obfuscated ~727,680-byte stage-2
   (Math_Symbol.js / math_init.js). Stage-2 hits AWS IMDS (169.254.169.254),
   reads Vault / Kubernetes / GCP / Azure / npm secrets, runs a TruffleHog-style
   key sweep, republishes trojanized versions via stolen npm tokens, and plants
   IDE hooks in .claude / .vscode configs to target AI coding assistants.
   Harvests are committed to public GitHub repos described "Shai-Hulud: Here We
   Go Again" (results-*.json).

   C2 is first-in-family EtherHiding: an Ethereum-mainnet contract read via
   eth_call across ~75 public RPC endpoints, with an HTTP fallback (npm-cache.com)
   and a GitHub-commit-search fallback whose dead-drop strings
   ("thebeautifulsnadsoftime", "thebeautifulmarchoftime") are mutations of
   TeamPCP's known "TheBeautifulSandsOfTime" dead-drop — corroborating the
   Shai-Hulud / TeamPCP lineage (copycat authorship plausible given the worm is
   open-sourced). Related family baselines: [[ironworm-npm-worm]],
   [[miasma-redhat-npm]], [[miasma-v2-phantom-gyp]], [[easydayjs-mastra-rat]].

   Rule 1 — npm manifest behavioural: package.json with the ChainDrop
            "preinstall": "node setup.mjs" wiring.
   Rule 2 — IOC sweep: EtherHiding contract, HTTP C2, dead-drop strings,
            payload filenames, exfil marker (co-occurrence-guarded).
   Rule 3 — stage-2 specimen: SHA-256 pins for the loader + harvester, plus a
            size-band + AWS-IMDS heuristic fallback.

   Sources:
     https://www.stepsecurity.io/blog/chaindrop-npm-worm
     https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/
     https://semgrep.dev/blog/2026/its-not-npm-ver-yet-npm-worm-chaindrop-hits-400-packages-including-jaredwray-servicetitan-ornikar-qlik-and-nebulajs/
     https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack
     https://www.bleepingcomputer.com/news/security/massive-chaindrop-npm-supply-chain-attack-infects-hundreds-of-packages/
*/

import "hash"

rule ChainDrop_NpmManifest
{
    meta:
        description = "npm package.json carrying the ChainDrop preinstall wiring \"preinstall\": \"node setup.mjs\" — worm dropper hook"
        author      = "synthetic-detections"
        date        = "2026-08-05"
        severity    = "critical"
        family      = "chaindrop-npm-worm"
        reference   = "https://www.stepsecurity.io/blog/chaindrop-npm-worm"

    strings:
        // package.json structural anchors
        $pkg_name    = "\"name\"" ascii
        $pkg_scripts = "\"scripts\"" ascii

        // The ChainDrop preinstall command — bounded regex tolerant of spacing
        // and quoting; pins the "node setup.mjs" invocation observed across the
        // jaredwray primary wave and the second-wave propagation.
        $preinst = /"preinstall"\s*:\s*"[^"]{0,20}node\s+\.?\/?setup\.mjs[^"]{0,20}"/ ascii

    condition:
        // Small JSON manifest carrying the exact preinstall wiring. The command
        // "node setup.mjs" as a preinstall hook is the ChainDrop dropper anchor;
        // a benign package using a differently-named setup script will not match.
        filesize < 128KB
        and $pkg_name
        and $pkg_scripts
        and $preinst
}

rule ChainDrop_IOC
{
    meta:
        description = "ChainDrop static IOC sweep — EtherHiding contract, HTTP C2, GitHub dead-drop strings, payload filenames, exfil marker"
        author      = "synthetic-detections"
        date        = "2026-08-05"
        severity    = "high"
        family      = "chaindrop-npm-worm"
        reference   = "https://www.stepsecurity.io/blog/chaindrop-npm-worm"

    strings:
        // Globally-unique campaign indicators — safe to fire standalone.
        $eth_contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103" ascii nocase
        $c2_http      = "npm-cache.com" ascii nocase
        $dd1          = "thebeautifulsnadsoftime" ascii nocase
        $dd2          = "thebeautifulmarchoftime" ascii nocase
        $dd3          = "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients" ascii

        // Family-level / corroborating tokens — generic enough to require a
        // cluster or a unique indicator alongside them.
        $eth_selector = "0x53ed5143" ascii nocase          // eth_call selector, not unique alone
        $marker       = "Shai-Hulud: Here We Go Again" ascii  // shared across Mini Shai-Hulud waves
        $f1           = "Math_Symbol.js" ascii
        $f2           = "math_init.js" ascii
        $f3           = "router_runtime.js" ascii
        $imds         = "169.254.169.254" ascii

    condition:
        filesize < 50MB
        and (
            // Unique ChainDrop indicators fire on their own.
            any of ($eth_contract, $c2_http, $dd1, $dd2, $dd3)
            or
            // Otherwise require a corroborating cluster: the shared Shai-Hulud
            // marker plus at least one payload-filename or the IMDS+selector pair.
            (
                $marker
                and ( 2 of ($f1, $f2, $f3) or ($imds and $eth_selector) )
            )
        )
}

rule ChainDrop_Stage2_Specimen
{
    meta:
        description = "ChainDrop loader/harvester specimen — SHA-256 pins (setup.mjs, Math_Symbol.js) plus a size-band + AWS-IMDS heuristic"
        author      = "synthetic-detections"
        date        = "2026-08-05"
        severity    = "critical"
        family      = "chaindrop-npm-worm"
        reference   = "https://www.stepsecurity.io/blog/chaindrop-npm-worm"

    strings:
        $imds     = "169.254.169.254" ascii
        $math     = "Math_Symbol" ascii
        $marker   = "Shai-Hulud: Here We Go Again" ascii

    condition:
        // Exact SHA-256 pins for the known specimens (zero-FP).
        hash.sha256(0, filesize) == "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc"  // Math_Symbol.js / math_init.js stage-2
        or hash.sha256(0, filesize) == "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668"  // setup.mjs loader A (jaredwray wave)
        or hash.sha256(0, filesize) == "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb"  // setup.mjs loader B (second wave)
        // Heuristic fallback for repacked stage-2 variants: the ~727,680-byte
        // harvester band carrying the AWS-IMDS host and a Bun/self reference.
        or (
            filesize >= 680KB and filesize <= 800KB
            and $imds
            and ($math or $marker)
        )
}
