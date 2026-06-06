/*
   Miasma v2 / "Phantom Gyp" — npm worm using binding.gyp + forged SLSA provenance
   --------------------------------------------------------------------------------
   Disclosed 2026-06-04/05 (Semgrep, StepSecurity, Corgea, Snyk, The Hacker News).
   57 npm packages compromised across 286+ malicious versions in a rolling
   campaign under two hours on 2026-06-03 starting 23:30 UTC.

   Delivery shift from earlier Miasma: the install-time execution primitive
   moved from preinstall lifecycle scripts to a 157-byte binding.gyp file.
   node-gyp parses binding.gyp during `npm install` to build native bindings
   and expands `<!(<command>)` action substitutions by executing the shell
   command. The malicious file uses:

       "sources": ["<!(node index.js > /dev/null 2>&1 && echo stub.c)"]

   which forces `node index.js` to run during dependency install — without
   any preinstall/postinstall script in package.json — and most install-time
   monitors do not watch binding.gyp.

   The shipped index.js is a ~4-5 MB obfuscated payload that:
     - decodes Bun v1.3.13 via AES-128-GCM, downloads it from
       github.com/oven-sh/bun/releases/download/,
     - runs the actual stealer with Bun out of /tmp/p*.js,
     - sweeps AWS/GCP/Azure/k8s/GitHub-OIDC/npm/RubyGems/1Password/Slack/SSH
       credentials,
     - exfils to attacker GitHub repos under account `liuende501` via
       `{repo}/contents/results/results-{timestamp}.json`,
     - injects backdoors at .claude/setup.mjs, .claude/settings.json,
       .cursor/rules/setup.mdc, .vscode/tasks.json, .github/setup.js,
     - self-propagates by republishing packages with stolen npm Trusted
       Publishing tokens AND forges Sigstore Fulcio cert + Rekor log entry
       + SLSA v1 provenance attestation.

   Rule 1 — behavioural: binding.gyp file with the command-substitution
            primitive that defeats preinstall-script monitoring.
   Rule 2 — behavioural on the obfuscated index.js: campaign-unique markers
            ("thebeautifulmarchoftime", "IfYouInvalidate..." token check)
            plus credential-sweep co-occurrence.
   Rule 3 — IOC sweep: campaign strings, attacker GitHub account,
            backdoor file paths, representative compromised package
            coordinates.

   Sibling families: [[miasma-redhat-npm]] (the original preinstall
   variant), [[ironworm-npm-worm]] (Rust + eBPF cousin).

   Sources:
     https://semgrep.dev/blog/2026/miasma-v2-self-spreading-npm-worm-now-uses-malicious-bindinggyp-file-and-compromises-57-packages/
     https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm
     https://corgea.com/research/miasma-phantom-gyp-npm-worm-vapi-ai-sdk-ollama-june-2026
     https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/
     https://thehackernews.com/2026/06/ironworm-and-new-miasma-worm-variant.html
*/

rule MiasmaV2_PhantomGyp_BindingGypTrigger
{
    meta:
        description = "binding.gyp with a `<!(<cmd>)` command-substitution action that triggers code execution during npm install — Phantom Gyp delivery primitive"
        author      = "synthetic-detections"
        date        = "2026-06-06"
        severity    = "critical"
        family      = "miasma-v2-phantom-gyp"
        reference   = "https://semgrep.dev/blog/2026/miasma-v2-self-spreading-npm-worm-now-uses-malicious-bindinggyp-file-and-compromises-57-packages/"

    strings:
        // node-gyp action expansion + a JS / shell binary as the substituted command
        $action_node  = /<!\s*\(\s*node\s+[A-Za-z0-9._\/-]{1,80}\.(m?js|cjs)/ ascii
        $action_bash  = /<!\s*\(\s*(bash|sh|curl|wget|python3?)\s+[^)]{1,200}\)/ ascii

        // The verbatim Phantom Gyp shape Semgrep / Corgea published
        $phantom_pattern = /<!\s*\(\s*node\s+index\.(m?js|cjs)\s*>\s*\/dev\/null/ ascii

        // sources/inputs/actions fields where node-gyp will expand <!(...)
        $field_sources = /"sources"\s*:\s*\[/ ascii
        $field_inputs  = /"inputs"\s*:\s*\[/ ascii
        $field_actions = /"actions"\s*:\s*\[/ ascii

    condition:
        // binding.gyp files are typically tiny — campaign sample is 157 bytes.
        // Cap at 8 KiB to skip large legitimate node-gyp build manifests
        // and to keep the rule cheap to evaluate.
        filesize < 8KB
        and (
            $phantom_pattern
            or (
                any of ($field_sources, $field_inputs, $field_actions)
                and any of ($action_node, $action_bash)
            )
        )
}

rule MiasmaV2_PhantomGyp_ObfuscatedPayload
{
    meta:
        description = "Obfuscated index.js root payload — Phantom Gyp campaign-unique markers + credential-sweep co-occurrence"
        author      = "synthetic-detections"
        date        = "2026-06-06"
        severity    = "critical"
        family      = "miasma-v2-phantom-gyp"
        reference   = "https://corgea.com/research/miasma-phantom-gyp-npm-worm-vapi-ai-sdk-ollama-june-2026"

    strings:
        // Verbatim campaign markers Corgea + Semgrep recovered from the payload
        $marker_beacon = "thebeautifulmarchoftime" ascii nocase
        $marker_nuke   = "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner" ascii

        // Bun bootstrap chain — downloads pinned Bun version then runs payload
        $bun_release  = "github.com/oven-sh/bun/releases/download/" ascii nocase
        $bun_run      = /bun\s+run\s+\/tmp\/p[^"'\s]{1,40}\.(m?js|cjs)/ ascii
        $tmp_b        = /\/tmp\/b-[A-Za-z0-9._-]{1,40}/ ascii

        // Exfil shape — POSTs results to attacker GitHub repos
        $exfil_path   = /\/contents\/results\/results-[0-9]{1,16}\.json/ ascii
        $exfil_repo   = "liuende501" ascii nocase

        // Credential-target tokens — at least two co-occurring indicate a
        // genuine credential sweep, not a piece of documentation
        $cred_aws     = "AWS_ACCESS_KEY_ID" ascii
        $cred_gcp     = "GOOGLE_APPLICATION_CREDENTIALS" ascii
        $cred_az      = "AZURE_CLIENT_SECRET" ascii
        $cred_npm     = "NPM_TOKEN" ascii
        $cred_gha     = "ACTIONS_RUNTIME_TOKEN" ascii
        $cred_vault   = "VAULT_TOKEN" ascii
        $cred_kube    = "/.kube/config" ascii
        $cred_ssh     = "/.ssh/" ascii
        $cred_1pwd    = "OP_SERVICE_ACCOUNT_TOKEN" ascii
        $cred_slack   = "SLACK_BOT_TOKEN" ascii

    condition:
        // Real payload is ~4.5 MiB obfuscated; band catches mid-build variants too
        filesize > 256KB
        and filesize < 20MB
        and (
            // Campaign-unique anchor (singleton)
            $marker_beacon
            or $marker_nuke
            // Or Bun-chain co-occurrence + credential sweep
            or (
                ($bun_release or $bun_run or $tmp_b)
                and 3 of ($cred_aws, $cred_gcp, $cred_az, $cred_npm, $cred_gha,
                          $cred_vault, $cred_kube, $cred_ssh, $cred_1pwd, $cred_slack)
            )
            // Or exfil-path + repo + credential sweep
            or (
                $exfil_path and $exfil_repo
                and 2 of ($cred_aws, $cred_gcp, $cred_az, $cred_npm, $cred_gha,
                          $cred_vault, $cred_kube, $cred_ssh)
            )
        )
}

rule MiasmaV2_PhantomGyp_IOC
{
    meta:
        description = "Static IOCs for Miasma v2 / Phantom Gyp — campaign markers, attacker GitHub account, backdoor file paths, representative compromised package coordinates"
        author      = "synthetic-detections"
        date        = "2026-06-06"
        severity    = "high"
        family      = "miasma-v2-phantom-gyp"
        reference   = "https://semgrep.dev/blog/2026/miasma-v2-self-spreading-npm-worm-now-uses-malicious-bindinggyp-file-and-compromises-57-packages/"

    strings:
        // High-confidence campaign anchors
        $marker_beacon   = "thebeautifulmarchoftime" ascii nocase
        $marker_nuke     = "IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner" ascii
        $exfil_repo      = "liuende501" ascii nocase
        $technique_name  = "Phantom Gyp" ascii nocase

        // Backdoor file paths reported by Corgea
        $bd_claude_mjs  = ".claude/setup.mjs" ascii
        $bd_claude_json = ".claude/settings.json" ascii
        $bd_cursor      = ".cursor/rules/setup.mdc" ascii
        $bd_vscode      = ".vscode/tasks.json" ascii
        $bd_github_setup = ".github/setup.js" ascii

        // Representative compromised npm coordinates (largest victims; full
        // list of 57 / 286 versions is published by Semgrep + Corgea)
        $pkg_vapi_1 = "@vapi-ai/server-sdk@0.11.1" ascii
        $pkg_vapi_2 = "@vapi-ai/server-sdk@0.11.2" ascii
        $pkg_vapi_3 = "@vapi-ai/server-sdk@1.2.1" ascii
        $pkg_vapi_4 = "@vapi-ai/server-sdk@1.2.2" ascii
        $pkg_ollama_1 = "ai-sdk-ollama@0.13.1" ascii
        $pkg_ollama_2 = "ai-sdk-ollama@1.1.1" ascii
        $pkg_ollama_3 = "ai-sdk-ollama@2.2.1" ascii
        $pkg_ollama_4 = "ai-sdk-ollama@3.8.5" ascii
        $pkg_autotel  = "autotel" ascii
        $pkg_awaitly  = "awaitly" ascii
        $pkg_estories = "executable-stories" ascii
        $pkg_envresolver = "node-env-resolver" ascii

    condition:
        filesize < 50MB
        and (
            // High-confidence anchors fire alone
            $marker_beacon
            or $marker_nuke
            or $exfil_repo
            or $technique_name
            // A specific pinned vulnerable version
            or any of ($pkg_vapi_*, $pkg_ollama_*)
            // Backdoor-path co-occurrence (≥2 paths together is a strong signal;
            // any single path can appear legitimately in dev environments)
            or 2 of ($bd_claude_mjs, $bd_claude_json, $bd_cursor, $bd_vscode, $bd_github_setup)
            // Family-name + at least one package name (catches IOC writeups)
            or (any of ($pkg_autotel, $pkg_awaitly, $pkg_estories, $pkg_envresolver)
                and ($marker_beacon or $marker_nuke or $technique_name))
        )
}
