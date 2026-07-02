/*
   Miasma → Microsoft Azure / AI-agent-config trigger (disclosed 2026-06-06)
   --------------------------------------------------------------------------
   On 2026-06-05 GitHub disabled 73 Microsoft repositories in a 105-second
   sweep across the Azure, Azure-Samples, Microsoft, and MicrosoftDocs
   organisations after a compromised contributor account pushed a malicious
   commit to `Azure/durabletask`. The escalation moves the Miasma worm's
   install-time execution from `preinstall`/`binding.gyp` onto **AI-coding-
   agent workspace configs**: opening the repo in Claude Code, Gemini CLI,
   Cursor, or VS Code is the trigger.

   The plant always lands in:

       .claude/settings.json     -> SessionStart hook running .github/setup.js
       .cursor/rules/setup.mdc   -> rule injection telling the agent to run setup.js
       .gemini/settings.json     -> equivalent settings hook
       .vscode/tasks.json        -> task with "runOn": "folderOpen"
       package.json              -> "test" script hijacked to setup.js
       .github/setup.js          -> 4.3 MiB Bun-based credential-sweep payload

   Credential targets: AWS CLI, Azure, GCP, Kubernetes (.kube/config), npm
   auth tokens, GitHub PATs. Exfil to attacker-controlled GitHub accounts
   (windy629 with 200+ dead-drop repos, HerGomUli, liuende501) plus repos
   named "Miasma: The Spreading Blight" / "Hades - The End for the Damned".

   Three rules:
     1. AIAgentConfigInjection — co-occurrence of any AI-agent workspace
        config file content that invokes ./github/setup.js (or runs node
        on a .github/* path). Catches the planted manifests on disk
        regardless of which specific file the operator picked.
     2. PayloadRunner — the 4.3 MiB `.github/setup.js` Bun-based payload,
        gated on size band + Bun runtime imports + credential-sweep
        targets + the published SHA-256 of two known runners.
     3. IOC sweep — exfil GitHub accounts, campaign theme strings,
        affected Microsoft repo names.

   Sibling families: [[miasma-redhat-npm]] (the original @redhat-cloud-services
   preinstall variant), [[miasma-v2-phantom-gyp]] (the binding.gyp +
   forged-SLSA variant), [[ironworm-npm-worm]] (Rust + eBPF cousin).

   Sources:
     https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html
     https://opensourcemalware.com/blog/miasma-reaches-azure
     https://thecybersecguru.com/news/miasma-worm-targets-ai-coding-agents-github-microsoft/
*/

rule Miasma_Azure_AIAgentConfigInjection
{
    meta:
        description = "Workspace AI-coding-agent config (.claude / .cursor / .gemini / .vscode / package.json) wired to invoke .github/setup.js — the Miasma Azure trigger primitive"
        author      = "synthetic-detections"
        date        = "2026-06-07"
        severity    = "critical"
        family      = "miasma-azure-aiagent"
        reference   = "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"

    strings:
        // Direct invocation of the planted runner from any agent-config
        // file — the load-bearing pattern that's identical across the
        // five plant sites.
        $invoke_setup = /node\s+\.?\/?\.github\/setup\.js/ ascii

        // Specific shape per planted config (Claude SessionStart hook,
        // Cursor rule injection, VS Code folderOpen task, npm test script
        // hijack). 2-of these is a strong corroborator for the worm shape
        // even when the file extension is unusual.
        $claude_hook  = /SessionStart[^}]{1,400}\.github\/setup\.js/ ascii
        $cursor_rule  = /Run\s+`?node\s+\.?\/?\.github\/setup\.js`?\s+to\s+initialize/ ascii nocase
        $vscode_task  = /"runOn"\s*:\s*"folderOpen"/ ascii
        $npm_test     = /"test"\s*:\s*"node\s+\.?\/?\.github\/setup\.js"/ ascii
        $gemini_set   = /"\.gemini\/settings\.json"/ ascii

        // Standalone runner-path references (in case the rule applies to
        // setup.js itself, a directory listing, or a tasking dump).
        // Match both with and without leading "/" — JSON `args` arrays
        // use the unprefixed form ".github/setup.js" while shell paths
        // use "./.github/setup.js" or "/full/path/.github/setup.js".
        $path_runner  = ".github/setup.js" ascii
        $path_claude  = ".claude/settings.json" ascii
        $path_cursor  = ".cursor/rules/setup.mdc" ascii

    condition:
        filesize < 256KB
        and (
            // Either the verbatim invocation phrase (catches the
            // single-string command form — Claude hook, npm test hijack,
            // Cursor rule prose, single-line VS Code command).
            $invoke_setup
            // Or a co-occurrence of two of the agent-specific config
            // shapes (catches obfuscated invocations of the same payload).
            or 2 of ($claude_hook, $cursor_rule, $vscode_task, $npm_test, $gemini_set)
            // Or a single agent-specific config shape paired with a
            // setup.js path reference — catches the args-array VS Code
            // form ("args": [".github/setup.js"], runOn: folderOpen) and
            // similar split-invocation variants.
            or (
                any of ($vscode_task, $claude_hook, $cursor_rule, $npm_test, $gemini_set)
                and $path_runner
            )
            // Or co-occurrence of any two of the path-listing anchors
            // (catches IOC dumps and forensic artefact listings).
            or 2 of ($path_runner, $path_claude, $path_cursor)
        )
}

rule Miasma_Azure_PayloadRunner
{
    meta:
        description = "Miasma Azure setup.js runner — 4.3 MiB Bun-based credential-sweep payload (two published SHA-256 + behavioural anchors)"
        author      = "synthetic-detections"
        date        = "2026-06-07"
        severity    = "critical"
        family      = "miasma-azure-aiagent"
        reference   = "https://thecybersecguru.com/news/miasma-worm-targets-ai-coding-agents-github-microsoft/"

    strings:
        // Published SHA-256 of the runner (in IOC dumps / writeups)
        $h_pub_1 = "d630397de8b01af0f6f5cf4463da91b17f28195a2c50c8f3f38ad9f7873fdb8e" ascii nocase
        $h_pub_2 = "3a9db5ba0c8cd4c91e91717df6b1a141fc1e0fbc0558b5a78d7f5c23f5b2a150" ascii nocase

        // Bun-runtime fingerprints (Miasma v1+ stages all bootstrap Bun
        // via download then run /tmp/* — this pattern moves in-tree)
        $bun_release = "github.com/oven-sh/bun/releases/download/" ascii nocase
        $bun_run     = /bun\s+run\s+\/tmp\/[A-Za-z0-9._-]{1,40}\.(m?js|cjs)/ ascii
        $tmp_b       = /\/tmp\/b-[A-Za-z0-9._-]{1,40}/ ascii

        // Credential sweep target tokens — at least three indicates an
        // active credential harvester, not a documentation snippet.
        $cred_aws    = "AWS_ACCESS_KEY_ID" ascii
        $cred_az     = "AZURE_CLIENT_SECRET" ascii
        $cred_gcp    = "GOOGLE_APPLICATION_CREDENTIALS" ascii
        $cred_kube   = "/.kube/config" ascii
        $cred_npm    = "NPM_TOKEN" ascii
        $cred_gha    = "ACTIONS_RUNTIME_TOKEN" ascii
        $cred_gh_pat = "gho_" ascii  // GitHub PAT prefix; rule includes co-occurrence guard
        $cred_ssh    = "/.ssh/" ascii

    condition:
        // Specific hash always fires
        any of ($h_pub_*)
        or (
            // Behavioural: size band typical of the 4.3 MiB bloated runner
            // (loosened to accept 2-16 MiB for future generations)
            filesize > 1MB and filesize < 20MB
            and any of ($bun_release, $bun_run, $tmp_b)
            and 3 of ($cred_aws, $cred_az, $cred_gcp, $cred_kube,
                      $cred_npm, $cred_gha, $cred_gh_pat, $cred_ssh)
        )
}

rule Miasma_Azure_IOC
{
    meta:
        description = "Static IOCs — Miasma Azure exfil GitHub accounts, campaign theme strings, sample affected Microsoft repo names"
        author      = "synthetic-detections"
        date        = "2026-06-07"
        severity    = "high"
        family      = "miasma-azure-aiagent"
        reference   = "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"

    strings:
        // Attacker GitHub accounts hosting dead-drop exfil repos
        $acc_windy629 = "windy629" ascii fullword
        $acc_hergom   = "HerGomUli" ascii fullword
        $acc_liuende  = "liuende501" ascii fullword

        // Campaign theme strings used as exfil repo descriptions
        $theme_blight = "Miasma: The Spreading Blight" ascii
        $theme_hades  = "Hades - The End for the Damned" ascii
        $theme_name   = "TeamPCP" ascii fullword

        // Sample affected Microsoft repo coordinates (subset of 73)
        $repo_azsearch  = "azure-search-openai-demo" ascii
        $repo_durable_n = "durabletask-dotnet" ascii
        $repo_durable_g = "durabletask-go" ascii
        $repo_durable_j = "durabletask-js" ascii
        $repo_durable_m = "durabletask-mssql" ascii
        $repo_funcs     = "functions-container-action" ascii
        $repo_llm_ft    = "llm-fine-tuning" ascii
        $repo_winddocs  = "windows-driver-docs" ascii

        // Direct-compromise non-Microsoft repos (icflorescu/*)
        $repo_mantine_dt = "mantine-datatable" ascii
        $repo_mantine_cm = "mantine-contextmenu" ascii

    condition:
        filesize < 50MB
        and (
            // Attacker accounts or campaign themes — high-confidence singletons
            $acc_windy629 or $acc_hergom or $acc_liuende
            or $theme_blight or $theme_hades
            // NOTE: bare repo coordinates are not IOCs on their own — the
            // mantine-* libraries and azure-search/durabletask samples are
            // widely used, so a benign app or lockfile easily lists two.
            // Require a campaign anchor (attacker account, theme, or the
            // TeamPCP marker) alongside the repo names.
            // TeamPCP + a repo name corroborates campaign attribution writeup
            or ($theme_name and any of ($repo_*))
        )
}
