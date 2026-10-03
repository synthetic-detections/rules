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

rule Miasma_Azure_AIAgentConfigInjection {
  meta:
    description = "Workspace AI-coding-agent config (.claude / .cursor / .gemini / .vscode / package.json) wired to invoke .github/setup.js — the Miasma Azure trigger primitive"
    author = "synthetic-detections"
    date = "2026-06-07"
    severity = "critical"
    family = "miasma-azure-aiagent"
    reference = "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"
  strings:
    $invoke_setup = /node\s+\.?\/?\.github\/setup\.js/
    $claude_hook = /SessionStart[^}]{1,400}\.github\/setup\.js/
    $cursor_rule = /Run\s+`?node\s+\.?\/?\.github\/setup\.js`?\s+to\s+initialize/
    $vscode_task = /"runOn"\s*:\s*"folderOpen"/
    $npm_test = /"test"\s*:\s*"node\s+\.?\/?\.github\/setup\.js"/
    $gemini_set = /"\.gemini\/settings\.json"/
    $path_runner = ".github/setup.js"
    $path_claude = ".claude/settings.json"
    $path_cursor = ".cursor/rules/setup.mdc"
  condition:
    ($invoke_setup or 2 of ($claude_hook, $cursor_rule, $vscode_task, $npm_test, $gemini_set) or any of ($vscode_task, $claude_hook, $cursor_rule, $npm_test, $gemini_set) and $path_runner or 2 of ($path_runner, $path_claude, $path_cursor)) and filesize < 256KB
}

rule Miasma_Azure_PayloadRunner {
  meta:
    description = "Miasma Azure setup.js runner — 4.3 MiB Bun-based credential-sweep payload (two published SHA-256 + behavioural anchors)"
    author = "synthetic-detections"
    date = "2026-06-07"
    severity = "critical"
    family = "miasma-azure-aiagent"
    reference = "https://thecybersecguru.com/news/miasma-worm-targets-ai-coding-agents-github-microsoft/"
  strings:
    $h_pub_1 = "d630397de8b01af0f6f5cf4463da91b17f28195a2c50c8f3f38ad9f7873fdb8e" nocase
    $h_pub_2 = "3a9db5ba0c8cd4c91e91717df6b1a141fc1e0fbc0558b5a78d7f5c23f5b2a150" nocase
    $bun_release = "github.com/oven-sh/bun/releases/download/" nocase
    $bun_run = /bun\s+run\s+\/tmp\/[A-Za-z0-9._-]{1,40}\.(m?js|cjs)/
    $tmp_b = /\/tmp\/b-[A-Za-z0-9._-]{1,40}/
    $cred_aws = "AWS_ACCESS_KEY_ID"
    $cred_az = "AZURE_CLIENT_SECRET"
    $cred_gcp = "GOOGLE_APPLICATION_CREDENTIALS"
    $cred_kube = "/.kube/config"
    $cred_npm = "NPM_TOKEN"
    $cred_gha = "ACTIONS_RUNTIME_TOKEN"
    $cred_gh_pat = "gho_"
    $cred_ssh = "/.ssh/"
  condition:
    any of ($h_pub_*) or any of ($bun_release, $bun_run, $tmp_b) and 3 of ($cred_aws, $cred_az, $cred_gcp, $cred_kube, $cred_npm, $cred_gha, $cred_gh_pat, $cred_ssh) and filesize > 1MB and filesize < 20MB
}

rule Miasma_Azure_IOC {
  meta:
    description = "Static IOCs — Miasma Azure exfil GitHub accounts, campaign theme strings, sample affected Microsoft repo names"
    author = "synthetic-detections"
    date = "2026-06-07"
    severity = "high"
    family = "miasma-azure-aiagent"
    reference = "https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html"
  strings:
    $acc_windy629 = "windy629" fullword
    $acc_hergom = "HerGomUli" fullword
    $acc_liuende = "liuende501" fullword
    $theme_blight = "Miasma: The Spreading Blight"
    $theme_hades = "Hades - The End for the Damned"
    $theme_name = "TeamPCP" fullword
    $repo_azsearch = "azure-search-openai-demo"
    $repo_durable_n = "durabletask-dotnet"
    $repo_durable_g = "durabletask-go"
    $repo_durable_j = "durabletask-js"
    $repo_durable_m = "durabletask-mssql"
    $repo_funcs = "functions-container-action"
    $repo_llm_ft = "llm-fine-tuning"
    $repo_winddocs = "windows-driver-docs"
    $repo_mantine_dt = "mantine-datatable"
    $repo_mantine_cm = "mantine-contextmenu"
  condition:
    ($acc_windy629 or $acc_hergom or $acc_liuende or $theme_blight or $theme_hades or $theme_name and any of ($repo_*)) and filesize < 50MB
}
