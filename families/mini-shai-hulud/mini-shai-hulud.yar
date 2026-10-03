/*
   Mini Shai-Hulud — core worm payload (cross-variant)
   ---------------------------------------------------
   TeamPCP (UNC6780 / Storm-2999 / Altered Spider) supply-chain worm,
   first seen 2026-05-11. Open-sourced by the actor under MIT licence on
   2026-05-12. Has spawned multiple delivery variants: npm preinstall
   (original wave, 400+ packages), Miasma/RedHat-Cloud-Services, Phantom
   Gyp (binding.gyp), AI-agent workspace configs (Azure/durabletask), and
   GitHub Actions (actions-cool/issues-helper, maintain-one-comment).

   This rule set targets the CORE payload artefacts that are shared across
   ALL delivery variants: hardcoded string constants, encryption salt,
   persistence service names, dead-man's-switch marker, and the credential-
   sweep/exfil infrastructure fingerprints.

   Siblings: [[miasma-redhat-npm]], [[miasma-azure-aiagent]],
             [[miasma-v2-phantom-gyp]]

   Sources:
     https://www.bleepingcomputer.com/news/security/github-actions-re-enabled-with-mini-shai-hulud-payload-still-active/
     https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
     https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/
     https://hivesecurity.gitlab.io/blog/shai-hulud-github-actions-supply-chain-attack/
     FBI FLASH-20260702-01 (TLP:CLEAR)
*/

rule MiniShaiHulud_CorePayload {
    meta:
        description = "Mini Shai-Hulud core payload — hardcoded strings shared across all delivery variants (npm, GitHub Actions, AI-agent configs)"
        author = "synthetic-detections"
        date = "2026-09-27"
        severity = "critical"
        family = "mini-shai-hulud"
        reference = "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/"
    strings:
        $salt = "svksjrhjkcejg"
        $deadman = "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"
        $c2_keyword = "FIRESCALE" fullword
        $repo_marker = "Shai-Hulud: Here We Go Again"
        $pypi_marker = "PUSH UR T3MPRR"
        $commit_email = "claude@users.noreply.github.com"
        $deaddrop_a = "RevokeAndItGoesKaboom"
        $deaddrop_b = "TheBeautifulSandsOfTime"
        $svc_gh_mon = "gh-token-monitor.service"
        $svc_pg_mon = "pgsql-monitor.service"
        $payload_router = "router_init.js"
        $payload_hangup = "hangup.wav"
        $payload_ring = "ringtone.wav"
        $payload_sysmon = "sysmon.py"
        $cred_aws = "AWS_ACCESS_KEY_ID"
        $cred_gha = "ACTIONS_RUNTIME_TOKEN"
        $cred_vault = "VAULT_TOKEN"
        $cred_kube = "/.kube/config"
        $cred_ssh = "/.ssh/"
    condition:
        ($salt or $deadman or $c2_keyword or $repo_marker or $pypi_marker or 2 of ($commit_email, $deaddrop_a, $deaddrop_b, $svc_gh_mon, $svc_pg_mon) or 2 of ($payload_router, $payload_hangup, $payload_ring, $payload_sysmon) and 2 of ($cred_aws, $cred_gha, $cred_vault, $cred_kube, $cred_ssh)) and filesize < 20MB
}

rule MiniShaiHulud_GitHubAction_IOC {
    meta:
        description = "Mini Shai-Hulud GitHub Actions delivery — actions-cool/issues-helper and maintain-one-comment hijack IOCs + exfil domain"
        author = "synthetic-detections"
        date = "2026-09-27"
        severity = "high"
        family = "mini-shai-hulud"
        reference = "https://www.bleepingcomputer.com/news/security/github-actions-re-enabled-with-mini-shai-hulud-payload-still-active/"
    strings:
        $action_ih = "actions-cool/issues-helper"
        $action_moc = "actions-cool/maintain-one-comment"
        $exfil_domain = "m-kosche.com"
        $exfil_sub = "t.m-kosche"
        $dev_claude = ".claude/settings.json"
        $dev_vscode = ".vscode/tasks.json"
        $dev_cursor = ".cursor/rules/"
        $theme_a = "Shai-Hulud"
        $theme_b = "TeamPCP" fullword
    condition:
        ($exfil_domain or $exfil_sub or $action_ih and $action_moc or any of ($action_ih, $action_moc) and any of ($theme_a, $theme_b) or any of ($action_ih, $action_moc) and 2 of ($dev_claude, $dev_vscode, $dev_cursor)) and filesize < 50MB
}

rule MiniShaiHulud_SpecimenPin {
    meta:
        description = "Mini Shai-Hulud specimen hash pin — FBI FLASH-20260702-01 published SHA-256 values for TeamPCP payloads"
        author = "synthetic-detections"
        date = "2026-09-27"
        severity = "critical"
        family = "mini-shai-hulud"
        reference = "FBI FLASH-20260702-01 (TLP:CLEAR)"
    strings:
        $h01 = "18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a" nocase
        $h02 = "c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926" nocase
        $h03 = "0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a" nocase
    condition:
        any of ($h*) and filesize < 50MB
}
