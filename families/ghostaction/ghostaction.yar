/*
   GhostAction — GitHub Actions credential-theft campaign (October 2026 wave)
   --------------------------------------------------------------------------
   Compromised maintainer accounts push malicious `security-audit.yml`
   workflows into GitHub repositories. The workflow triggers on
   `pull_request_target` (runs in the privileged base-repo context),
   extracts repository secrets and GITHUB_TOKEN, and exfiltrates them
   via curl POST to attacker C2 infrastructure.

   October 2026 wave: 30,000+ repos affected, 3,325 secrets confirmed
   stolen (cloud credentials, AI API keys, CI/CD tokens). Active since
   at least 2026-10-08.

   Static artifacts:
     - C2 IPs: 193.32.204.199 (October 2026 wave), 45.139.104.115 (2025 wave)
     - Malicious workflow filename: security-audit.yml
     - Trigger: pull_request_target (privileged context)
     - Exfil: curl POST of GITHUB_TOKEN + secrets to C2
     - Affected orgs should rotate all secrets exposed since 2026-10-08.

   Rule 1 — Behavioral: GitHub Actions workflow using pull_request_target
            that accesses secrets and exfiltrates via curl to external host.
   Rule 2 — IOC: C2 IP addresses and campaign-specific identifiers.
   Rule 3 — Structural: workflow YAML with the security-audit naming
            pattern + privileged trigger + secret access + HTTP exfil shape.

   Sources:
     https://www.stepsecurity.io/blog/ghostaction-returns
     https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/
*/

rule GhostAction_Workflow_Behavior : behavioral supply_chain
{
    meta:
        description = "GitHub Actions workflow using pull_request_target with secret exfiltration via curl — GhostAction campaign pattern"
        author      = "synthetic-detections"
        date        = "2026-10-21"
        severity    = "critical"
        family      = "ghostaction"
        reference   = "https://www.stepsecurity.io/blog/ghostaction-returns"
    strings:
        $trigger   = "pull_request_target"
        $secrets_a = /secrets\.[A-Z_]{2,40}/
        $secrets_b = "GITHUB_TOKEN"
        $secrets_c = "${{ secrets."
        $curl_post = /curl\s+[^\n]{0,120}-X\s*POST/
        $curl_data = /curl\s+[^\n]{0,120}(-d\s|--data)/
        $wget_post = /wget\s+[^\n]{0,120}--post/
        $c2_oct26  = "193.32.204.199" ascii wide
        $c2_2025   = "45.139.104.115" ascii wide
    condition:
        $trigger
        and any of ($secrets_a, $secrets_b, $secrets_c)
        and (any of ($curl_post, $curl_data, $wget_post) or any of ($c2_oct26, $c2_2025))
        and filesize < 1MB
}

rule GhostAction_IOC : ioc
{
    meta:
        description = "GhostAction campaign IOCs — C2 IP addresses from the October 2026 and 2025 waves"
        author      = "synthetic-detections"
        date        = "2026-10-21"
        severity    = "high"
        family      = "ghostaction"
        reference   = "https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/"
    strings:
        $c2_oct26 = "193.32.204.199" ascii wide
        $c2_2025  = "45.139.104.115" ascii wide
        $wf_name  = "security-audit.yml" nocase
        $campaign = "GhostAction" nocase
    condition:
        any of ($c2_oct26, $c2_2025) or ($wf_name and ($campaign or any of ($c2_oct26, $c2_2025)) and filesize < 50MB)
}

rule GhostAction_Workflow_Structure : supply_chain
{
    meta:
        description = "Workflow YAML with security-audit naming, pull_request_target trigger, secret access, and HTTP POST exfiltration — structural match for GhostAction campaign variants"
        author      = "synthetic-detections"
        date        = "2026-10-21"
        severity    = "critical"
        family      = "ghostaction"
        reference   = "https://www.stepsecurity.io/blog/ghostaction-returns"
    strings:
        $name_a  = "security-audit" nocase
        $name_b  = "security_audit" nocase
        $trigger = "pull_request_target"
        $tok_a   = "GITHUB_TOKEN"
        $tok_b   = "${{ secrets."
        $exfil_a = /curl\s[^\n]{0,200}(193\.32\.204\.199|45\.139\.104\.115)/
        $exfil_b = /curl\s+[^\n]{0,120}-X\s*POST\s+[^\n]{0,120}\$\{\{/
        $runs_on = "runs-on:"
    condition:
        any of ($name_a, $name_b)
        and $trigger
        and any of ($tok_a, $tok_b)
        and any of ($exfil_a, $exfil_b)
        and $runs_on
        and filesize < 1MB
}
