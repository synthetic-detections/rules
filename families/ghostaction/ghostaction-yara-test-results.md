# ghostaction — YARA test results

Family: GhostAction GitHub Actions credential-theft campaign.
Compromised maintainer accounts push malicious `security-audit.yml` workflows;
exfil via curl POST to C2. 30k+ repos, 3,325 secrets stolen (October 2026 wave).
Rules authored: 2026-10-21.

## Rules

| Rule | Type | Severity |
|------|------|----------|
| GhostAction_Workflow_Behavior | behavioral (pull_request_target + secret exfil via curl) | critical |
| GhostAction_IOC | IOC (C2 IPs from October 2026 and 2025 waves) | high |
| GhostAction_Workflow_Structure | structural (security-audit naming + privileged trigger + secret access + C2 POST) | critical |

## Local smoke test (yara 4.5.2)

Compiles clean (`yara -w ghostaction.yar`).

Specimens (mock reconstructions from public reporting — inert):

| Specimen | Behavior | IOC | Structure |
|----------|----------|-----|-----------|
| mock-malicious-workflow.yml | match | match | match |
| mock-ioc-report.txt | match | match | — |
| mock-2025-wave-workflow.yml | match | match | match |

Benign controls (must NOT match) — both clean:

| Benign | Result | Purpose |
|--------|--------|---------|
| legit-security-scan.yml | no match | CodeQL analysis workflow using pull_request (not pull_request_target) |
| legit-pr-target-workflow.yml | no match | legitimate pull_request_target labeler — uses secrets.GITHUB_TOKEN but no curl/exfil |

## FP-avoidance notes

`pull_request_target` is used by legitimate labeler, auto-merge, and triage
workflows. The behavioral rule requires the co-occurrence of secret access
AND an exfil vector (curl POST or C2 IP). A legitimate workflow that reads
`secrets.GITHUB_TOKEN` for PR labeling but does not curl it anywhere will
not match. The structural rule further gates on the `security-audit` naming
pattern, making false positives on normal CI workflows very unlikely.

## Corpus FP test

PENDING — submit via detached scan.
