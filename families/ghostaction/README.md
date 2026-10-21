# ghostaction

GitHub Actions credential-theft campaign. Compromised maintainer accounts
push malicious `security-audit.yml` workflows that run on
`pull_request_target`, extract repository secrets and `GITHUB_TOKEN`, and
exfiltrate them via HTTP POST to attacker infrastructure.

**October 2026 wave:** 30,000+ repos affected, 3,325 secrets confirmed
exfiltrated. C2: `193.32.204[.]199`. An earlier 2025 wave used
`45.139.104[.]115`.

## Coverage

| Type | File | What it detects |
|------|------|-----------------|
| YARA | `ghostaction.yar` | Malicious workflow patterns (behavioral), C2 IOCs, structural workflow shape |
| Suricata | `ghostaction.rules` | HTTP POST to campaign C2 IPs; GITHUB_TOKEN exfiltration in POST body |

## Sources

- [StepSecurity — GhostAction Returns](https://www.stepsecurity.io/blog/ghostaction-returns)
- [GitGuardian — GhostAction Campaign: 3,325 Secrets Stolen](https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/)
