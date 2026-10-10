# ahsaycbs-xmrig — test results

Family: AhsayCBS exploitation -> XMRig cryptominer
Disclosed: 2026-10-08 (Huntress). Rules authored: 2026-10-10.

## Rules

| Rule | Type | Severity |
|------|------|----------|
| AhsayCBS_XMRig_Behavioral | behavioral (service persistence, watchdog, pool config, staging) | critical |
| AhsayCBS_XMRig_IOC | IOC (pool user, staging domain, attacker IPs) | high |
| AhsayCBS_XMRig_Specimen | specimen pin (SHA-256 hashes of 3 known samples) | critical |

## Local smoke test (yara 4.5.2)

Compiles clean (`yara -w ahsaycbs-xmrig.yar`).

Specimens (mock reconstructions from public reporting — inert):

| Specimen | Behavioral | IOC | Specimen |
|----------|------------|-----|----------|
| mock-watchdog-loader.ps1 | match | match | — |
| mock-ioc-report.txt | match | match | — |
| mock-miner-config.json | match | match | — |

Specimen-pin rule fires only on exact SHA-256 hash; mock files are not the
real samples so the Specimen column shows "—" as expected.

Benign controls (must NOT match) — all clean:

| Benign | Result | Purpose |
|--------|--------|---------|
| legit-edge-update-service.txt | no match | legitimate Edge update service (name differs) |
| legit-service-restart.ps1 | no match | admin script using Stop/Start-Service without campaign service name |
| legit-xmrig-config.json | no match | generic XMRig config pointing to different pool/user |

## FP-avoidance notes

The behavioral rule anchors on campaign-specific artifacts rather than generic
XMRig or service-management strings. Key FP boundaries:

- The service name "MicrosoftEdgeUpdateSvc" (with Svc suffix) is distinct from
  the legitimate "MicrosoftEdgeUpdate" service.
- Kryptex pool matching requires co-occurrence with the campaign pool user
  (krxYMRN97D) — a generic Kryptex connection alone does not match.
- PowerShell watchdog path (taskmgr killing + service control) requires the
  campaign service name to avoid flagging legitimate admin scripts.
- The staging domain (imagefiles-backup.oss-ap-southeast-7.aliyuncs.com) is
  campaign-specific infrastructure, not a generic Alibaba Cloud bucket.
- IOC rule: attacker IPs require 2+ co-occurring or a campaign anchor to avoid
  false positives from shared hosting / Tor exit nodes.

## Corpus FP test

| Rule                       |  Slice | Hits | Verdict |
|----------------------------|-------:|-----:|---------|
| AhsayCBS_XMRig_Behavioral | 10,980 |    0 | Clean   |
| AhsayCBS_XMRig_IOC        | 10,774 |    0 | Clean   |
