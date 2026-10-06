# ClingSTUN IoT Backdoor — YARA Test Results

**Date:** 2026-10-06
**Rules file:** `clingstun-iot-backdoor.yar`
**Rules:** 3 (ClingSTUN_Backdoor_Behavior, ClingSTUN_IOC_Infrastructure, ClingSTUN_Specimen_Pin)

## Rule compilation

All three rules compile cleanly with `yara` 4.5.x. `import "hash"` required for specimen pin rule.

## Specimen test

No specimens available in public repositories at time of writing (MalwareBazaar returned 401, MalShare had no matching hashes). Download server URLs submitted to MalShare for server-side retrieval; servers appear offline (published 2026-10-05, likely already rotated).

21 SHA-256 hashes pinned from Fortinet report. Specimen pin rule will match if/when samples become publicly available.

## Benign test

| File | Expected | Result |
|---|---|---|
| `benign/legitimate_stun_client.bin` | clean | clean |

Benign ELF with partial STUN strings (Google STUN IP, `/dev/watchdog`, STUN magic bytes) correctly does NOT trigger. The behavioral rule requires co-occurrence of ClingSTUN-specific artifacts (`.cling` paths + infection tags + persistence targets), preventing false positives on legitimate STUN clients.

## Corpus FP test

| Rule | Corpus size | Hits | Verdict |
|---|---|---|---|
| ClingSTUN_Backdoor_Behavior | 5,963 | 0 | CLEAN |

Zero false positives. Co-occurrence guards (`.cling` paths + infection tags + persistence targets) are sufficiently specific to avoid triggering on legitimate ELF binaries.

## Coverage assessment

| Rule | Detection class | Confidence |
|---|---|---|
| ClingSTUN_Backdoor_Behavior | Behavioral: persistence paths, infection tags, UA string, proc hiding | High — 4 independent co-occurrence groups |
| ClingSTUN_IOC_Infrastructure | IOC: 24 STUN IPs + 6 download servers + exploit paths | High — operator STUN server is unique; 4+ STUN co-occurrence threshold |
| ClingSTUN_Specimen_Pin | Hash: 21 SHA-256 from Fortinet report | Critical — exact match |

## Suricata rules

7 rules in `clingstun-iot-backdoor.rules`:
- Operator STUN server contact (critical)
- Anomalous zero-length STUN binding request with threshold (high)
- Spoofed Google STUN response (critical)
- HTTP with `clingwashere` User-Agent (critical)
- Realtek SDK exploit POST /picsdesc.xml (high)
- Known staging server contact (critical)
- Mutex port 33957 (medium)

## Notes

- ClingSTUN was disclosed 2026-10-05 by FortiGuard Labs (Vincent Li). The campaign ran in three waves with different download servers.
- Self-propagation uses 7 hardcoded exploits (CVE-2014-8361, CVE-2016-20016, CVE-2021-35394, CVE-2023-26801, CVE-2023-41011, CVE-2024-3721, CVE-2025-34037).
- The STUN-based C2 is the distinctive feature: commands embedded in STUN transaction ID field, spoofed to appear as Google STUN responses.
- Multi-arch: ARM, x86, x86-64, MIPS, PowerPC variants exist.
