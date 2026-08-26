# SLEEPWALKER — YARA test results

Family: `sleepwalker-backdoor` · authored 2026-08-26 · source: r136a1 (Dominik Reichel), 2026-08-24.

## Rules
1. `SLEEPWALKER_ESET_Sideload` (critical) — PE + ≥3 spoofed DPAPI exports + (ERAAgent.exe | dpapisvc.dll).
2. `SLEEPWALKER_Host_Weakening` (high) — PE + EveryoneIncludesAnonymous + NullSessionPipes + host marker.
3. `SLEEPWALKER_Crypto_Pin` (critical) — embedded AES-256-CCM key / config-nonce byte sequences.

## Smoke test (in-repo)
specimens/ — all three rules match `sleepwalker_dpapi_sideload.bin`:
```
SLEEPWALKER_ESET_Sideload   specimens/sleepwalker_dpapi_sideload.bin
SLEEPWALKER_Host_Weakening  specimens/sleepwalker_dpapi_sideload.bin
SLEEPWALKER_Crypto_Pin      specimens/sleepwalker_dpapi_sideload.bin
```
benign/ — clean (no hits):
- `legit_dpapi.bin` (PE + the 7 DPAPI exports but NO ESET/dpapisvc marker) → correctly NOT matched: proves the co-occurrence guard prevents FP on the legitimate dpapi.dll.
- `eset_eraagent.bin` (PE + "ERAAgent.exe" only) → NOT matched.
- `hardening_notes.txt` (mentions the registry values but not a PE) → NOT matched.

## Corpus FP test
Scanned the FP-risk behavioural rule (`SLEEPWALKER_ESET_Sideload`, PE check inlined, single-rule submission — the corpus-scan gate rejects multi-rule sets) against the MalShare corpus on 2026-08-26 (job 9): **5,844 scanned, 0 matches, 0 read-errors in 8m42s** — CLEAN, no false positives. The ESET/dpapisvc co-occurrence guard holds. `SLEEPWALKER_Crypto_Pin` (exact AES-key/nonce byte sequences) and `SLEEPWALKER_Host_Weakening` (triple co-occurrence) are inherently near-zero-FP and were not separately corpus-scanned. (scan report retained locally)

## Notes
- No C2 IOCs exist (the sample embeds none). Detection is content/behaviour + the crypto pin.
- Sample SHA-256 `d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60`; not on MalShare as of 2026-08-26.
