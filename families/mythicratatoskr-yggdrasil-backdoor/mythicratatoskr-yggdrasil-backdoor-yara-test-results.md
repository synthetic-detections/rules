# MythicRatatoskr YARA Test Results

**Date:** 2026-10-23
**YARA version:** 4.5.2 (classic), Linux x86_64
**Rule file:** `mythicratatoskr-yggdrasil-backdoor.yar`

## Source

ESET LABScon 2026: [MythicRatatoskr](https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration/)

## Specimens

| File | Expected Rule | Result |
|---|---|---|
| `specimens/specimen-agent.bin` | Sandworm_MythicRatatoskr_Agent | **MATCH** |
| `specimens/specimen-iocs.bin` | Sandworm_MythicRatatoskr_IOCs | **MATCH** |
| `specimens/specimen-socks5.bin` | Sandworm_MythicRatatoskr_SOCKS5 | **MATCH** |
| `specimens/specimen-socks5.bin` | Sandworm_MythicRatatoskr_Agent | **MATCH** (expected — shares function names) |
| `benign/benign-go-service.bin` | (none) | **NO MATCH** |
| `benign/benign-random.bin` | (none) | **NO MATCH** |

## Why benign cases don't false-positive

- **benign-go-service.bin**: Contains `runService` and `saveConfig` (generic Go names) but lacks the PSK, check-in UUID, backdoor commands, and Yggdrasil indicators. The Agent rule requires either the AES PSK or UUID combined with 2+ function names, or 4+ function names combined with a command string — two generic names alone don't trigger.
- **benign-random.bin**: No ASCII strings at all.

## Caveats

- All specimens are synthetic (embedded strings in flat binaries). Real samples are Go ELF/PE binaries; string layout may differ but Go binaries preserve function names and string literals.
- Only SHA-1 hashes published by ESET; SHA-256 hashes not available for `hash =` metadata pinning.
- The SOCKS5 specimen also triggers the Agent rule because it shares debug strings and function names — this is intentional and correct for the real tool.
- RC4 key and C2 IPv6 address are campaign-specific; the IOC rule will go stale when infrastructure rotates, but the Agent rule's function-name anchors survive.

## Corpus FP test

| Samples scanned | Hits | Duration | Verdict |
|---|---|---|---|
| 6,648 | 0 | 9m58s | **CLEAN** |

Scan job 37, 2026-10-23. Agent rule only (scanner gate requires single-rule submission). Zero false positives.
