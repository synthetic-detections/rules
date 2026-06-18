# Axios SILKBELL/WAVESHAPER — YARA test results

**Date:** 2026-06-18
**Engine:** YARA 4.5.2
**Family:** axios-silkbell-rat

## Rules

| # | Rule | Severity | Target |
|---|---|---|---|
| 1 | Axios_SILKBELL_Dropper | critical | setup.js with OrDeR_7077 XOR, platform POST bodies, phantom dep |
| 2 | Axios_WAVESHAPER_RAT | critical | MicrosoftUpdate/com.apple.act.mond persistence, beacon protocol |
| 3 | Axios_SILKBELL_IOC | high | C2 infra, hashes, accounts, Sapphire Sleet pivots |

## Specimen results (should match)

| Specimen | Rule 1 | Rule 2 | Rule 3 |
|---|---|---|---|
| mock-silkbell-dropper.js | **HIT** | — | **HIT** |
| mock-waveshaper-win-rat.ps1 | — | **HIT** | **HIT** |
| mock-ioc-report.txt | **HIT** | **HIT** | **HIT** |

## Benign results (should NOT match)

| File | Rule 1 | Rule 2 | Rule 3 |
|---|---|---|---|
| legit-axios-usage.js | — | — | — |
| legit-powershell-persistence.ps1 | — | — | — |

## Cross-family separation (vs easydayjs-mastra-rat)

| easydayjs rules vs axios specimens | Result |
|---|---|
| mock-silkbell-dropper.js | clean |
| mock-waveshaper-win-rat.ps1 | clean |
| mock-ioc-report.txt | clean |

| axios rules vs easydayjs specimens | Result |
|---|---|
| mock-setup-cjs-dropper.js | clean |
| mock-protocal-cjs-rat.js | clean |
| mock-ioc-report.txt | clean |

Clean separation despite shared tradecraft (identical User-Agent, same hosting provider, same attack pattern). Each family's rules require family-specific artifacts alongside shared indicators.

## Tradecraft comparison: Axios (2026-03-31) vs easy-day-js (2026-06-17)

| Dimension | Axios / SILKBELL | easy-day-js / Mastra |
|---|---|---|
| Target | axios (70M weekly DL) | @mastra scope (4M monthly) |
| Entry | Hijacked maintainer token | Hijacked contributor scope |
| Phantom dep | plain-crypto-js@4.2.1 | easy-day-js@1.11.22 |
| Dropper | setup.js | setup.cjs |
| Obfuscation | XOR "OrDeR_7077"+333, Base64, reverse | Custom-alphabet Base64, 40-elem rotation, checksum 0x4c11d |
| Name encoding | — | XOR 0x80 byte sequence in .pkg_logs |
| C2 hosting | Hostwinds (142.11.206[.]73) | Hostwinds (23.254.164[.]92, .123) |
| C2 port | 8000 | 8000 |
| Campaign ID | /6202033 | /49890878 |
| User-Agent | mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0) | **identical** |
| TLS disable | NODE_TLS_REJECT_UNAUTHORIZED=0 | **identical** |
| Self-delete | fs.rmSync | **identical** |
| Win persist | MicrosoftUpdate Run key, wt.exe | NvmProtocal Run key, NodePackages |
| macOS persist | com.apple.act.mond, macWebT | com.nvm.protocal.plist, Library/NodePackages |
| Linux persist | /tmp/ld.py | nvmconf.service, .config/systemd |
| Payload type | Cross-platform RAT (WAVESHAPER) | Cross-platform RAT + crypto stealer |
| Beacon | JSON→Base64, 60s interval | ICAP-style, 10min interval |
| Crypto theft | Not primary | 166 wallet extensions |
| Attribution | Sapphire Sleet (Microsoft confirmed) | Sapphire Sleet (tradecraft overlap, unconfirmed) |

**Shared signatures (actor-level):** User-Agent string, Hostwinds hosting, port 8000 dropper, postinstall hook pattern, TLS disable, self-delete, cross-platform RAT architecture.

**Evolved between campaigns:** obfuscation scheme (XOR→custom Base64), persistence naming convention (Microsoft-themed → Node-themed), beacon protocol and interval, crypto-wallet targeting added.

## Caveats

- No real malware samples for either family — rules validated against synthetic specimens from vendor analyses.
- Axios attribution is confirmed (Microsoft + GTIG). easy-day-js attribution is tradecraft overlap only.
- Campaign IDs (6202033, 49890878) are operation-specific and will rotate.
- The "nrwise" string in the IOC rule may generate FP in contexts where that's a common username — low risk given the 50MB filesize cap and any-of condition.
