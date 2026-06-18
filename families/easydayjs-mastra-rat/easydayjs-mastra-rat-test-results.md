# easy-day-js / Mastra npm RAT — YARA test results

**Date:** 2026-06-18
**Engine:** YARA 4.5.2
**Family:** easydayjs-mastra-rat

## Rules

| # | Rule | Severity | Target |
|---|---|---|---|
| 1 | EasyDayJS_Dropper_Behavior | critical | setup.cjs dropper with TLS disable + XOR marker + self-delete |
| 2 | EasyDayJS_RAT_Persistence | critical | Cross-platform RAT with protocal.cjs + NvmProtocal/LaunchAgent/systemd |
| 3 | EasyDayJS_IOC | high | C2 IPs, campaign ID, hijacked accounts, package coordinates |

## Specimen results (should match)

| Specimen | Rule 1 | Rule 2 | Rule 3 |
|---|---|---|---|
| mock-setup-cjs-dropper.js | **HIT** | — | — |
| mock-protocal-cjs-rat.js | — | **HIT** | **HIT** |
| mock-ioc-report.txt | — | **HIT** | **HIT** |

## Benign results (should NOT match)

| File | Rule 1 | Rule 2 | Rule 3 |
|---|---|---|---|
| legit-dayjs-usage.js | — | — | — |
| legit-mastra-package.json | — | — | — |
| legit-nvm-config.sh | — | — | — |

## Notes

- The IOC report triggers Rule 2 (RAT Persistence) because it contains persistence artifact names (NvmProtocal, com.nvm.protocal, nvmconf.service) alongside C2 indicators — correct behavior for an IOC sweep rule scanning incident reports.
- Benign dayjs usage, clean @mastra package.json, and legitimate nvm config all pass cleanly.
- Rule 1 uses the XOR-0x80 byte sequence `{E5 E1 F3 F9 AD E4 E1 F9 AD EA F3}` as a hex string match — this catches the encoded "easy-day-js" marker written to .pkg_logs even if the plaintext name never appears on disk.

## Companion family: axios-silkbell-rat

The Axios npm compromise (2026-03-31, Microsoft-confirmed Sapphire Sleet) shares extensive tradecraft with this campaign: identical User-Agent string, Hostwinds hosting, port 8000 dropper, postinstall hook pattern, TLS disable, self-delete, cross-platform RAT architecture. Cross-family testing confirms clean separation — neither family's rules fire on the other's specimens despite the shared indicators. Full tradecraft comparison in `axios-silkbell-rat-test-results.md`.

## Caveats

- No real malware samples available yet (easy-day-js was pulled from npm). Rules validated against synthetic specimens reconstructed from JFrog, Snyk, Phoenix Security, Orca, and Aikido analyses.
- The Sapphire Sleet / BlueNoroff attribution is tradecraft-overlap only, not confirmed. The IOC rule does not include BlueNoroff-specific indicators.
- Campaign ID "49890878" is specific to this operation; future operations from the same actor would likely rotate this value.
