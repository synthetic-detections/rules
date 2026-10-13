# Midnight Mimosa — YARA test results

**Date:** 2026-10-12
**Rule file:** `midnight-mimosa.yar`
**Source:** [Bitdefender Labs](https://www.bitdefender.com/en-us/blog/labs/midnight-mimosa-malware) (2026-10-08)

## Environment

- YARA 4.5
- Debian (Linux 6.12)

## Rules

| Rule | Type | Severity |
|---|---|---|
| MidnightMimosa_FirmwareBackdoor_Behavioral | Behavioural | critical |
| MidnightMimosa_IOC | IOC sweep | high |
| MidnightMimosa_Specimen | Specimen pin | critical |

## Compile check

```
yara -w midnight-mimosa.yar /dev/null
```

Result: **PASS** (no errors, no warnings)

## Specimen tests (should match)

| File | Expected rule(s) | Result |
|---|---|---|
| specimen-behavioral-a.bin | Behavioral, IOC | MATCH |
| specimen-behavioral-b.bin | Behavioral | MATCH |
| specimen-ioc-c2.bin | IOC | MATCH |
| specimen-ioc-pkgs.bin | IOC | MATCH |
| specimen-ioc-marker.bin | IOC | MATCH |
| specimen-ioc-dropper.bin | IOC | MATCH |
| specimen-ioc-framework.bin | IOC | MATCH |
| specimen-pin-dex.bin | Specimen, IOC | MATCH |
| specimen-pin-elf.bin | Specimen, IOC | MATCH |
| specimen-pin-apk.bin | Specimen, IOC | MATCH |

## Benign tests (should NOT match)

| File | Description | Result |
|---|---|---|
| benign-vending.bin | Legitimate vending/settings packages | SILENT |
| benign-single-pkg.bin | Single enabler-like package (no co-occurrence) | SILENT |
| benign-system.bin | Legitimate system packages and libraries | SILENT |
| benign-dex.bin | DEX with unrelated app content | SILENT |

## Corpus FP test

| Rule | Corpus slice | Hits | Verdict |
|------|-------------|------|---------|
| MidnightMimosa_FirmwareBackdoor_Behavioral | 6,461 files | 0 | CLEAN |
| MidnightMimosa_IOC | 10,803 files | 0 | CLEAN |
| MidnightMimosa_Specimen | 11,460 files | 0 | CLEAN |
