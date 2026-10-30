# BLOODALCHEMY / VAPOR PANDA — YARA test results

**Family:** bloodalchemy-vapor-panda
**Rules:** 3 (Behaviour / IOC / Specimen)
**Date:** 2026-10-30
**Source:** CrowdStrike — "VAPOR PANDA Uses AI-Driven ARTEX to Scale Global Espionage Campaign" (2026-10-29)

## Environment

- YARA 4.5.x, Debian bookworm amd64
- yara-linter applied (--align --multiline --brace-newline --explicit-parens)

## Source artifacts

CrowdStrike published 3 SHA-256 hashes, 3 C2 domains with resolved IPs,
the GameHook DLL sideloading triad file names, and the internal dev path
`D:\ProjectX\Merman_New\`. Rules cover all disclosed static indicators.

**Published hashes:**
- `49fe7041...` — renamed GameHook binary (svchost.exe)
- `3fb5a9fb...` — graphics-hook-filter64.dll (loader)
- `36425183...` — graphics-hook_config.bin (encrypted payload)

## Compile check

```
yara -w bloodalchemy-vapor-panda.yar /dev/null → OK (no warnings)
```

## Specimen test

| File | Rule hits |
|---|---|
| bloodalchemy-loader-sim.bin | Behaviour, IOC |
| bloodalchemy-c2-sim.bin | IOC |

Behaviour rule fires on the loader specimen (GameHook triad + Merman_New
path + C2 domains). IOC rule fires on both specimens (C2 domain co-occurrence).
Specimen-pin rule not testable without real samples (hash-pinned).

## Benign test

| File | Rule hits |
|---|---|
| legit-gamehook-obs.bin | (none) |
| legit-db-client.bin | (none) |

No false positives. The benign GameHook file (graphics-hook-filter64.dll
alone without config or dev path) does not trigger Behaviour. Partial domain
overlap (mysql.com, sqlite.org) does not trigger IOC.

## Corpus FP test

| Rule | Samples | Hits | Verdict |
|---|---|---|---|
| BloodAlchemy_VaporPanda_Behaviour | 10,510 | 0 | CLEAN |
| BloodAlchemy_VaporPanda_IOC | — | — | pending |
| BloodAlchemy_VaporPanda_Specimen | — | — | pending |
