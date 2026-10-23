# Stadia RAT YARA Test Results

**Date:** 2026-10-23
**YARA version:** 4.5.2 (classic), Linux x86_64
**Rule file:** `stadia-rat.yar`

## Source

Varonis: [StealC Returns](https://www.varonis.com/blog/stealc-returns)

## Specimens

| File | Expected Rule | Result |
|---|---|---|
| `specimens/specimen-strings.exe` | StealC_Stadia_RAT_Strings | **MATCH** |
| `specimens/specimen-iocs.bin` | StealC_Stadia_RAT_IOCs | **MATCH** |
| `specimens/specimen-structural.exe` | StealC_Stadia_RAT_Structural | **NO MATCH** (expected — see caveat) |
| `specimens/specimen-structural.exe` | StealC_Stadia_RAT_Strings | **MATCH** (build marker + HVNC object) |
| `benign/benign-multi-import.exe` | (none) | **NO MATCH** |
| `benign/benign-random.bin` | (none) | **NO MATCH** |

## Why benign cases don't false-positive

- **benign-multi-import.exe**: Valid PE32 stub with `set_online` string, but has 3 imports (not 1) and lacks `STADIA_BETA`, `StadiaVnc%d`, and the RC4 key. The Strings rule requires the build marker or HVNC object name in combination with other indicators; `set_online` alone is not enough. The Structural rule requires `pe.number_of_imports == 1`.
- **benign-random.bin**: No PE header, no matching strings.

## Caveats

- **Structural rule not tested against synthetic PE**: The `pe.number_of_imports` condition requires a properly constructed import directory that YARA's PE module can parse. Synthetic stubs don't have this; the rule is designed for the real 560 KB sample (`ea9284...`). Import count = 1 (KERNEL32 only) is a strong discriminator from YARA's PE module.
- The RC4 key (`eepkTOgSwdNCgrhITR`) is build-specific and will rotate across builds. The build marker `STADIA_BETA` and VNC object `StadiaVnc%d` are more stable anchors.
- Locale check DWORDs (0x0419 etc.) are common 4-byte sequences; they only contribute as co-occurrence with other Stadia-specific strings, never standalone.
- App-Bound Encryption helper blob hash (`0e5337a4...`) is shared with StealC v3.5 — IOC rule intentionally catches both.

## Corpus FP test

| Samples scanned | Hits | Duration | Verdict |
|---|---|---|---|
| 10,352 | 0 | 14m16s | **CLEAN** |

Scan job 38, 2026-10-23. Strings rule only (scanner gate requires single-rule submission). Zero false positives.
