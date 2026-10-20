# Heartbreaker macOS ransomware — YARA test results

Family: heartbreaker-macos-ransomware
Rules: heartbreaker-macos-ransomware.yar (3 rules)
Date: 2026-10-20

## Source

Patrick Wardle, Objective-See, blog_0x8A (2026-10-18).
https://objective-see.org/blog/blog_0x8A.html

## Environment

- YARA 4.5.x, Linux x86_64
- Rules import `hash` module

## Compile check

Clean — no warnings, no errors.

## Specimen tests

| File | Heartbreaker_Behavioral | Heartbreaker_IOC | Heartbreaker_Specimen |
|------|-------------------------|------------------|-----------------------|
| heartbreaker-ransom-note.txt | MATCH | MATCH | n/a (text, not binary) |
| heartbreaker-plist.xml | no match | no match | n/a |

Behavioral fires on the combination of metamorphic markers + encryption indicators + persistence artefacts. IOC fires on >= 3 unique family strings. Specimen rule requires the actual Mach-O binary hash.

## Benign tests

| File | Heartbreaker_Behavioral | Heartbreaker_IOC | Heartbreaker_Specimen |
|------|-------------------------|------------------|-----------------------|
| legitimate-rust-app.txt | no match | no match | n/a |
| generic-plist.xml | no match | no match | n/a |

Zero false positives on structurally similar benign samples.

## Corpus FP test

Corpus FP scan pending.
