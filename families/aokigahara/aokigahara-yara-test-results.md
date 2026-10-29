# Aokigahara — YARA test results

**Family:** aokigahara
**Date:** 2026-10-29
**Rule file:** `aokigahara.yar`

## Sources

- Dark Reading — Aokigahara targets developer keyrings & AI assistants: https://darkreading.com/endpoint-security/aokigahara-stealer-developer-keyrings-ai-assistants
- GridinSoft — Aokigahara AI sessions & developer keys: https://blog.gridinsoft.com/aokigahara-ai-sessions-developer-keys/
- Cyber Security News — New Aoki malware: https://cybersecuritynews.com/new-aoki-malware/

## Environment

- YARA 4.5.x, Linux x86_64
- Three rules: `Aokigahara_Behavior` (behavioral/critical), `Aokigahara_IOC` (ioc/high), `Aokigahara_Specimen` (specimen/critical)

## Compile check

```
$ yara -w aokigahara.yar /dev/null
(clean — no errors or warnings)
```

## Specimen tests

| File | Expected | Result |
|------|----------|--------|
| `aokigahara-behavior-specimen.bin` | Aokigahara_Behavior | MATCH |
| `aokigahara-ioc-specimen.bin` | Aokigahara_IOC | MATCH |

Both specimens contain a minimal MZ/PE header plus embedded strings matching the rule conditions. The behavioral specimen includes the `Aokigahara` family string, `aisessions` module marker, `/gate` C2 endpoint, and AI-assistant path strings (`.claude.json`, `ChatGPT`, `Cursor`). The IOC specimen contains C2 domains `dobeqnesmot.cc` and `hjazfioe.surf`.

## Benign tests

| File | Expected | Result |
|------|----------|--------|
| `legitimate-ai-tool.bin` | no match | CLEAN |

The benign file contains legitimate AI tool references (`ChatGPT`, `Cursor`, `config.toml`) without the module markers, C2 indicators, or family string — confirming the co-occurrence guards prevent false positives on software that merely references AI assistant names.

## Corpus FP test

Corpus FP scan pending.
