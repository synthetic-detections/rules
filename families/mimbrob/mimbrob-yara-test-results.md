# mimbrob — test results

Family: Mimbrob espionage campaign (FBULoader / RAT-Go / Dronner)
Disclosed: 2026-09-29 (F6). Rules authored: 2026-10-01.

## Rules

| Rule | Type | Severity |
|------|------|----------|
| Mimbrob_Behavioural | behavioral (DLL sideloading, RAT strings, C2 patterns) | critical |
| Mimbrob_IOC | IOC (C2 domains/IPs + phishing domains, >=2 co-occurrence) | high |
| Mimbrob_Specimen | hash pins (8 MD5) | critical |

## Local smoke test (yara 4.5.2)

Compiles clean (`yara -w mimbrob.yar /dev/null`). `import "hash"` required for Specimen rule.

Specimens (mock reconstructions from public reporting — inert):

| Specimen | Behavioural | IOC | Specimen |
|----------|-------------|-----|----------|
| fbuloader_sideload.bin | match | — | — |
| ratgo_loader.bin | match | — | — |
| dronner_stub.bin | match | — | — |
| c2_config.bin | — | match | — |

Benign controls (must NOT match) — all clean:

| Benign | Result | Purpose |
|--------|--------|---------|
| clean.txt | no match | generic text mentioning Yandex Browser |
| partial_browserdll.txt | no match | lone `browser.dll` without C2 domain must not trigger |
| ip_superstring.txt | no match | superstrings of C2 IPs must not trigger `fullword` |
| legit_tasks.txt | no match | legitimate scheduled-task names that share substrings |

## FP-avoidance notes

The Behavioural rule uses co-occurrence guards throughout:

- **FBULoader** fires only when a FBULoader-specific indicator (`Browser
  Update Checker`, the YaBrowser path, directory version, `/api/verify/`)
  co-occurs with the `yandex-update` C2 domain substring. Lone `browser.dll`
  does not trigger.

- **RAT-Go** requires any two of six RAT-Go indicators together. The
  standalone exception is the Russian debug placeholder string found in
  MSASN1.dll (`hex bytes`), which is highly campaign-specific.

- **Dronner** requires any two Dronner indicators, or the `ydx-stat` C2
  domain substring alongside a sideloading DLL name.

The IOC rule requires co-occurrence of at least two infrastructure tokens,
preventing single-domain false positives on unrelated `.ru` TLD strings.
The `fullword` modifier on C2 IP addresses prevents superstring matches.

## Corpus FP test

No automated corpus scan available at authoring time. The Behavioural
rule's co-occurrence guards and campaign-specific string anchors (Yandex
domain impersonation patterns, RAT-Go internal identifiers, Dronner
installer names) are sufficiently specific that false positives against
commodity malware are unlikely.

The IOC rule is infrastructure-pinned with co-occurrence. All eight C2 and
phishing domains are directly attributed to Mimbrob by F6.

The eight MD5 hashes in the Specimen rule are verified against the F6
report published 2026-09-29.
