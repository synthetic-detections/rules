# daxin-stupig — test results

Family: Daxin (kernel rootkit) + Stupig (pre-login SYSTEM backdoor), Taiwan 2026.
Source: Symantec / Carbon Black Threat Hunter, reported 2026-07. Rules authored: 2026-07-23.

## Rules

| Rule | Type | Severity |
|------|------|----------|
| Daxin_Stupig_Behavior | behavioral (srt64.sys driver / Stupig logon backdoor) | critical |
| Daxin_Stupig_IOC | IOC (sample hashes via hash module + filenames) | high |
| Daxin_Stupig_Specimen | specimen pin (full Stupig shape) | critical |

## Local smoke test (yara 4.5.2)

Compiles clean (imports the `hash` module for exact-sample matching).

| Specimen | Behavior | IOC | Specimen |
|----------|----------|-----|----------|
| mock-stupig-loader.txt | match | match | match |
| mock-daxin-driver.txt | match | match | — |
| mock-ioc.txt | match | match | — |

Benign / structurally-similar (must NOT match): all clean.

| Benign file | Result |
|-------------|--------|
| legit-keyboard-layout.txt (kbdus.dll, Keyboard Layouts, winlogon, DosKeybCodes) | clean |
| legit-driver-inf.txt (System32\drivers, generic .sys names) | clean |

The hard FP shapes are covered: a legitimate keyboard-layout note (mentions winlogon +
Keyboard Layouts + DosKeybCodes but no `stupig`/`kbdus1`) and a generic driver note
(System32\drivers + .sys names but no `srt64.sys`). Neither matches.

## Design notes (FP control)

- The Stupig branch fires only when the campaign-unique `stupig` logon-trigger string
  co-occurs with the keyboard-layout-DLL/winlogon persistence shape — generic
  winlogon/Keyboard-Layout strings alone do not match.
- `srt64.sys` is the specific Daxin driver name; `kbdus1.dll` is the specific Stupig DLL.
- The IOC rule pins the two published SHA-256 samples exactly via the hash module, plus
  the distinctive-filename co-occurrence.

## Corpus FP test

Scope: recent family — any corpus hit is a candidate FP to investigate.

- Daxin_Stupig_Behavior: 1,763 samples scanned, 0 matches, 0 read-errors → clean
- Daxin_Stupig_IOC: not corpus-scanned — the hash-module clauses match only the two exact
  published samples; the filename co-occurrence (`kbdus1`+`stupig`, or `srt64.sys`) is a
  strict subset of the behavioral rule already under test.
- Daxin_Stupig_Specimen: not scanned — requires `stupig`+`kbdus1`+winlogon/keyboard-layout
  together; strictly tighter than the behavioral rule.
