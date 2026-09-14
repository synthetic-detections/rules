# Midnight Blizzard GTG-20006 — YARA test results

Family: `midnight-blizzard-gtg20006`
Rule file: `midnight-blizzard-gtg20006.yar`
Author: synthetic-detections
Date: 2026-09-14
Disclosure: September 2026 (Anthropic threat intelligence report on GTG-20006 campaign)

## Rules

1. `MidnightBlizzard_GTG20006_Behavioural` (critical, behavioural) — Microsoft-impersonation
   C2 domain patterns (`ms365-*`, `m365-*`, `owa-ms365`, `stat(ic|istic)-ms.live`,
   `docs-viewer.org`, `wa-(connect|meeting)`) combined with campaign executable names
   (`msedgeupdate_v3.exe`, `WUEngine.exe`, etc.) or family strings. Also fires on 2+
   distinct C2 patterns or 2+ campaign executables without cross-correlation. The unique
   build-string `client_20260507093021_4286d211_x64.exe` fires standalone.

2. `MidnightBlizzard_GTG20006_IOC` (high) — static IOC sweep of all 10 C2 domains and
   7 C2 IPs with a co-occurrence guard: at least 2 indicators must match. Individual
   domains like `docs-viewer.org` or any single IP will not fire alone.

3. `MidnightBlizzard_GTG20006_Specimen` (critical, specimen-pin) — SHA-256 pins for the
   two known campaign sample hashes (`be998574...d8d42c`, `918fa52a...11c593`).

## Recorded hashes (IOC store)

SHA-256: `be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c`,
`918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593`.

## In-repo smoke test

Specimens (should match -- all pass):
- `specimens/gtg20006-config-fragment.bin` (synthetic config carrying C2 domains + exe
  names + IPs) -> `MidnightBlizzard_GTG20006_Behavioural` + `MidnightBlizzard_GTG20006_IOC` pass
- `specimens/gtg20006-ioc-list.txt` (IOC list with all campaign domains and IPs) ->
  `MidnightBlizzard_GTG20006_Behavioural` + `MidnightBlizzard_GTG20006_IOC` pass

Benign (structurally similar -- must NOT match, all clean):
- `benign/edge-update-readme.txt` -- mentions `msedgeupdate.exe` and legitimate Microsoft
  update domains but contains zero campaign C2 patterns; confirms the behavioural rule
  requires campaign-specific domain infrastructure, not just the executable name alone. No match.
- `benign/m365-admin-guide.txt` -- mentions `DiagHost.exe` and legitimate Microsoft 365
  admin domains (`admin.microsoft.com`, `teams.microsoft.com`) but contains zero campaign
  IOCs; confirms that legitimate M365 references do not trigger. No match.

Result: 2/2 specimens hit their intended rules (4 total hits across 2 rules); 0/2 benign
files matched.

## Known residual FP risk

`MidnightBlizzard_GTG20006_Behavioural` uses regex patterns like `ms365-[a-z]{2,10}\.(com|live)`
which could in theory match a legitimate domain registered in that pattern space. The
co-occurrence requirement (C2 pattern + executable name, or 2+ C2 patterns) substantially
reduces this risk. The standalone fire for `client_20260507093021_4286d211_x64.exe` is
campaign-unique due to the embedded build timestamp and hash.

`MidnightBlizzard_GTG20006_IOC` requires 2+ indicators, eliminating single-indicator FPs.
Domains like `docs-viewer.org` or IPs like `104.145.210.184` alone will not fire.

## Corpus FP test

Corpus FP scan pending.
