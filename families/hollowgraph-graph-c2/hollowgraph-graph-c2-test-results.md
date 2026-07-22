# hollowgraph-graph-c2 — test results

Family: HollowGraph — Microsoft 365 Graph / calendar covert C2 implant (Cavern component)
Reported: 2026-07-20 (Group-IB). Rules authored: 2026-07-22.

## Rules

| Rule | Type | Severity |
|------|------|----------|
| HollowGraph_GraphCalendar_C2_Behavior | behavioral (Graph calendar C2 + config + magic date) | critical |
| HollowGraph_IOC | IOC (logAzure.txt + 2050-05-13 date, guarded) | high |
| HollowGraph_Implant_Specimen | specimen pin (full implant shape) | critical |

## Local smoke test (yara 4.5.2)

Compiles clean, no short-atom warnings (bare `GET`/`RSA` 3-byte atoms were
removed — they are too short to scan and too generic to be signal).

Specimens (inert mock reconstructions from public reporting):

| Specimen | Behavior | IOC | Specimen |
|----------|----------|-----|----------|
| mock-hollowgraph-implant.cs | match | match | match |
| mock-ioc-report.txt | match | match | match |

Benign / structurally-similar (must NOT match): all clean.

| Benign file | Result |
|-------------|--------|
| legit-graph-calendar-app.cs (real Graph /me/events + /me/calendar + token auth) | clean |
| legit-crypto-helper.cs (AES-256-GCM + RSA + generic GET/SEND helpers) | clean |

The two hardest FP shapes are covered: a legitimate Microsoft Graph calendar
integration, and a generic AES-256-GCM/RSA crypto helper. Neither carries the
`logAzure.txt` config, the 2050-05-13 magic event date, or the
Graph-calendar + attachment + crypto + credential co-occurrence the rules need.

Note during authoring: the benign files initially self-matched because their
"must NOT match" comments literally named `logAzure.txt` and `2050`; the
comments were reworded so the benign corpus is genuinely artifact-free.

## Design notes (FP control)

- Microsoft Graph SDK strings (`graph.microsoft.com`, `/me/events`,
  `/me/calendar`) appear in countless legitimate apps, so no rule fires on
  Graph usage alone.
- `logAzure.txt` is the campaign-unique anchor (Path 1 / IOC).
- The 2050-05-13 magic event date only counts when it co-occurs with Graph
  calendar usage (Path 2 / IOC).
- The behavioral fallback (Path 3) requires Graph calendar + attachment
  dead-drop + AES-256-GCM + hardcoded app-credential material together.

## Corpus FP test

Scope: recent family — any corpus hit is a candidate FP to investigate.
Bounded slices of the real-malware corpus (2026-07-22):

- HollowGraph_GraphCalendar_C2_Behavior: 1,466 samples scanned, 0 matches, 0 read-errors → clean
- HollowGraph_IOC: 2,354 samples scanned, 0 matches, 0 read-errors → clean
- HollowGraph_Implant_Specimen: not scanned — condition requires logAzure.txt +
  2050-05-13 + Graph host/events + AES-256-GCM to co-occur in one file; FP risk
  assessed negligible.

Verdict: no false positives on the scanned slices.
