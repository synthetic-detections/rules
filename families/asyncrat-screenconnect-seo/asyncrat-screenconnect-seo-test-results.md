# asyncrat-screenconnect-seo — test results

Family: SEO-poisoned ScreenConnect -> AsyncRAT ("FlowProxy Monitor V3")
Disclosed: 2026-07-01 (Kaspersky, Hunt.io). Rules authored: 2026-07-02.

## Rules

| Rule | Type | Severity |
|------|------|----------|
| AsyncRAT_ScreenConnect_SEO_Behavior | behavioral (loader/injector chain + AsyncRAT config) | critical |
| AsyncRAT_ScreenConnect_SEO_LoaderShape | structural (multi-stage loader artifacts) | high |
| AsyncRAT_ScreenConnect_SEO_IOC | IOC (C2 IPs/domains, file hashes) | high |

## Local smoke test (yara 4.5.2)

Compiles clean (`yara -w asyncrat-screenconnect-seo.yar`).

Specimens (mock reconstructions from public reporting — inert):

| Specimen | Behavior | LoaderShape | IOC |
|----------|----------|-------------|-----|
| mock-ioc-report.txt | match | match | match |
| mock-screenconnect-loader.ps1 | match | — | — |
| mock-loader-stage.vbs | match | match | — |

Benign controls (must NOT match) — both clean:

| Benign | Result | Purpose |
|--------|--------|---------|
| legit-screenconnect-install.txt | no match | normal ScreenConnect deploy must not trip on generic "screenconnect.client.exe"/"ScreenConnect" |
| legit-defender-exclusion.ps1 | no match | lone legitimate `Add-MpPreference -ExclusionPath` must not trip the behavioral rule |

## FP-avoidance notes

AsyncRAT and ScreenConnect are both commodity/legitimate. The rules deliberately
anchor on campaign-specific artifacts — the internal build label
"FlowProxy Monitor V3", scheduled-task names ("SystemInstallTask", "3losh"),
the side-load DLL name (install.res.1033.dll), the loader-chain filenames, and
the tracked C2 set — rather than generic AsyncRAT/ScreenConnect strings. Path 3
of the behavioral rule requires the rogue side-load DLL, so a signed ConnectWise
install alone does not match.

## Corpus FP test (MalShare, ~497k samples)

Ran via task-runner (yara-fp-scan, task #20, 2026-07-02) — per-rule bounded
scan (--max-hits 40 / --budget 15m) against the MalShare corpus (~497k samples).

**Result: 0 hits, all three rules — FP-clean.**

| Rule | Corpus hits |
|------|-------------|
| AsyncRAT_ScreenConnect_SEO_Behavior | 0 |
| AsyncRAT_ScreenConnect_SEO_LoaderShape | 0 |
| AsyncRAT_ScreenConnect_SEO_IOC | 0 |

For a family disclosed one day ago, any corpus hit would have been a candidate
false positive; none surfaced.

Note: the specific sample hashes from the reports were not present in MalShare
at authoring time (checked 4 SHA256/MD5 — all absent), so the IOC rule is
currently validated only against the mock report; live samples were not
available via hash-based fetch.
