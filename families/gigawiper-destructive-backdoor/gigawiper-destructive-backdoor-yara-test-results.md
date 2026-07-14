# GigaWiper — YARA test results

Source: Microsoft Security Blog, 2026-07-09
(https://www.microsoft.com/en-us/security/blog/2026/07/09/gigawiper-anatomy-of-a-destructive-backdoor-assembled-from-multiple-malware/);
The Hacker News, 2026-07-09.

Rules validated with YARA 4.5.2.

## Rules

| rule | severity | anchors |
|---|---|---|
| `GigaWiper_Go_ToolSymbols` | critical | assembled Go tool/package symbols `rabbit_tools_tool_{wipe,wipec,ran}_*`, `rabbit_bin.RunOnceRegistryMain` (near-unique) |
| `GigaWiper_Wiper_FakeRansom_Artifacts` | critical | PE + `.candy` / `image_danger.jpg` / OneDrive-masquerade persistence / GRAT-CWipe PDB, co-occurrence gated |
| `GigaWiper_IOC` | high | RabbitMQ/Redis C2 `185.182.193.21:5544/7542`, secondary C2 `212.8.248.104` |

## Discrimination logic

- The `rabbit_tools_tool_*` symbols are the assembled implant's own package
  paths and do not appear in ordinary RabbitMQ client code — the behavioural
  rule keys on those, not on the word "rabbit".
- `.candy`, `image_danger.jpg`, and the `OneDrive Update` task each alias
  benign things individually, so the artifact rule requires a PE **and**
  co-occurrence of two markers (or a standalone FlockWiper/GRAT PDB path,
  which is specific on its own).

## Smoke test (in-repo)

```
$ yara -r gigawiper-destructive-backdoor.yar specimens/     # expect hits
GigaWiper_Go_ToolSymbols              specimens/gigawiper_go_symbols.bin
GigaWiper_IOC                         specimens/gigawiper_c2_config.txt
GigaWiper_Wiper_FakeRansom_Artifacts  specimens/gigawiper_flockwiper_pdb.bin
GigaWiper_Wiper_FakeRansom_Artifacts  specimens/gigawiper_wiper_artifacts.bin

$ yara -r gigawiper-destructive-backdoor.yar benign/        # expect none
(clean)
```

`benign/` covers the discriminators: a genuine RabbitMQ client binary, a game
save file literally named `*.candy`, a real OneDrive updater carrying the
`OneDrive Update` task, and a report-prose excerpt with a single marker.
None fire.

## Corpus FP test

PENDING — the corpus scan was unavailable at author time. To be run against the
malware corpus when available. For this recent family, any corpus hit is a
candidate false positive to investigate and tighten; result (samples, hits,
verdict) to be recorded here.
