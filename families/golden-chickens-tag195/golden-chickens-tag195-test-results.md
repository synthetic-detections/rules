# golden-chickens-tag195 — test results

Family: Golden Chickens MaaS reboot — TAG-195 (dev) / TAG-127 (deploy).
Families: TinyEgg, ChonkyChicken, modular ChonkyChicken, ChromEggscalator.
Disclosed: 2026-07-24 (Recorded Future Insikt Group). Rules authored: 2026-07-26.

## Rules

| Rule | Type | Severity |
|------|------|----------|
| GoldenChickens_TAG195_Implant_Behavior | behavioral (persistence + CDP theft + .ocx staging) | critical |
| GoldenChickens_TAG195_Modular_Shape | structural (WebSocket-agent / controller .ocx shape) | high |
| GoldenChickens_TAG195_IOC | IOC (C2 domains + IPs) | high |
| GoldenChickens_TAG195_SampleHash | specimen-pin (29 SHA-256) | critical |

## Local smoke test (yara 4.5.2)

Compiles clean (`yara -w golden-chickens-tag195.yar`).

Specimens (mock reconstructions from public reporting — inert):

| Specimen | Behavior | Modular | IOC |
|----------|----------|---------|-----|
| mock-ioc-report.txt | — | — | match |
| mock-chonkychicken-config.txt | match | — | — |
| mock-modular-controller.txt | match | match | — |

Benign controls (must NOT match) — both clean:

| Benign | Result | Purpose |
|--------|--------|---------|
| legit-mscomctl-app.txt | no match | legit Microsoft Common Controls (mscomctl.ocx/mscom.ocx) must not trip |
| legit-chrome-devtools-automation.txt | no match | benign CDP automation (port 9222) without the -32000 hidden-window offset must not trip |

## FP-avoidance notes

mscomctl.ocx / mscom.ocx are legitimate Microsoft Common Controls filenames and
`--remote-debugging-port=9222` is used by benign browser automation — none of
these are ever matched alone. Every behavioral path requires a campaign-unique
co-occurrence: the `Run\WinComCtl` persistence value with an .ocx staging name,
the `-32000` hidden-window offset with the debugging port, or two distinctive
.ocx names together (chromelevator/koki/wpad_capture/updater/agent). The modular
rule anchors the generic `/ws/agent` path to a controller filename or the
`ChromElevator` provenance string, and treats the `ws://localhost:3000/ws/agent`
dev listener as campaign-specific on its own.

## Corpus FP test (MalShare, ~497k samples)

**PENDING** — the corpus-scanning service was unreachable at authoring time
(connection timeouts on 2026-07-26). Re-run the bounded per-rule scan
(--max-hits 40 / --budget 15m) when the service is back; any hit on a family
disclosed two days ago is a candidate FP to investigate and tighten.

Note: the 29 sample SHA-256 hashes were checked against MalShare at authoring
time — all absent — so the SampleHash rule is validated only against pinned
values; live samples were not available via hash-based fetch.
