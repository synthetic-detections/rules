# headmare-trueconf-phantomgraph — YARA test results

Family: Head Mare TrueConf supply-chain intrusion (PhantomCore / PhantomGraph)
Author: synthetic-detections
Date: 2026-08-10
Source: Kaspersky Securelist (disclosed 2026-08-08)

## Rules
1. `HeadMare_PhantomGraph_Artifacts` (critical) — PhantomGraph DLL/service/path/CLSID constellation, PE-gated with co-occurrence guard.
2. `HeadMare_TrueConf_Linux_Persistence` (high) — masquerading Acronis/OMI Linux service + path artifacts, 2-of co-occurrence.
3. `HeadMare_TrueConf_IOC` (high) — web-shell/installer/side-load pins (2-of) or any pinned MD5.

## In-repo smoke test

Command: `yara -r headmare-trueconf-phantomgraph.yar specimens/` and `… benign/`

Specimens (should match) — ALL HIT:
- `specimens/phantomgraph_pe.bin` → `HeadMare_PhantomGraph_Artifacts`
- `specimens/linux_persistence.elf` → `HeadMare_TrueConf_Linux_Persistence`
- `specimens/ioc_report.txt` → `HeadMare_TrueConf_IOC`

Benign (should NOT match) — ALL CLEAN:
- `benign/legit_iis_module.bin` (legit inetsrv/IIS PE) — no hit
- `benign/acronis_backup.service` (real Acronis product path) — no hit
- `benign/trueconf_install.log` (legit TrueConf client install log) — no hit

Verdict: PASS. Behavioural rules require the distinctive combination (service names + install path + tasking artifacts); benign IIS/Acronis/TrueConf references do not trigger.

## Corpus false-positive test

Status: **PENDING** — corpus-scan service was unreachable at authoring time (request timed out). To be re-run and recorded here (slice size / matches / read-errors / verdict). Rules are non-hash behavioural + literal-IOC; a recent-family corpus hit would be a candidate FP to investigate and tighten.

## Notes
- Family is a distinct cluster from the April-2026 Chinese/Havoc TrueConf activity — do not conflate.
- MD5-only IOC set (Kaspersky published MD5s); pins are lowercase-hex literals, so full-file hashing is not required.
