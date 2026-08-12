# operation-dream-job-lazarus — YARA test results

Source: Check Point Research, "Shattering the Dream — When a Job Offer Becomes a
Zero-Day Attack" (2026-08-11). Family covers the 2026 Operation Dream Job wave:
FudModule v3.1 (afd.sys CVE-2026-68820), Troy backdoor, SecurityPDF decoy loader,
and the RelayShell PHP webshell (Roundcube CVE-2025-49113).

## Rules

| Rule | Severity | Keys on |
|------|----------|---------|
| Lazarus_FudModule_GodMode | critical | PE + ≥3 god-mode telemetry strings (or 2 + SAC/vaccine token) |
| Lazarus_Troy_Backdoor | critical | PE + Troy_Handle PDB frag OR ≥4 command words + CONNECTED |
| Lazarus_SecurityPDF_Decoy | high | SumatraPDF "encrypted" decoy marker + libmupdf/PDF/PE guard |
| Lazarus_RelayShell_Webshell | high | PHP + embedded RelayShell operator identifier |
| Lazarus_DreamJob_C2 | high | ≥2 of the 2026-wave C2 domains/IPs (count-guarded) |

## In-repo smoke test

```
$ yara -r operation-dream-job-lazarus.yar specimens/
Lazarus_DreamJob_C2 specimens//dreamjob_c2_config.txt
Lazarus_FudModule_GodMode specimens//fudmodule_godmode.bin
Lazarus_SecurityPDF_Decoy specimens//securitypdf_decoy.pdf
Lazarus_RelayShell_Webshell specimens//relayshell.php
Lazarus_Troy_Backdoor specimens//troy_backdoor.bin

$ yara -r operation-dream-job-lazarus.yar benign/
(no output — clean)
```

Specimens are synthetic PE/PDF/PHP stubs carrying the distinctive strings. Benign
set is deliberately structurally similar: a normal PE with generic API strings, a
legitimate libmupdf-rendered PDF **without** the decoy marker (guards against the
SecurityPDF rule firing on any mupdf output), a normal PHP page, and an analyst
note mentioning a single C2 host (guards the ≥2 count on the C2 rule).

## Corpus FP test

PENDING — corpus-scan service unavailable at authoring time (DNS resolution
failure to the scan host). To run once reachable, scan each rule on a recent
slice; any hit on this recent family is a candidate FP to investigate. The
content keys chosen (verbatim FudModule telemetry, the Troy PDB fragment, the
unique SumatraPDF decoy sentence, the RelayShell operator id) are long and
specific, so broad corpus FPs are not expected. File-hash IOCs are tracked in the
2026-08-12 digest hash store rather than in-rule, keeping these rules
content-based and corpus-scannable.

## Notes

- Keys on content, not CVE numbers or file hashes (both forgeable / churny).
- FudModule is a data-only rootkit (no BYOVD driver to signature), so the rule
  targets its in-binary telemetry strings.
- Attribution (DPRK / Lazarus / APT38) per Check Point; not overstated.
