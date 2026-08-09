# DynoWiper / LazyWiper (Poland energy-sector) — YARA test results

Rule file: `dynowiper-energy-sector.yar` (5 rules)
Family: `dynowiper-energy-sector`
Sources: CERT Polska original report 2026-01-30 + follow-up 2026-08-08.

## Rules
1. `DynoWiper_Wiper_Behavior` (critical) — PE + `filesize<500KB` + `Error opening file: `
   (wide) + ≥3 of the drive-walk exclusion list, including the attacker typo
   `program files(x86)`. Extends CERT's published DynoWiper rule with a co-occurrence guard.
2. `DynoWiper_PDB_Guarded` (high) — the `vagrant\…\Source\Release\Source.pdb` build path,
   gated on a PE + (the vagrant user path or an exclusion string) so the forgeable PDB
   cannot fire alone.
3. `DynoWiper_GPO_Distributor` (critical) — the PowerShell GPO dropper: the hardcoded
   filter GUID `79A87EBB-4DF6-4541-9530-CAD8BEE8A7AD`, the `Custom Domain Policy` +
   `Custom GPO Task` name pair, or the exact self-delete line.
4. `LazyWiper_Build` (low) — `WriteRandomBytes` + ≥2 of the misspelled `.pcks*` extensions
   + a DC-abort check. CERT assess LazyWiper as LLM-generated; this pins THIS build and is
   deliberately low-severity — it will not survive regeneration with different identifiers.
5. `DynoWiper_Campaign_IOCs` (high) — sample sha256/sha1 pins + the Static-Tundra relay
   C2 IPs (185.200.177.10, 31.172.71.5). Atomic; decay expected.

Not covered (by design): the OT-side destruction (Hitachi RTU560 firmware, Mikronika/Relion
file deletion, Moxa/Teltonika/WAGO resets, Siemens S7 STOP) was default-credential /
native-protocol abuse with no distributable sample; and the entire Aug-2026 follow-up
(private-APN vector) is living-off-the-land with zero binary artifacts.

## In-repo smoke test
`yara -r dynowiper-energy-sector.yar specimens/` → 5 hits (all expected):
- `dynowiper-sample.bin` → DynoWiper_Wiper_Behavior + DynoWiper_PDB_Guarded
- `dynacom_update.ps1` → DynoWiper_GPO_Distributor
- `KB284726.ps1` → LazyWiper_Build
- `dynowiper-ioc-sweep.txt` → DynoWiper_Campaign_IOCs

`yara -r dynowiper-energy-sector.yar benign/` → **0 hits (clean)**.
Benign set: a legit installer PE (correct `Program Files (x86)` spelling, no error string),
a routine GPO-maintenance script (Default Domain Policy backup + a differently-named task,
no GUID), a benign backup tool (`Write-RandomPadding` + extension list, no LazyWiper combo),
and a wiper-glossary note. All correctly do not match — the guards hold.

## Corpus FP test
Budget-bounded slices, one rule per job (gate requires single-rule + filesize guard):
- `DynoWiper_Wiper_Behavior` — 2,674 scanned, **0 matches**, 0 read-errors.
- `DynoWiper_PDB_Guarded` — 5,848 scanned, **0 matches**, 0 read-errors.
- `DynoWiper_GPO_Distributor` — 6,138 scanned, **0 matches**, 0 read-errors.
- `LazyWiper_Build` — 6,321 scanned, **0 matches**, 0 read-errors.
- `DynoWiper_Campaign_IOCs` — 6,411 scanned, **0 matches**, 0 read-errors.

Verdict: no false positives on the sampled corpus slices for any of the five rules
(27,392 files total across the slices, 0 matches each); guards verified against
structurally-similar benign PE/PowerShell/text.
