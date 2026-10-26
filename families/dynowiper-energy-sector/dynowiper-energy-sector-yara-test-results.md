# DynoWiper / LazyWiper (Poland energy-sector) — YARA test results

Rule file: `dynowiper-energy-sector.yar` (6 rules)
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
4. `LazyWiper_Behavior` (critical) — the operational pattern of LazyWiper: `Add-Type` C#
   embedding + ≥3 of the FileStream write indicators (FileStream, FileAccess.Write,
   new Random(), new byte[32], Seek(16) + `DisableRealTimeMonitoring` Defender disable.
   Not a PE. Survives cosmetic LLM regeneration as long as the technique stays the same.
5. `LazyWiper_Build` (low) — pins THIS specific LLM-generated build: `RandomByteWriter`
   class or `WriteRandomBytes` method + ≥2 misspelled `.pcks*` extensions + `pe-dc`
   hostname abort or `GetHostName` API call. Will not survive regeneration.
6. `DynoWiper_Campaign_IOCs` (high) — sample sha256/sha1 pins + the Static-Tundra relay
   C2 IPs (185.200.177[.]10, 31.172.71[.]5). Atomic; decay expected.

Not covered (by design): the OT-side destruction (Hitachi RTU560 firmware, Mikronika/Relion
file deletion, Moxa/Teltonika/WAGO resets, Siemens S7 STOP) was default-credential /
native-protocol abuse with no distributable sample; and the entire Aug-2026 follow-up
(private-APN vector) is living-off-the-land with zero binary artifacts.

## Update 2026-10-26 — LazyWiper rules rewritten from CERT Polska report

The CERT Polska Energy Sector Incident Report PDF was parsed to extract actual
LazyWiper code fragments (Fig 29/30), the SHA256 hash, and the complete extension list.

Changes:
- **Added `LazyWiper_Behavior`** (critical) — new behavioral rule for the PowerShell + C#
  overwrite-with-seek pattern. Anchors on the technique (Add-Type embedding, FileStream
  write loop with 16-byte seek, Defender disable) rather than cosmetic identifiers.
- **Rewrote `LazyWiper_Build`** — fixed DC-abort strings: the actual specimen uses
  `"pe-dc"` hostname comparison (`GetHostName().ToLower().Contains("pe-dc")`), not
  `DomainController`/`ProductType` WMI checks. Added `RandomByteWriter` class name
  and sample SHA256 hash in metadata.
- **Updated specimen** `KB284726.ps1` — replaced 3-line stub with proper synthetic specimen
  reconstructed from CERT Polska report code fragments (Fig 29: C# WriteRandomBytes,
  Fig 30: Add-Type + Defender disable + pe-dc check, plus full extension list from p33).
- **Added benign** `legit-csharp-hasher.ps1` — PowerShell using Add-Type C# embedding
  for SHA256 file hashing (FileAccess.Read, no Random/Seek/Defender patterns).

## In-repo smoke test

Environment: YARA 4.5.2, Linux x86_64, 2026-10-26.

`yara -r dynowiper-energy-sector.yar specimens/` → 6 hits (all expected):

| Specimen | Rule(s) matched |
|---|---|
| `dynowiper-sample.bin` | `DynoWiper_Wiper_Behavior` + `DynoWiper_PDB_Guarded` |
| `dynacom_update.ps1` | `DynoWiper_GPO_Distributor` |
| `KB284726.ps1` | `LazyWiper_Behavior` + `LazyWiper_Build` |
| `dynowiper-ioc-sweep.txt` | `DynoWiper_Campaign_IOCs` |

`yara -r dynowiper-energy-sector.yar benign/` → **0 hits (clean)**.

Benign set (5 files): a legit installer PE (correct `Program Files (x86)` spelling,
no error string), a routine GPO-maintenance script (Default Domain Policy backup
+ a differently-named task, no GUID), a benign backup tool (`Write-RandomPadding`
+ extension list, no LazyWiper combo), a wiper-glossary note, and a C#-embedding
file-hasher (FileAccess.Read, no overwrite/Seek/Defender patterns).

### Why the benign cases don't false-positive

- **`legit-csharp-hasher.ps1`** vs `LazyWiper_Behavior`: has `Add-Type` (matches $embed)
  and `FileStream` (matches $w1), but uses `FileAccess.Read` (not Write → $w2 misses),
  no `new Random()` ($w3), no `new byte[32]` ($w4), no `Seek(16` ($w5), no
  `DisableRealTimeMonitoring` ($def). Only 1 of 5 $w* strings match; condition needs 3.
- **`legit-csharp-hasher.ps1`** vs `LazyWiper_Build`: no `RandomByteWriter`, no
  `WriteRandomBytes`, no `.pcks*` extensions, no `pe-dc`, no `GetHostName`.
- **`legit-backup-tool.ps1`** vs both LazyWiper rules: has `Write-RandomPadding` (not
  `WriteRandomBytes`), has `.bak`/`.pfx` but no `.pcks*`, no `Add-Type`, no C#, no
  `DisableRealTimeMonitoring`.

## Corpus FP test

Budget-bounded slices, one rule per job (gate requires single-rule + filesize guard):

### Original 5 rules (2026-08-09)
- `DynoWiper_Wiper_Behavior` — 2,674 scanned, **0 matches**, 0 read-errors.
- `DynoWiper_PDB_Guarded` — 5,848 scanned, **0 matches**, 0 read-errors.
- `DynoWiper_GPO_Distributor` — 6,138 scanned, **0 matches**, 0 read-errors.
- `LazyWiper_Build` (old strings) — 6,321 scanned, **0 matches**, 0 read-errors.
- `DynoWiper_Campaign_IOCs` — 6,411 scanned, **0 matches**, 0 read-errors.

Rerun 2026-08-11 (independent second pass, larger budget-bounded slices):
- `DynoWiper_Wiper_Behavior` — 5,241 scanned, **0 matches**, 0 read-errors.
- `DynoWiper_PDB_Guarded` — 12,304 scanned, **0 matches**, 0 read-errors.
- `DynoWiper_GPO_Distributor` — 11,616 scanned, **0 matches**, 0 read-errors.
- `LazyWiper_Build` (old strings) — 12,115 scanned, **0 matches**, 0 read-errors.
- `DynoWiper_Campaign_IOCs` — 12,021 scanned, **0 matches**, 0 read-errors.

Cumulative across both passes: 80,689 file-scans, 0 matches.

### Updated LazyWiper rules (2026-10-26)
- `LazyWiper_Behavior` — PENDING (corpus scan launched, awaiting results)
- `LazyWiper_Build` (rewritten) — PENDING (corpus scan launched, awaiting results)

## Update 2026-08-22 — FP tightening
Campaign IOC condition changed from `any of them` to `filesize < 4MB and (any of ($s*) or all of ($ip*))`: the two C2 IPs are YARA substring matches (185.200.177.10 ⊂ 185.200.177.100), so they now require both relay IPs together; the full SHA-256 hashes still fire alone. Smoke test re-run: specimens hit, benign clean.
