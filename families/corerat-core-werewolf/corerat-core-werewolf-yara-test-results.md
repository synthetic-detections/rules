# CoreRAT (Core Werewolf) — YARA test results

Family: `corerat-core-werewolf`
Authored: 2026-08-27
Source: BI.ZONE "Arsenal revamped: Core Werewolf hits Russian organizations with CoreRAT" (2026-08-26),
corroborated by GBHackers / CyberSecurityNews (2026-08-26/27).

## Rules
1. `CoreRAT_Behaviour` (critical) — PE + hardcoded mutex `301525677` co-occurring with a CoreRAT C2
   URI path (`/5743e279`, `/0a445b0e`, `/ba4b6dc1`, `/97e8be66`) or a deployment EXE name
   (`Firepoin.exe`, `Baresl.exe`, `Biostars.exe`).
2. `CoreRAT_C2_IOC` (high) — >=2 distinct CoreRAT C2 domains/IPs (co-occurrence guard).
3. `CoreRAT_Delivery_Pin` (critical) — decoy PDF name co-occurring with a deployment EXE name.

## Smoke test
- `specimens/` (3 representative files) — each rule matched its intended specimen:
  - `corerat_behaviour_stub.bin` → CoreRAT_Behaviour
  - `corerat_c2_config.json` → CoreRAT_C2_IOC
  - `corerat_delivery_sfx.txt` → CoreRAT_Delivery_Pin
- `benign/` (3 structurally-similar files: a legit PE carrying an unrelated 9-digit number,
  a single-host config, a PDF-only listing with no EXE) — clean, no matches.

Result: PASS (expected hits on specimens, clean on benign).

Note: no live CoreRAT sample was held at authoring time; specimens are synthetic representatives
built from the vendor report's static artifacts. Rules 1/3 are co-occurrence-guarded so a bare
mutex/decoy string alone cannot fire.

## Corpus FP test
Status: PENDING — a corpus false-positive scan of the highest-FP-risk rule (`CoreRAT_C2_IOC`,
the 2-of-N host match) was submitted to the corpus scanner (~497k samples). Result to be
recorded here when the scan completes. Any corpus hit on this recent family is a candidate FP
to investigate and tighten.
