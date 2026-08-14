# PATCHCORD / SHEETCORD / HACKERAI (APT36) — YARA test results

Source: Acronis Threat Research Unit, 2026-08-13 — "PATCHCORD: New malware
cluster targets Afghan telecom and South Asian critical infrastructure."
Attribution: APT36 / Transparent Tribe (Pakistan-nexus espionage).

## Rules

1. `PATCHCORD_Beacon` (critical) — PE + `Beacon/1.0.0` user-agent, co-occurrence
   guarded by an APT36 campaign token (`TMS_AfghanTelecom`, `Salaam_telecom`,
   `SystemHelper.vbs`, `AFTEL`) or a hard C2 IP (108.187.42.63 / 46.30.188.13).
   The UA is generic, so it never fires alone.
2. `PATCHCORD_Campaign_Artifacts` (high) — >=2 distinctive lure/persistence file
   names (`TMS_AfghanTelecom.exe`, `Bonus_Salaam_telecom.zip`,
   `Ministry of Communication & Information Technology.msi`, `MCIT.pdf`,
   `SystemHelper.vbs`, `GateSentinel-C2-Rat-Hvnc`), filesize-guarded.
3. `PATCHCORD_Samples` (critical) — SHA-256 pins for the 13 report samples.

## Smoke test (in-repo)

```
$ yara -w patchcord-apt36.yar specimens/
PATCHCORD_Beacon             specimens/patchcord_beacon.bin
PATCHCORD_Campaign_Artifacts specimens/campaign_lures.txt

$ yara -w patchcord-apt36.yar benign/
(no output — clean)
```

- **specimens/** (should match):
  - `patchcord_beacon.bin` — PE stub carrying `Beacon/1.0.0` + C2 IP → rule 1. ✓
  - `campaign_lures.txt` — installer/persistence names (>=2) → rule 2. ✓
- **benign/** (should NOT match — structurally similar):
  - `generic_beacon.bin` — PE with `Beacon/1.0.0` but no campaign token / C2 →
    correctly NOT matched (verifies rule 1's guard against generic beacons). ✓
  - `telecom_news.txt` — Afghan-telecom prose with exactly one artifact token →
    below rule 2's `2 of` threshold, correctly NOT matched. ✓
  - `normal_installer.bin` — generic Inno Setup PE → clean. ✓

Rule 3 (`PATCHCORD_Samples`) is validated by construction — synthetic specimens
cannot reproduce the pinned SHA-256 values, so it is not exercised by the smoke
test; it is a deterministic hash pin.

## Corpus false-positive test

**PENDING** — the corpus false-positive service was unavailable at authoring time
(name resolution failure). To be run against rules 1–2 when the service is
reachable; any hit on this recent family is a candidate FP to investigate and
tighten. The hash-pin rule (3) is deliberately excluded from any corpus sweep —
a pure full-file hash rule forces hashing the entire corpus and offers no FP
signal, so it is validated by construction only.

## Notes

- 0 of the 13 SHA-256 samples are on public sample-sharing services (checked
  2026-08-14) — consistent with targeted APT tooling.
- SHEETCORD (Google Sheets C2) and HACKERAI C2 Agent (GitHub Gists C2) share the
  campaign's lure/persistence artifacts; rule 2 covers their installer stage.
  A network signature for the cloud-service C2 is not included (legitimate
  Google/GitHub domains — would over-match); host-based artifacts are the
  reliable signal here.
