# MALFEX — YARA test results

Family: `malfex`
Rule file: `malfex.yar`
Author: synthetic-detections
Date: 2026-10-09
Disclosure: 2026-10 (Checkmarx, CloudSEK, Hackread — MALFEX npm supply-chain campaign: Overlord RAT, movinlike stealer, npm worm)

## Rules

1. `MALFEX_OverlordRAT_Behavioral` (critical, behavioural) — "ScopeSmart Technologies" fake
   vendor name co-occurring with operational markers: scheduled task `\Maiden`, AES key
   `malfexteam2027`, process hollowing target `TapiUnattend.exe`, or AutoIt script names
   (`h.a3x` / `Oxygen.a3x`). The vendor string is unique to this campaign and not a real
   company — combined with any operational marker, it is a high-confidence detection.
2. `MALFEX_IOC` (high) — static IOC sweep. Globally unique tokens (`corpmalfex@gmail.com`,
   `malfexteam2027`, `ScopeSmart Technologies`) fire standalone. C2 IPs require mutual
   co-occurrence (two or more together) or pairing with a campaign anchor. npm package names
   (`function-flag`, `function-color`, etc.) require co-occurrence with a campaign-specific
   indicator to avoid FPs on legitimate package listings.
3. `MALFEX_Specimen` (critical, specimen-pin) — exact SHA-256 hash match for four known
   samples: Overlord RAT loader, AutoIt3.exe (abused binary), decoded RAT payload, and
   movinlike stealer.

## In-repo smoke test

Specimens (should match — all pass):
- `specimens/malfex-overlord-behavioral.txt` → `MALFEX_OverlordRAT_Behavioral` + `MALFEX_IOC`
  (synthetic stub carrying ScopeSmart vendor + all operational markers)
- `specimens/malfex-ioc-sweep.txt` → `MALFEX_OverlordRAT_Behavioral` + `MALFEX_IOC`
  (full IOC reference document with all campaign indicators)

Note: `MALFEX_Specimen` (rule 3) requires exact file hash match and therefore does not match
synthetic stubs. The rule is validated by construction — a file whose SHA-256 matches one of
the four pinned hashes will fire.

Benign (structurally similar — must NOT match, all clean):
- `benign/legit-npm-package-list.txt` — legitimate npm dependency listing with generic
  package names (function-bind, color-convert, native-image); no MALFEX-specific strings.
  Confirms npm package references alone do not fire.
- `benign/legit-autoit-script.txt` — benign AutoIt automation script; no ScopeSmart vendor
  name or MALFEX task names. Confirms AutoIt usage alone does not fire.
- `benign/legit-task-scheduler.txt` — legitimate Windows Task Scheduler XML export; no
  MALFEX-specific task names (Maiden, Welcome, Wichita). Confirms task scheduler artifacts
  alone do not fire.

Result: 2/2 specimens hit their intended rules; 0/3 benign files matched.

## Known residual FP risk

`MALFEX_IOC` fires standalone on `ScopeSmart Technologies` — this is a fictitious company
name used exclusively by this threat actor. Any file referencing it warrants investigation.
The `cavecrew` GitHub handle has a co-occurrence guard and will not fire alone.

## Corpus FP test

| Rule                          |  Slice | Hits | Verdict |
|-------------------------------|-------:|-----:|---------|
| MALFEX_OverlordRAT_Behavioral |  6,291 |    0 | Clean   |
| MALFEX_IOC                    | 10,896 |    0 | Clean   |
