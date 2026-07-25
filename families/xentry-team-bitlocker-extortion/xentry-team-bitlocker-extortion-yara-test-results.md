# XEntry Team — BitLocker/printer extortion — YARA test results

Family: `xentry-team-bitlocker-extortion`
Rule file: `xentry-team-bitlocker-extortion.yar`
Authored: 2026-07-25
Source: Kaspersky Securelist (2026-07-21) — https://securelist.com/new-extortion-scheme-printers-bitlocker/120718/

## Rules

| Rule | Severity | Anchor |
|------|----------|--------|
| XEntry_Team_RansomNote_Behavior | critical | both reused "guarantee" sentences together |
| XEntry_Team_Branding_IOC | high | "Hacked by XEntry Team" brand + one supporting artifact |
| XEntry_Team_RansomNote_Pin | critical | brand string AND both guarantee sentences |

Note: this family is text/LOLBin-only — encryption is performed with built-in
Windows BitLocker (`manage-bde`), so there is no encryptor binary, file magic,
or published hash/C2 to pin. Rules target the ransom note as delivered (dropped
note file, printed page, on-screen blue-screen message).

## In-repo smoke test

Command: `yara -r xentry-team-bitlocker-extortion.yar specimens/` and `.../benign/`

Specimens (should match):
- `specimens/specimen_ransom_note.txt` → XEntry_Team_RansomNote_Behavior, XEntry_Team_Branding_IOC, XEntry_Team_RansomNote_Pin ✓ (all three)
- `specimens/specimen_bluescreen_message.txt` → XEntry_Team_Branding_IOC ✓ (brand + manage-bde/BitLocker; no guarantee sentences, so Behavior/Pin correctly do not fire)

Benign (should NOT match):
- `benign/benign_generic_ransom_note.txt` → clean ✓ (generic double-extortion note; mentions "reputation"/"guarantee"/"reviews" but not the verbatim XEntry sentences or brand)
- `benign/benign_business_reviews.txt` → clean ✓ (legitimate vendor statement referencing reputation, "no negative online reviews", and BitLocker — no brand, no verbatim sentences)

Result: **PASS** — specimens hit the intended rules, benign structurally-similar files are clean.

## Corpus FP test

Rule scanned: `XEntry_Team_Branding_IOC` (broadest string surface; the other two
require both verbatim guarantee sentences, near-zero corpus FP risk).
Corpus: full malware sample set, budget-limited slice, --max-hits 40, budget 15m.
Status: **RUNNING (detached)** at time of commit — result announced on completion.
Expectation: 0 hits — the `Hacked by XEntry Team` brand string gates every match
path, and it is a made-up crew name unlikely to appear in unrelated samples. Any
hit on this recent family is a candidate FP to investigate and tighten.

_Update this section with slice size / hits / verdict when the scan returns._
