# AmnesiaStealer (macOS) — YARA test results

Family: `amnesiastealer-macos-stealer`
Rules: `AmnesiaStealer_macOS_Behavior` (critical), `AmnesiaStealer_macOS_IOC` (high),
`AmnesiaStealer_macOS_Specimen` (critical).
Source: Jamf Threat Labs, 2026-08-13 — https://www.jamf.com/blog/amnesia-stealer-macos-infostealer-clickfix/

## Artifacts keyed on
- Embedded secrets: config XOR key `4mn3s1a_2o26!xK` (leetspeak "amnesia 2026"),
  safe-storage destructive-rewrite password `pqz8N3vKxRmY2aLcQ`.
- Module/debug markers: `[HYBRID_DEBUG]`, `.local/share/.stream`, `run_controller`,
  `dump_mail`, `/tmp/mail_accounts_smoke`, `BUILD_V3_MARKER.txt`, `v3_shell_chrome`.
- Network: C2 `debug.allllowef.space`, delivery `github.aoitour.com`,
  `X-API-Key: 86770e8759abf2dad9ae85f5e11a25e9`, `/api/bot/join`, `/api/bot/actions?build_id=`.
- SHA-256: `de5748…fab55a` (stage 1), `e85374…b31a5` (stage 2 "stream" module).

## In-repo smoke test — PASS
```
$ yara -r amnesiastealer-macos-stealer.yar specimens/
AmnesiaStealer_macOS_Behavior  specimens/amnesiastealer-strings.txt
AmnesiaStealer_macOS_IOC       specimens/amnesiastealer-strings.txt
AmnesiaStealer_macOS_Specimen  specimens/amnesiastealer-strings.txt
$ yara -r amnesiastealer-macos-stealer.yar benign/
(no output — clean)
```
- `specimens/amnesiastealer-strings.txt` — reconstructed distinctive strings; matches all three rules.
- `benign/rust-cdp-browser-tool.txt` — structural lookalike (legit Rust CLI driving Chrome over
  CDP/chromiumoxide: shares Rust/cargo + CDP + browser-name surface, none of the AmnesiaStealer
  markers). Correctly NOT matched.

## Corpus false-positive scan
Behavioral rule (`AmnesiaStealer_macOS_Behavior`) submitted as a single rule.
IOC and Specimen rules are hash/domain/secret-pinned (near-zero FP by construction — the leetspeak
XOR key and the sample SHA-256s do not occur in benign files) and are not corpus-swept.
- Status: **RUNNING** at commit time (submitted 2026-08-18, `--max-hits 40 --budget 15m`);
  verdict to be recorded here when the job completes. The behavioral condition requires the near-unique
  `4mn3s1a_2o26!xK` / `pqz8N3vKxRmY2aLcQ` secret, or `[HYBRID_DEBUG]`+module co-occurrence, or two
  distinct module strings together — no single generic string can trip it, so FPs are expected to be zero.
