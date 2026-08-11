# WEL1DROPPER npm RAT — YARA test results

Family: `wel1dropper-npm-rat` · authored 2026-08-11 · 3 rules.

## Rules
- `WEL1DROPPER_Loader_Behavior` (critical) — hookless `require()`-triggered JS
  downloader: OS/arch fingerprint + Cloudflare-Workers `oob-worker` host **or**
  DNS-TXT/`wel1.ru` staging fallback, plus a helper-file entry point.
- `WEL1DROPPER_IOC` (high) — staging subdomains, Workers hosts, disguised
  LaunchAgent, payload paths, bank decoy strings; `>=2` co-occurrence guard.
- `WEL1DROPPER_MacOS_Persistence` (critical) — disguised WindowServer
  LaunchAgent + anti-analysis (lldb/frida/dtrace, VMware) / beacon combo.

Each rule carries a `filesize < 500KB` guard (all real artifacts are small
JS / text / shell files).

## In-repo smoke test
`yara -r wel1dropper-npm-rat.yar specimens/` → 4 hits (all expected):
- `_helpers.js` → `WEL1DROPPER_Loader_Behavior` + `WEL1DROPPER_IOC`
- `macos_stage.sh` → `WEL1DROPPER_MacOS_Persistence`
- `wel1dropper-iocs.txt` → `WEL1DROPPER_IOC`

`yara -r wel1dropper-npm-rat.yar benign/` → **0 hits (clean)**.
Benign set (structurally similar, must NOT match):
- `legit-telemetry.js` — real npm telemetry helper reading `process.platform`/
  `process.arch`, posting to a first-party endpoint (fingerprint but no staging).
- `dns-lookup-util.js` — legitimate `dns.resolveTxt` SPF checker (resolveTxt but
  no `wel1.ru`/helper entry).
- `legit-launchagent.sh` — app installer writing its own non-disguised
  LaunchAgent (LaunchAgents+launchctl but no WindowServer impersonation/beacon).

All correctly do not match — the fingerprint/persistence overlaps are held by
the co-occurrence guards.

## Corpus FP test
Budget-bounded slices, one rule per job (single-rule + filesize-guard required),
2026-08-11:
- `WEL1DROPPER_Loader_Behavior` — 6,402 scanned, **0 matches**, 0 read-errors.
- `WEL1DROPPER_IOC` — 11,872 scanned, **0 matches**, 0 read-errors.
- `WEL1DROPPER_MacOS_Persistence` — 11,925 scanned, **0 matches**, 0 read-errors.

Verdict: no false positives on the sampled slices for any of the three rules
(30,199 file-scans total, 0 matches each). Guards verified against benign npm
telemetry / DNS-TXT utilities / legitimate LaunchAgent installers.

## Notes
- No file hashes were published in the primary reporting (domains, Workers
  hosts, file paths and tool names only) — detection is network/behaviour/
  persistence-based, not hash-pinned. Hash pins can be added if a sample set
  surfaces on MalShare/VT.
- Siblings: [[miasma-redhat-npm]], [[ironworm-npm-worm]], [[easydayjs-mastra-rat]]
  (shared npm supply-chain playbook; WEL1DROPPER's novelty is the hookless
  require()-trigger + DNS-TXT chunked staging).
