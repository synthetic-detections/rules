# steam-clickfix-xmrig — test results

Family: Steam forum ClickFix → XMRig cryptominer
First reported: 2026-07-25 (BleepingComputer, unattributed cryptojacking)
Rules authored: 2026-07-27

## Rules

- `Steam_ClickFix_XMRig_Dropper` (critical) — the ClickFix PowerShell dropper:
  "msf utility / PC Opt" lure + Defender exclusion on `C:\Windows\Background` +
  payload fetch from `msfconfig[.]icu` + `XMRig-<host>` scheduled task. All paths
  require co-occurrence of a campaign anchor.
- `Steam_ClickFix_XMRig_Config` (high) — XMRig `config.json` pinned to the campaign
  install dir / C2 (generic XMRig config markers gated by a campaign anchor).
- `Steam_ClickFix_XMRig_IOC` (critical) — hard IOCs: C2 domain, payload URL, and the
  two full install-path artefacts.
- Suricata: `steam-clickfix-xmrig.rules` — TLS SNI + DNS for `msfconfig[.]icu`, and an
  HTTP fallback for the `/tmp/system.txt` payload path. Validated with
  `suricata -T` (7.0.10, config loaded successfully).

## Smoke test (in-repo)

Specimens (should match):
```
Steam_ClickFix_XMRig_Config   specimens/config.json
Steam_ClickFix_XMRig_IOC      specimens/config.json
Steam_ClickFix_XMRig_Dropper  specimens/msf_pc_opt_dropper.ps1
Steam_ClickFix_XMRig_IOC      specimens/msf_pc_opt_dropper.ps1
Steam_ClickFix_XMRig_Dropper  specimens/iocs.txt
Steam_ClickFix_XMRig_IOC      specimens/iocs.txt
```
Benign (should NOT match): clean — `legit_xmrig_config.json` (real XMRig config, no
campaign anchor) and `legit_debloat.ps1` (real admin script using Add-MpPreference +
schtasks) both produce no hits.

Result: PASS. One iteration needed — an early benign specimen falsely matched because its
own explanatory comments quoted the campaign anchor strings; comments rewritten to drop the
literal IOCs, benign now clean.

## Corpus FP test

PENDING — the corpus-scan service was unreachable at authoring time (connection
timed out on both `scan --detach` and `status`). Re-run when the service is back:
a corpus false-positive scan.
Any hit on this recent family is a candidate FP. Anchors are campaign-specific
(`C:\Windows\Background`, `msfconfig[.]icu`, `/tmp/system.txt`, the "msf utility/PC Opt"
lure, `XMRig-<host>` task) with co-occurrence guards, so broad corpus FPs are not expected;
the generic-XMRig `Config` rule is the one to watch since real miner configs are common —
it is gated on a campaign anchor to suppress those.

## Notes

- No file hashes were published by the vendor, so there is no specimen pin by hash and
  nothing was added to the digest hash store for this family.
- Related ClickFix families in-repo: golden-chickens-maas, uac0145-sandworm-clickfix.
