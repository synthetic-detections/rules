# PEERSTITCH FortiGate Implant — YARA Test Results

## Environment

- YARA 4.5.2, Debian 13 (trixie)
- Rule file: `peerstitch-fortigate-implant.yar` (3 rules)
- Specimens: 2 synthetic (ARM64 ELF implant carrying the injector byte templates + daemon/proc artifacts; JS/WASM stager)
- Benign: 2 synthetic (ARM64 ELF that legitimately names the FortiOS daemons; a real ACME/Node helper)

## Source

- [Unit 42 — PEERSTITCH, a stealthy FortiGate implant (CVE-2024-47575 + CVE-2025-61624)](https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware.md)
- [securityonline.info — FortiOS PEERSTITCH malware via FortiManager](https://securityonline.info/fortios-peerstitch-malware-fortimanager/)
- Cluster: CL-STA-0954 (Unit 42) / UNC5820 (Mandiant), suspected nation-state overlap
- Behaviour: one-shot process-memory patcher injecting `/bin/miglogd` + `/bin/iked`; no on-disk binary, no listening port, no outbound C2; Emscripten/WASM + Node.js stager

## Compile check

```
yara -w peerstitch-fortigate-implant.yar /dev/null
→ 3 rules loaded, 0 errors, 0 warnings
```

## Specimen tests (should alert)

| Specimen | Rules matched | Notes |
|----------|--------------|-------|
| peerstitch_implant_arm64.elf | Behavioural, IOC | ARM64 ELF; mmap/injector byte templates + `/proc/%d/mem` + daemon paths + ACME cover |
| peerstitch_stager.js | IOC | stager filenames (pM.js/ipssem.js/lldprx) + ACME cover + staging dir + C2 IPs |

## Benign tests (should NOT alert)

| Benign | Alerts | Notes |
|--------|--------|-------|
| fortios_daemon_strings_arm64.elf | 0 | ARM64 ELF naming miglogd/iked but no injector bytes, no `/proc/%d/mem`, no cover |
| acme_node_helper.js | 0 | genuine ACME client; no campaign cover path/body, no stager filenames, no C2 |

## Rule logic

| Rule | Detection | Confidence |
|------|-----------|-----------|
| PEERSTITCH_Behavioural | ARM64 ELF + injector byte templates co-occurring with `/proc/%d/mem` and the injected daemons | critical |
| PEERSTITCH_IOC | co-occurring IOC strings: ACME cover path/body, staging dir, path-traversal names, stager filenames, C2 IPs (guarded by co-occurrence) | high |
| PEERSTITCH_Specimen | SHA-256 pin of the 7 Unit 42 samples | critical |

Design notes: the behavioural rule is pinned to `EM_AARCH64` ELF so it cannot fire on unrelated
x86 malware; byte-template matches alone require two independent templates (or one template plus
the `/proc/%d/mem` write path) to fire. The IOC rule never fires on the FortiOS daemon names
alone — those appear in legitimate firmware — but requires the ACME-cover combination, the
staging directory with a stager filename, or multiple C2 markers.

## Corpus FP test

Corpus FP scan of the broadest rule (PEERSTITCH_Behavioural) against a corpus slice:
**6,914 samples scanned, 0 matches, 0 read errors** — clean, no false positives. The
specimen-pin rule is hash-only (no FP surface) and the IOC rule is guarded by string
co-occurrence; the behavioural rule is the one with any breadth, and it stayed silent across
the slice. Benign ARM64 ELF that names the FortiOS daemons also stays clean locally, which is
the main structural-collision risk. Verdict: no tightening needed.

## Campaign overlap

Shares the Fortinet-appliance target surface with `fortigatesniffer-credential-harvester` and
`fortisandbox-jsonrpc-cve-2026-39813`, but PEERSTITCH is a distinct in-memory ARM64 implant
(no credential-sniffer strings, no JSON-RPC artifacts) — no rule-overlap expected.
