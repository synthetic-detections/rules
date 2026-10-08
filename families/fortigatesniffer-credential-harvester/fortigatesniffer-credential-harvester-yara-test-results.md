# FortigateSniffer Credential Harvester — YARA Test Results

## Environment

- YARA 4.5.2, Debian 13 (trixie)
- Rule file: `fortigatesniffer-credential-harvester.yar` (3 rules)
- Specimens: 2 synthetic (ELF + PE with campaign strings)
- Benign: 1 synthetic (Go network tool without sniffer-specific strings)

## Source

- [CybersecurityNews — FortigateSniffer tool analysis](https://cybersecuritynews.com/fortigatesniffer-tool-fortibleed/)
- [FBI/SS joint warning — FortiBleed remains active](https://thehackernews.com/2026/10/fbi-warns-fortibleed-remains-active.html)
- Campaign: FortiBleed — Russian-speaking IAB harvesting Fortinet credentials, feeding INC/Lynx/Payload ransomware
- Tool: FortigateSniffer (fg_sniffer), Go-based, Linux + Windows variants
- Companions: mpbrute2.bin, forticheck, gen_rotator, spray_da.py

## Compile check

```
yara -w fortigatesniffer-credential-harvester.yar /dev/null
→ 3 rules loaded, 0 errors, 0 warnings
```

## Specimen tests (should alert)

| Specimen | Rules matched | Strings hit |
|----------|--------------|-------------|
| fg_sniffer_sim_elf.bin | Behavioural, IOC | 13 strings (sniffer, diag, protos, C2) |
| fg_sniffer_sim_pe.bin | Behavioural, IOC | 10 strings (sniffer, diag, protos, tools) |

## Benign tests (should NOT alert)

| Benign | Alerts | Notes |
|--------|--------|-------|
| go_network_tool.bin | 0 | ELF with protocol names but no sniffer strings |

## Rule logic

| Rule | Detection | Confidence |
|------|-----------|------------|
| FortigateSniffer_Behavioural | PE/ELF with fg_sniffer + diagnostic sniffer command, or sniffer name + 3+ protocol targets, or Go build + diagnostic + protocols | Critical — distinctive tool name + FortiOS command combo |
| FortigateSniffer_IOC | Co-occurrence of campaign file names, C2 subnet prefixes, and tooling names | High — subnet prefixes could alias, guarded by co-occurrence |
| FortigateSniffer_Specimen | SHA-256 hash pin for 4 known samples | Critical — exact match only |

## Corpus FP test

Corpus FP scan pending.
