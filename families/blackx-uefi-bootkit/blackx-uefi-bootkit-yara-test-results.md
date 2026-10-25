# BlackX UEFI Bootkit — YARA Test Results

## Environment

- OS: Debian 13 (trixie), x86_64
- YARA: 4.5.x
- Suricata: 7.0.10

## Sources

- [Kaspersky Securelist — BlackX UEFI bootkit](https://securelist.com/uefi-bootkit-blackx/121539/)
- [BleepingComputer — BlackX exploits Baton Drop](https://www.bleepingcomputer.com/news/security/blackx-uefi-bootkit-exploits-baton-drop-flaw-to-bypass-secure-boot/)

## Rules

| Rule | Severity | Detection basis |
|------|----------|-----------------|
| BlackX_OxiDLLRunner_Behavioural | critical | OxiDLLRunner sideloading pattern + plugin loader strings |
| BlackX_IOC | high | Campaign-specific IOCs with co-occurrence (≥2 of 8 indicators) |
| BlackX_Specimen | critical | MD5 hash pin on known sideloading host binary |

## Compile check

```
$ yara -w blackx-uefi-bootkit.yar /dev/null
(clean, no warnings)
```

## Specimen test

```
$ yara -r -s blackx-uefi-bootkit.yar specimens/
BlackX_OxiDLLRunner_Behavioural specimens/synth-blackx-oxidllrunner.bin
BlackX_IOC specimens/synth-blackx-oxidllrunner.bin
```

Both string-based rules fire on the synthetic specimen. Specimen pin (rule 3)
does not fire because the synthetic PE has a different hash than the real
sample — this rule will activate only against the actual malicious binary
(MD5 af8a983b9ada07eae1259bf2953abd40), which is not publicly available yet.

## Benign test

```
$ yara -r -s blackx-uefi-bootkit.yar benign/
(no output — clean)
```

Benign PE with `v8_context_snapshot.bin` string alone does not trigger either
rule due to co-occurrence requirements.

## Suricata test

```
attack-dns-archivetj.pcap  → sid:9001001 BLACKX C2 DNS lookup ✓
attack-tls-archivetj.pcap  → sid:9001002 BLACKX C2 TLS SNI ✓
benign-dns-example.pcap    → (no alerts) ✓
benign-tls-example.pcap    → (no alerts) ✓
```

## Corpus FP test

Corpus FP scan pending.
