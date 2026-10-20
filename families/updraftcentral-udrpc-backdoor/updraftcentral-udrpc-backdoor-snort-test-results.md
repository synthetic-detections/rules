# updraftcentral-udrpc-backdoor — Suricata test results

**Date:** 2026-10-20
**Engine:** Suricata 7.0.10 RELEASE
**Rule file:** updraftcentral-udrpc-backdoor.rules (4 sids: 9001001–9001004)

## Rules

| SID | Description |
|---|---|
| 9001001 | CVE-2026-10795 format=1 legacy UDRPC exploit |
| 9001002 | Stolen connection-key command delivery |
| 9001003 | plugin.upload_plugin malicious plugin push |
| 9001004 | OffSeq webshell access (admin888 gate) |

## Compile check

Rules loaded without warnings under `suricata -S`.

## Smoke test

| PCAP | Expected | Result |
|---|---|---|
| attack-udrpc-format1.pcap | 9001001, 9001002 | 9001001, 9001002 |
| attack-udrpc-stolenkey.pcap | 9001002 | 9001002 |
| attack-udrpc-upload.pcap | 9001002, 9001003 | 9001002, 9001003 |
| attack-webshell-offseq.pcap | 9001004 | 9001004 |
| benign-wp-ajax.pcap | (none) | (none) |
| benign-updraft-backup.pcap | (none) | (none) |

**4/4 attack PCAPs alerted correctly, 0/2 benign PCAPs false-positived.**

## Notes

- attack-udrpc-format1.pcap fires both 9001001 and 9001002 because the
  synthetic payload includes both `format=1` and a `.central.updraftplus.com`
  key_name; in the wild the CVE-2026-10795 vector may use a locally-generated
  key without the `.central.updraftplus.com` namespace, firing only 9001001.
- attack-udrpc-upload.pcap fires 9001002 and 9001003; 9001003 is the
  high-confidence rule specifically targeting plugin delivery commands.
