# ToxNet v2 — Suricata test results

Rule file: `toxnetv2.rules` (3 rules, sids 9001201–9001203)
Source: Joe Security (Joe Sandbox), 2026-08-25
Authored: 2026-08-28
Environment: Suricata 7.0.10, single runmode, `-k none`

## Rules

- `9001201` — HTTP GET for the payload `kaf.sh` at the distinctive URI path
  `/z0l1mxjm4mdl4jjfjf7sb2vdmv/kaf.sh` (host-independent; survives delivery-host rotation).
- `9001202` — any traffic to the payload-delivery host `45.151.139.113`.
- `9001203` — any traffic to the Tox C2 node `45.130.151.214` (Tox DHT 33445 / HTTPS 443).

## PCAP smoke test

`pcap-gen.py` synthesises the flows (scapy). One-or-more alert per attack, zero on benign:

```
--- attack-kaf-delivery.pcap ---
[1:9001202:1] TOXNETV2 payload-delivery host 45.151.139.113
[1:9001201:1] TOXNETV2 payload delivery HTTP GET (kaf.sh at z0l1mxjm4mdl4jjfjf7sb2vdmv path)
--- attack-c2-ip.pcap ---
[1:9001203:1] TOXNETV2 Tox C2 node 45.130.151.214 (DHT 33445 / HTTPS 443)
--- benign-shell-fetch.pcap ---
(no alerts)
```

`benign-shell-fetch.pcap` is a plain `GET /scripts/setup.sh` from an unrelated mirror — a
generic `.sh` fetch without the ToxNet path token and to neither hardcoded IP, so it stays
silent. This confirms `9001201` keys on the full distinctive path (not bare `kaf.sh`).

## Why no YARA rule

ToxNet v2 ships **without a YARA rule**, by design:

- Joe Security published **no file hashes**, so there is no specimen to hash-pin.
- The only high-entropy static token is the URL path segment
  `z0l1mxjm4mdl4jjfjf7sb2vdmv/kaf.sh` — a delivery/network artifact matched far more
  reliably on the wire (rule `9001201`) than as a loose binary string.
- The remaining candidate static strings — `c2.data` (Tox state file) and `kaf.sh` — are
  too generic to anchor a YARA rule without an unacceptable false-positive rate, and the
  hardcoded IPs are already covered by the IP rules.
- No further binary-internal strings were invented to pad a rule.

A Suricata-only family is the correct shape here. If a sample surfaces (a hash, or the
AArch64 loader binary), a hash-pinned YARA rule should be added.

## Caveats

- Tox C2 traffic is encrypted P2P; `9001203` is IP reputation, not content inspection, and
  will erode if the operator rotates the node.
- The LLM controller (NVIDIA NIM, model `z-ai/glm-5.2`) is operator-side and not observable
  from victim network traffic, so it is documented for context only, not detected.
