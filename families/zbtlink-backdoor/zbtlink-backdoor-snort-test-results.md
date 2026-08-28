# SPEAKINGSTONE / DARKLANTERN (Zbtlink) — Suricata test results

Rule file: `zbtlink-backdoor.rules` (6 rules, sids 9001101–9001106)
Source: VulnCheck, "ZBT / DarkLantern / SpeakingStone" (2026-08-27)
Authored: 2026-08-28
Environment: Suricata 7.0.10, single runmode, `-k none`

## Rules

- `9001101` — DARKLANTERN inbound command to UDP/9992 carrying `revProto`.
- `9001102` — SPEAKINGSTONE inbound to UDP/10000 carrying `zbtProtocol`.
- `9001103` — SPEAKINGSTONE implant reply from UDP source ports 8897/8898 (`zbtProtocol`).
- `9001104` — DNS query for the C2 domain `ac-link.com`.
- `9001105` — DNS query for the sinkholed C2 domain `findmyipaddr.com`.
- `9001106` — any traffic to the reported C2 IP `47.107.224.89`.

The two UDP port rules gate on the implant proto tags so unrelated UDP to those ports does
not alert. IP `47.107.224.89` is shared with the `endlessdoors-zbtlink-backdoor` family.

## PCAP smoke test

`pcap-gen.py` synthesises the flows (scapy). One alert-per-attack, zero on benign:

```
--- attack-darklantern-9992.pcap ---
[1:9001101:1] ZBTLINK DARKLANTERN inbound UDP/9992 revProto command
--- attack-speakingstone-10000.pcap ---
[1:9001102:1] ZBTLINK SPEAKINGSTONE inbound UDP/10000 zbtProtocol command
--- attack-speakingstone-reply.pcap ---
[1:9001103:1] ZBTLINK SPEAKINGSTONE implant reply from UDP src 8897/8898 (zbtProtocol)
--- attack-c2-dns.pcap ---
[1:9001104:1] ZBTLINK SPEAKINGSTONE C2 domain lookup (ac-link.com)
[1:9001105:1] ZBTLINK C2 domain lookup (findmyipaddr.com, sinkholed)
--- attack-c2-ip.pcap ---
[1:9001106:1] ZBTLINK C2 IP 47.107.224.89 (Alibaba Shenzhen)
--- benign-udp.pcap ---
(no alerts)
```

`benign-udp.pcap` carries unrelated UDP/9992 noise (no proto tag) plus a legitimate
`www.zbt-china.com` DNS lookup — both stay silent, confirming the proto-tag gate and the
exact-domain match.

## Caveats

- Rules operate on plaintext UDP payloads and DNS. If the implant tunnels or encrypts the
  proto tags, the port rules (9001101/9001102/9001103) will miss; the DNS and C2-IP rules
  remain the fallback.
- `findmyipaddr.com` is sinkholed, so 9001105 will mostly flag residual/legacy beacons.
