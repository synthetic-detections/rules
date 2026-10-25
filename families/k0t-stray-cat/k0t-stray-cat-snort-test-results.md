# k0t / Stray Cat — Suricata test results

**Family:** k0t-stray-cat
**Source:** https://www.group-ib.com/blog/stray-cat-network-edge/
**Date:** 2026-10-25

## Environment

- Suricata 7.0.10
- Rules: `k0t-stray-cat.rules` (6 sids: 2026102501–2026102506)

## PCAP generation

```
python3 pcap-gen.py
→ 4 PCAPs: attack-dns-staging, attack-dns-meshcentral, attack-tcp-adaptixc2, benign-dns-unrelated
```

## Attack PCAPs

| PCAP | SIDs fired | Notes |
|------|-----------|-------|
| attack-dns-staging | 2026102501 ×4 | All 4 staging domains detected |
| attack-dns-meshcentral | 2026102505 ×2 | Both MeshCentral C2 domains detected |
| attack-tcp-adaptixc2 | — | TCP rule requires $HOME_NET config |

## Benign PCAPs

| PCAP | Alerts |
|------|--------|
| benign-dns-unrelated | 0 |

## Notes

- DNS rules (sids 501, 505) fire correctly on all campaign domains
- TLS SNI rules (sids 502, 506) require TLS traffic — not testable with plain DNS PCAPs
- TCP IP-match rules (sids 503, 504) require `$HOME_NET` to include source subnet
- All benign traffic silent as expected
