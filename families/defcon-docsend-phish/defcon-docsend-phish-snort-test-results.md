# Test transcript — `defcon-docsend-phish.rules`

## Environment

- Engine: **Suricata 7.0.10 RELEASE** (Snort-syntax rules, Suricata-native
  `tls.sni` / `dns.query` sticky buffers for the metadata rules).
- Platform: Linux 6.12 x86_64
- Date: 2026-08-22
- Sources:
  - <https://www.huntress.com/blog/defcon-phishing-google-doc-malware>
  - <https://techcrunch.com/2026/08/20/someone-targeted-security-researchers-using-a-fake-crypto-conference-as-a-lure/>

## Rules

| sid | Layer | Signal |
|---|---|---|
| 9000901 | HTTP | `/api/v1/getscpt/` — macOS polling-backdoor config fetch |
| 9000902 | HTTP | `POST /log` to the AMOS panel host 86.54.25.213 |
| 9000903 | HTTP | `/api/launcher/start` on a `web12api.com` host (Electron loader host profile) |
| 9000904 | HTTP | `/get_file?file=` on `eu0Xhub.com` (stage-2 archive retrieval) |
| 9000905 | HTTP | `/api/commands/` on `eu07connect.com` (Ledger Live implant tasking) |
| 9000906 | HTTP | NetSupport `CMD=POLL` body to an `msedgewebview*.pro` gateway (cleartext on 443) |
| 9000907 | TLS | SNI for the delivery / C2 domain set |
| 9000908 | DNS | query for the delivery / C2 domain set |
| 9000909 | IP | any traffic to 86.54.25.213, 192.253.248.181, 87.120.104.88 |

## Synthetic PCAPs

`pcap-gen.py` (scapy, via `families/_lib/h2c_http_helper.py`):

| PCAP | Flow | Expected |
|---|---|---|
| `benign-docsend-browse.pcap` | browser GET `docsend.com/view/…` + `/api/launcher/start` on an unrelated host | no alerts |
| `attack-macos-getscpt.pcap` | GET `/api/v1/getscpt/admin` → 192.253.248.181 | 9000901, 9000909 |
| `attack-macos-exfil.pcap` | POST `/log` → 86.54.25.213 | 9000902, 9000909 |
| `attack-win-launcher.pcap` | POST `/api/launcher/start` Host `docsend.web12api.com` | 9000903 |
| `attack-win-getfile.pcap` | GET `/get_file?file=2Ec6QYynajHw` Host `eu03hub.com` | 9000904 |
| `attack-win-ledger.pcap` | GET `/api/commands/0a1b2c3d` Host `eu07connect.com` | 9000905 |
| `attack-win-netsupport.pcap` | POST `CMD=POLL` Host `msedgewebview1.pro` → 87.120.104.88:443 | 9000906, 9000909 |

## Run

```
$ python3 pcap-gen.py
wrote 1 benign + 6 attack pcaps
$ for p in pcaps/*.pcap; do out=$(mktemp -d); \
    suricata -k none -r "$p" -S defcon-docsend-phish.rules -l "$out" --runmode single; \
    echo "--- $(basename "$p") ---"; awk -F'[][]' '{print $4}' "$out/fast.log" | sort | uniq -c; done
--- attack-macos-exfil.pcap ---
      1 1:9000902:1
      1 1:9000909:1
--- attack-macos-getscpt.pcap ---
      1 1:9000901:1
      1 1:9000909:1
--- attack-win-getfile.pcap ---
      1 1:9000904:1
--- attack-win-launcher.pcap ---
      1 1:9000903:1
--- attack-win-ledger.pcap ---
      1 1:9000905:1
--- attack-win-netsupport.pcap ---
      1 1:9000906:1
      1 1:9000909:1
--- benign-docsend-browse.pcap ---
(empty)
```

All nine signatures parse without error; every `attack-*` PCAP raises its
expected sids and the benign PCAP is silent. The unrelated
`/api/launcher/start` in the benign flow confirms the `web12api.com` host
guard on sid 9000903 is doing its job.

## Notes

- `http_host` is a normalised (lower-cased) buffer in Suricata 7; `nocase` on
  it is a parse error, so host contents are written lower-case. The host
  regex on sid 9000904 uses the `/W` (http_host) pcre flag — `/H` is
  http_header and silently fails to match.
- The TLS/DNS/IP rules (9000907–9000909) are the only coverage for the HTTPS
  paths (`docsend.online`, `eu03hub.com`, `web12api.com`, `eu07connect.com`,
  `*.lat`) without decryption; they are not exercised by the synthetic PCAPs.
