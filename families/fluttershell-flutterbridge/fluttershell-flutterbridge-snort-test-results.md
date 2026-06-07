# Test transcript — `fluttershell-flutterbridge.rules`

## Environment

- Engine: **Suricata 7.0.10 RELEASE**
- Date: 2026-06-07
- Source: <https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/>

## Synthetic PCAPs

| PCAP | Shape | Expected |
|---|---|---|
| `pcaps/benign-news-browse.pcap` | HTTP GET to `news.example.com/article/123` from a normal Safari UA | no alerts |
| `pcaps/attack-fluttershell-config.pcap` | HTTP GET to `atsheisdomestic.org/getConfig` from a `FlutterShell WebView` UA | sid 9000402 |

## Results

```
$ python3 pcap-gen.py
$ suricata -k none -r pcaps/benign-news-browse.pcap -S fluttershell-flutterbridge.rules -l /tmp/sout-bn --runmode single
$ cat /tmp/sout-bn/fast.log
(empty)

$ suricata -k none -r pcaps/attack-fluttershell-config.pcap -S fluttershell-flutterbridge.rules -l /tmp/sout-at --runmode single
$ cat /tmp/sout-at/fast.log
[1:9000402:1] FLUTTERSHELL HTTP fetch of WebView JS-bridge config or AI exfil endpoint
```

| PCAP | Expected | Observed |
|---|---|---|
| benign-news-browse | 0 alerts | 0 |
| attack-fluttershell-config | ≥1 alert | 1 (sid 9000402) |

## Three rules, three surfaces

- **sid 9000401 — TLS SNI.** Fires on TLS handshakes where SNI matches
  one of the four FlutterBridge C2 hostnames. Catches encrypted h2/h3
  fetches that the HTTP rule can't see. Not exercised in the smoke
  test (synthetic h1 PCAP) but compiles + loads cleanly.
- **sid 9000402 — HTTP path.** Fires on the five known C2 paths
  (`/update-thanks.html`, `/api/update-delay`, `/getConfig`,
  `/getUpdateThanksConfig`, `/summarize-text`). Fired correctly on the
  attack PCAP, silent on the benign.
- **sid 9000403 — DNS query.** Fires on DNS queries for one of the four
  C2 hostnames. Not exercised in the smoke test (PCAPs are
  TCP-only) but compiles + loads cleanly.

## Why benign stays clean

`benign-news-browse.pcap` requests `news.example.com/article/123` —
no FlutterShell C2 hostname, no C2 path, no SNI match. The PCRE on
sid 9000402 anchors path beginnings (`\/(update-thanks\.html|…)`); a
normal article URL doesn't fit the pattern.

## Caveats

- **C2 hostnames will sinkhole and rotate.** sid 9000401 + 9000403
  catch the four published hosts; expect rotation within days of
  disclosure. The path-shape rule (sid 9000402) is the rotation-
  resistant fallback — the JS payload library hardcodes those paths
  and changing them costs the operator a re-deploy.
- **TLS-encrypted h2/h3.** TLS rule sees SNI but not path. HTTP path
  rule fires only on cleartext h1 or at a TLS-terminating proxy.
- **Synthetic PCAPs.** The benign and attack PCAPs are scapy-built
  three-way handshakes + a single GET. Real-world FlutterShell traffic
  will include the WebView's own User-Agent in the actual TLS-decrypted
  request; the rule doesn't anchor on UA because Unit 42 didn't quote
  a verbatim UA string and the apps reuse stock WKWebView UA on macOS.
