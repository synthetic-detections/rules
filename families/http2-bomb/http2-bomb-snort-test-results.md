# Test transcript — `http2-bomb.rules`

## Environment

- Engine: **Suricata 7.0.10 RELEASE** (Snort 4 isn't packaged for Debian 13;
  Suricata reads Snort rule syntax natively and ships an HTTP/2 inspector).
- Platform: `Linux host 6.12.88+deb13-amd64 x86_64 GNU/Linux`
- Date: 2026-06-04
- Sources:
  - <https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb>
  - <https://seclists.org/oss-sec/2026/q2/790>
  - <https://thehackernews.com/2026/06/new-http2-bomb-vulnerability-allows.html>

## Synthetic PCAPs

`pcap-gen.py` (scapy) produces two h2c (cleartext HTTP/2) flows over the
same 10.99.0.10:51234 → 10.99.0.20:80 tuple:

| PCAP | Frames | Expected |
|---|---|---|
| `pcaps/benign-h2c.pcap` | preface + SETTINGS_INITIAL_WINDOW_SIZE=65535 + HEADERS GET / | no alerts |
| `pcaps/bomb-h2c.pcap` | preface + SETTINGS_INITIAL_WINDOW_SIZE=0 + HEADERS GET / + 10 × WINDOW_UPDATE inc=1 | sid 9000001 once, sid 9000002/3/10 ≥ 7 times each |

Each WINDOW_UPDATE in the bomb PCAP is delivered in its own TCP PSH/ACK
segment — the worst case for stream-reassembly-based detection (and the
shape the Codex PoC actually produces).

## The dsize trick

First iteration: the `WINDOW_UPDATE` content rule only fired once, even
though the bomb PCAP carries 10 frames. Suricata defaults to stream-payload
inspection, which **deduplicates a repeating content to one match per
reassembled flow**, so `detection_filter` never accumulates events.

Probing with `dsize:13;` (the exact size of a single WINDOW_UPDATE frame)
forced per-packet inspection and the rule then fired once per matching
segment. The drip rules (sids 9000002 and 9000003) carry `dsize:13;` for
this reason. The HTTP/2-aware rule (sid 9000010) doesn't need it because
the app-layer parser counts frames natively.

For batched drips (many WINDOW_UPDATEs packed into one TCP segment), the
`dsize`-pinned byte-content rules will not match — use sid 9000010 or a
production WAF that decodes HTTP/2 frames.

## Run — benign PCAP

```
$ suricata -k none -r pcaps/benign-h2c.pcap -S http2-bomb.rules \
           -l /tmp/suricata-benign --runmode single
$ cat /tmp/suricata-benign/fast.log
(empty)
```

## Run — bomb PCAP

```
$ suricata -k none -r pcaps/bomb-h2c.pcap -S http2-bomb.rules \
           -l /tmp/suricata-bomb --runmode single
$ awk -F'[][]' '/HTTP2-BOMB/ {print $4}' /tmp/suricata-bomb/fast.log | sort | uniq -c
   1 1:9000001:1
   7 1:9000002:2
   7 1:9000003:2
   7 1:9000010:1
```

Stats:

```
tcp.sessions               | Total | 1
detect.alert               | Total | 22
detect.alerts_suppressed   | Total |  9
```

22 alerts = 1 (SETTINGS) + 21 (3 drip rules × 7 alerts each). The 9
suppressed events are the 3 drip rules × 3 events each below the
`detection_filter:track by_src, count 3, seconds 60` threshold — exactly
what we want from rate-based detection.

## Result summary

| sid | What | Bomb alerts | Benign alerts | Verdict |
|---|---|---:|---:|---|
| 9000001 | SETTINGS_INITIAL_WINDOW_SIZE=0 | 1 | 0 | PASS |
| 9000002 | WINDOW_UPDATE inc=1, conn-level (dsize:13) | 7 | 0 | PASS |
| 9000003 | WINDOW_UPDATE inc=1, any stream_id (dsize:13, PCRE) | 7 | 0 | PASS |
| 9000010 | WindowUpdate inc=1 (Suricata HTTP/2 app-layer) | 7 | 0 | PASS |

## Why the benign PCAP is clean

`benign-h2c.pcap` carries:
- SETTINGS_INITIAL_WINDOW_SIZE = **65535** (default), so the 15-byte
  stall-pattern content `00 00 06 04 00 00 00 00 00 00 04 00 00 00 00`
  does not appear. The SETTINGS rule cannot match.
- No WINDOW_UPDATE frames at all. None of the drip rules can match.

## Caveats and what this does not cover

- **TLS-encrypted h2.** The byte-content rules (sids 9000001-9000003)
  cannot see encrypted frames; nor can `http2.frametype`. Deploy at a
  TLS-terminating proxy, or configure Suricata with a keylog file.
- **HPACK Indexed Reference Bomb.** Not modelled here. Suricata's HTTP/2
  parser already enforces header-list-size limits after HPACK
  decompression; pair with `app-layer-event:http2.*` for that leg.
- **Cookie-crumb-splitting bypass (RFC 9113 §8.2.3).** Naive per-field
  limits in vulnerable servers don't count cookie crumbs as fields. This
  is a server-side counting bug, not a wire signature — Suricata can't
  fix it. Patch the server.
- **Production thresholds.** `count 3 / 60 s` is set low for the smoke
  test. Tune to `count 50 / 5 s` (or higher) in production to separate
  Bomb traffic from any legitimate client that occasionally drips small
  WINDOW_UPDATEs.
- **Batched drips.** If an attacker packs many WINDOW_UPDATE frames into
  a single TCP segment (e.g. 100 × 13 bytes = 1300 bytes), `dsize:13;`
  will not match. sid 9000010 (HTTP/2 app-layer) handles that case in
  Suricata; for Snort 3 with the HTTP/2 module, write an equivalent
  using `http2_frame_type`.
- **Synthetic PCAP fidelity.** The scapy-generated PCAPs are minimal but
  correct h2c handshakes — Suricata's HTTP/2 parser successfully decoded
  SETTINGS_INITIAL_WINDOW_SIZE=0 from the bomb PCAP (visible in the
  `eve.json` `http2.request.settings` field). Behaviour against the real
  Codex PoC's wire traffic should match what we see here.
