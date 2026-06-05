# Test transcript — `sidecopy-xenofiscal.rules`

## Environment

- Engine: **Suricata 7.0.10 RELEASE**
- Platform: `Linux host 6.12.88+deb13-amd64 x86_64 GNU/Linux`
- Date: 2026-06-04
- Source: <https://www.seqrite.com/blog/operation-xenofiscal-sidecopy-deploying-persistent-xenorat-targeting-the-mof-afghanistan/>

## PCAPs

| PCAP | Shape | Expected |
|---|---|---|
| `pcaps/benign-edu-browse.pcap` | Chrome browsing students.example.edu | no alerts |
| `pcaps/attack-mshta-hta.pcap` | GET `/institute/cloudiya/zuidrt.hta` from abimj.edu.af with mshta-style UA | sids 9000201 + 9000202 |
| `pcaps/attack-xenorat-c2.pcap` | TCP push to 185.235.137.106:4433 | sid 9000203 |

## Results

```
benign-edu-browse        : (clean)
attack-mshta-hta         : 9000201 + 9000202
attack-xenorat-c2        : 9000203
```

Verbatim:

```
[1:9000201:1] XENOFISCAL HTTP request to compromised staging host abimj.edu.af (SideCopy)
[1:9000202:1] XENOFISCAL HTA download via mshta-style User-Agent (SideCopy loader stage)
[1:9000203:1] XENOFISCAL XenoRAT C2 (185.235.137.106 / AS59711 HZ Hosting)
```

## Why the benign case doesn't false-positive

`benign-edu-browse.pcap` has:
- Host header `students.example.edu`, not `abimj.edu.af` — sid 9000201 misses.
- URI `/news/spring-schedule.html`, doesn't end in `.hta` — sid 9000202 misses.
- Destination IP is the synthetic 10.99.0.20, not 185.235.137.106 — sid 9000203 misses.

## Caveats

- **Host IOC may rotate.** `abimj.edu.af` is the publicly attributed
  staging host as of 2026-06-02 disclosure. SideCopy moves staging
  domains regularly — sid 9000202 (mshta-style UA + .hta download) is the
  rotation-resistant signature; sid 9000201 will go stale.
- **mshta User-Agent variants.** The rule keys on `Mozilla/4.0` +
  `Trident` in the User-Agent header, which is the modern Windows mshta
  default. A campaign that customises the UA via the HTA itself would
  evade. Pair with proxy-side anomaly detection.
- **TLS-served HTA.** If the staging host shifts to HTTPS, only the SNI
  is visible — add a TLS rule keyed on `tls.sni; content:"abimj.edu.af";`
  for that.
- **C2 IP only.** sid 9000203 catches *any* traffic to 185.235.137.106;
  the rule classifies anything reaching that host as compromised, which
  is conservative and correct given the attribution.

## Not covered

- **LNK delivery stage** is filesystem, not wire — pair with a YARA rule
  on the Pashto-named LNK pattern if you have an email gateway with
  attachment extraction.
- **XenoRAT C2 protocol fingerprint.** Open-source XenoRAT has a
  documented framing; a dedicated rule on the beacon shape would catch
  XenoRAT activity even after IP rotation. Out of scope here.
