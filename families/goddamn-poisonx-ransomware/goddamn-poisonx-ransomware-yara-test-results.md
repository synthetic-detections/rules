# GodDamn + PoisonX — YARA test results

Source: Symantec Threat Hunter Team / Broadcom
(https://www.security.com/blog-post/goddamn-ransomware-beast-rebrand);
The Hacker News, 2026-07-09.

Rules validated with YARA 4.5.2.

## Rules

| rule | severity | anchors |
|---|---|---|
| `GodDamn_Ransomware_Binary` | critical | PE + `.God8Damn` extension / `encrypter-windows-gui-x86.exe`; `God8Damn` only with Beast/Monster lineage |
| `PoisonX_Signed_BYOVD_Driver` | critical | PE + `g11.sys` with driver kill-APIs, or abused signer **only** alongside ≥2 kernel-kill APIs |
| `GodDamn_IOC` | high | `AnyDesk_D-Drive Service` + `D:\ad_data` masquerade, AnyDesk relay C2s |

## Discrimination logic

- "Microsoft Windows Hardware Compatibility Publisher" is a legitimate signer
  string on countless benign drivers — it is never allowed to match alone; the
  PoisonX rule needs `g11.sys` **or** two kernel process-kill APIs with it.
- "AnyDeskService" and AnyDesk itself are legitimate — the IOC rule keys on the
  attacker-specific second service `AnyDesk_D-Drive Service` and its `D:\ad_data`
  path, and requires two relay C2s together rather than any single IP.
- `.God8Damn` and the GUI encrypter name are specific enough to stand alone;
  the bare `God8Damn` token needs the Beast/Monster lineage marker.

## Smoke test (in-repo)

```
$ yara -r goddamn-poisonx-ransomware.yar specimens/   # expect hits
GodDamn_IOC                  specimens/goddamn_anydesk_ioc.txt
GodDamn_Ransomware_Binary    specimens/goddamn_encrypter.bin
PoisonX_Signed_BYOVD_Driver  specimens/poisonx_g11_driver.sys

$ yara -r goddamn-poisonx-ransomware.yar benign/      # expect none
(clean)
```

`benign/` covers the discriminators: a legitimately-signed driver carrying the
same publisher string plus one kernel callback (below the 2-API threshold), a
real AnyDesk install with the genuine `AnyDeskService`, a game text mentioning
"Beast"/"Monster", and an AV signature-DB blob naming the family in lowercase
(case-sensitive extension token does not fire). None match.

## Corpus FP test

PENDING — the corpus scan was unavailable at author time. To be run against the
malware corpus when available. Watch `PoisonX_Signed_BYOVD_Driver` in particular
— the signer string is common, so any corpus hit there is a candidate FP to
tighten. Result to be recorded here as a short high-level table.
