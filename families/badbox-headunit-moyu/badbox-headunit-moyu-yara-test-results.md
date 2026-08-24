# badbox-headunit-moyu — YARA test results

Family: BADBOX / MoYu Group Android automotive head-unit malware (Securelist, 2026-08).
Rules: `MoYu_BADBOX_HeadUnit_Behavior` (critical), `MoYu_BADBOX_HeadUnit_IOC` (high),
`MoYu_BADBOX_HeadUnit_Specimen` (critical).

## In-repo smoke test (2026-08-24)

Command: `yara -r badbox-headunit-moyu.yar specimens/` and `... benign/`.

Specimens — all three rules match the reconstructed decompiled-strings specimen:

```
MoYu_BADBOX_HeadUnit_Behavior  specimens/moyu-headunit-decompiled-strings.txt
MoYu_BADBOX_HeadUnit_IOC       specimens/moyu-headunit-decompiled-strings.txt
MoYu_BADBOX_HeadUnit_Specimen  specimens/moyu-headunit-decompiled-strings.txt
```

Benign — clean (no matches), including a **legitimate TWCore-only build**
(`com.tw.core`, the malware's distribution vector) which the rules deliberately do
NOT key on, a generic Android billing/ads app, and an unrelated proxy/ad-network
SDK that shares the theme but none of the distinctive tokens:

```
(no output — benign/ produced zero hits)
```

Design notes:
- `com.tw.core` (legit TWCore) is excluded from the Behavior rule's strong-token
  set; only the malware-unique `com.tw.jar1`, `mosdk-host-loader`, `AdmoyuService`,
  `com.ast.sdk.BillingMain`, `com.miyc.transfer.Client`, `com.c.j.qbh` count, with a
  3-of threshold.
- The IOC rule is co-occurrence guarded (2 C2 domains, or a domain + an API path,
  or 2 API paths) so a single stray host cannot fire.
- The Specimen rule pins the three rarest tokens (loader thread + MoYu service +
  Zhima client), all present together only in this malware.

## Corpus FP test (2026-08-24)

Each rule was scanned independently against a slice of the malware sample corpus.
All three came back clean:

| Rule                            | Samples scanned | Matches | Read errors | Verdict |
|---------------------------------|-----------------|---------|-------------|---------|
| MoYu_BADBOX_HeadUnit_Behavior   | 5,379           | 0       | 0           | clean   |
| MoYu_BADBOX_HeadUnit_IOC        | 11,794          | 0       | 0           | clean   |
| MoYu_BADBOX_HeadUnit_Specimen   | 11,011          | 0       | 0           | clean   |

Verdict: **no false positives.** The malware-unique class/thread/service tokens
and the co-occurrence-guarded C2 set produce no corpus collisions.
