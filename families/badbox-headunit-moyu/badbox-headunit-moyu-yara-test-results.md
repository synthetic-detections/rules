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

## Corpus FP test

Status: **PENDING** — a corpus false-positive scan (`--max-hits 40 --budget 15m`)
was launched against the sample corpus after the smoke test. Result to be recorded
here on completion (samples scanned / matches / read-errors / verdict). The rule
tokens are highly distinctive (malware-unique class/thread/service names), so a
clean corpus pass is expected; any hit is a candidate FP to investigate.
