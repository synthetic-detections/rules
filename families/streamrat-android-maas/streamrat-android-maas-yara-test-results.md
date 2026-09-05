# StreamRat Android MaaS — Test Results

Android banking trojan / infostealer rented as Malware-as-a-Service, pushed
through Meta and TikTok ads to Spanish speakers (ThreatFabric, 2026-09-02).
Third Android family in the repository (after rokarolla-android-banker and
redwing-android-maas).

## YARA smoke test (yara 4.5.2)

### Mock specimens (should match)

| File | Rule | Result |
|------|------|--------|
| mock-streamrat-dex-behavior.txt | StreamRat_Behavior | MATCH (Paths 1, 2, 3 and 4) |
| mock-streamrat-dex-behavior.txt | StreamRat_IOC | MATCH (package name + C2 IP) |
| mock-streamrat-ioc-report.txt | StreamRat_IOC | MATCH (packages, IPs, labels + lure) |
| mock-streamrat-ioc-report.txt | StreamRat_Specimen_Pin | MATCH (both published SHA-256) |

### Benign (should NOT match)

| File | Rule | Result |
|------|------|--------|
| legit-websocket-sdk-config.json | all | CLEAN |
| legit-screen-mirror-app-manifest.txt | all | CLEAN |

`legit-websocket-sdk-config.json` carries `X-Device-Id` plus a `wss://` endpoint,
which is the common benign shape; Path 1 needs the full `X-Device-Id` /
`X-Device-Model` / `X-Api-Level` triplet, so it does not fire.
`legit-screen-mirror-app-manifest.txt` references MediaProjection, an
Accessibility service, an `update_` asset and `X-Device-Model`, but has no
`injections` directory, no VpnService, only one bespoke-page candidate and only
one header — every path stays below threshold.

## Corpus false-positive test

Each rule was scanned separately against a real-malware corpus slice (2026-09-05):

| Rule | Samples scanned | Matches | Read errors | Verdict |
|------|-----------------|---------|-------------|---------|
| StreamRat_Behavior | 5,056 | 0 | 0 | clean |
| StreamRat_IOC | 9,470 | 0 | 0 | clean |
| StreamRat_Specimen_Pin | not scanned | — | — | exact SHA-256 pins, zero-FP by construction |

No corpus hits on either the behavioural or IOC rule — no candidate false
positives, no tightening required.

## Rule design notes

**Rule 1 — StreamRat_Behavior (critical, behavioural).** Three artifact
families, each gated by co-occurrence:
- *WebSocket registration headers* — the `X-Device-Id` / `X-Device-Model` /
  `X-Api-Level` triplet sent on C2 registration. Only the full triplet plus a
  WebSocket transport marker anchors Path 1 (`X-Device-Id` alone is a common
  analytics-SDK header).
- *HTML dropper page set* — `set_launcher.html`, `vpn_required.html`,
  `r1edmi.html`; Path 2 needs two of the three plus the payload filename
  (`app.apk` / `update_`).
- *Overlay + capture cluster* — the `injections` overlay directory,
  MediaProjection (VNC), Accessibility service / `takeScreenshot` (HVNC) and
  the kill-switch VpnService; Path 3 needs all of them plus one C2 header,
  Path 4 needs the header triplet plus injections and a capture route.

  Confidence: medium. All strings are reported artifacts from the vendor
  write-up, not byte-confirmed against a sample in hand (neither published hash
  was retrievable at authoring time); the gates trade recall for a low
  false-positive rate.

**Rule 2 — StreamRat_IOC (high).** Package names and C2 IPs (all `fullword`)
anchor alone; the app labels and the ad-campaign name only count in pairs.

**Rule 3 — StreamRat_Specimen_Pin (critical).** The two published APK SHA-256
hashes as text — fires on samples carrying the hash and on IOC feeds / reports.

## Campaign overlap

ThreatFabric ties StreamRat's distribution infrastructure to a GitHub
repository previously used for the Mirax trojan; no Mirax rules exist in this
repository yet. No shared C2 with [[redwing-android-maas]] or
[[rokarolla-android-banker]].
