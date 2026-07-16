# RedWing Android MaaS — Test Results

Android malware-as-a-service (Zimperium zLabs, 2026-07). Telegram-rented banking
trojan, assessed as an Oblivion variant. Second Android family in the repository
(after rokarolla-android-banker).

## YARA smoke test (yara 4.5.2)

### Mock specimens (should match)

| File | Rule | Result |
|------|------|--------|
| mock-redwing-dex-behavior.txt | RedWing_MaaS_Behavior | MATCH (all four paths: telemetry schema, USSD forwarding pair, extraction regexes) |
| mock-redwing-ioc-report.txt | RedWing_IOC | MATCH (4 C2/dist domains + Cloudflare Worker) |
| mock-redwing-ioc-report.txt | RedWing_Specimen | MATCH (3 published SHA-256 hashes) |

### Benign (should NOT match)

| File | Rule | Result |
|------|------|--------|
| legit-app-analytics-telemetry.json | all | CLEAN |
| legit-vpn-app-manifest.txt | all | CLEAN |

`legit-app-analytics-telemetry.json` carries device-state keys that overlap the
telemetry rule (`device_id`, `connected_via`, `is_online`, `last_seen`,
`battery_level`) but omits the MaaS-specific `team_id`, so Path 1 (which requires
`team_id` AND `connected_via`) does not fire — and there is no USSD forwarding
pair or regex cluster for the other paths. `legit-vpn-app-manifest.txt` references
`Proton VPN` and requests overlay permission but carries no C2/hash/USSD strings.

## Corpus false-positive test

Each rule was scanned separately against a real-malware corpus slice (2026-07-16):

| Rule | Samples scanned | Matches | Read errors | Verdict |
|------|-----------------|---------|-------------|---------|
| RedWing_MaaS_Behavior | 4,915 | 0 | 0 | clean |
| RedWing_IOC | 9,299 | 0 | 0 | clean |
| RedWing_Specimen | not scanned | — | — | exact SHA-256 pins, zero-FP by construction |

No corpus hits on either the behavioural or IOC rule — no candidate false positives,
no tightening required.

## Rule design notes

**Rule 1 — RedWing_MaaS_Behavior (critical, behavioural).** Three artifact
families, gated by cross-subsystem co-occurrence so no single generic string
anchors a match:
- *C2 telemetry schema* — the per-device registration object. `team_id` (the
  MaaS multi-tenant/subscription key) + `connected_via` is the distinctive pair;
  Path 1 additionally requires two of the device-state keys.
- *Silent call-forwarding* — the `*21*` / `##21#` USSD activate/deactivate pair
  used to divert voice/SMS second factors. Only fires paired with device or
  overlay context (Path 2 / Path 4); neither code anchors alone.
- *Financial-data extraction regexes* — card/CVV/OTP/phone patterns; Path 3
  requires 3 of 4 plus context.

  Confidence: medium. The telemetry keys, USSD codes and regexes are reported
  artifacts from the Zimperium write-up rather than byte-confirmed against a
  sample in hand; the co-occurrence gates trade a little recall for a low
  false-positive rate. True-positive validation against live APKs is deferred
  (no samples retrieved).

**Rule 2 — RedWing_IOC (high, indicator).** C2 hosts (`redwing.top`,
`redwingqq.top`, `krusty-crabs.sbs`, the `mdkd1184.workers.dev` Worker) and
lookalike distribution hosts (`manyrei.live`, `wmanyrei.icu`, `yandex-disk.net`,
`offservers.ru`), verbatim from the Zimperium IOC repo. The masquerade filename
`Proton_VPN.apk` is supporting-only (paired with a domain) to avoid colliding
with the legitimate Proton VPN client. Fragile: breaks on infrastructure
rotation.

**Rule 3 — RedWing_Specimen (critical, pin).** All 103 published APK SHA-256
hashes, matched as text — fires on a sample that embeds its own hash and on IOC
feeds/reports carrying the hashes.

## Campaign context

- No overlap with existing families in the repo. Lineage to the Oblivion MaaS is
  noted by Zimperium; no Oblivion rules exist here yet.
- 82 targeted banking/crypto institutions, Russian-financial weighted.
- Distribution: lookalike hosts serving a fake `Proton_VPN.apk`; C2 over
  WebSocket + HTTP.
- IOC source: Zimperium zLabs (github.com/Zimperium/IOC/tree/master/2026-07-RedWing).
