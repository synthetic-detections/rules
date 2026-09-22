# brevo-clickfix-cdn-2026 — YARA + Suricata test results

Family: `brevo-clickfix-cdn-2026`
YARA rules: `BREVO_ClickFix_Injected_Loader` (critical), `BREVO_IOC` (high), `BREVO_WP_Admin_Plugin_Drop` (critical)
Suricata: `brevo-clickfix-cdn-2026.rules` (sids 2026092201-2026092205)
Date: 2026-09-22

## YARA smoke test (in-repo)

Specimens (should match):

| file | rules hit |
|---|---|
| specimens/brevo-injected-f.js | ClickFix_Injected_Loader, IOC, WP_Admin_Plugin_Drop |
| specimens/brevo-iocs.txt | IOC |

Benign (should stay clean):

| file | result |
|---|---|
| benign/legit-widget-loader.js | clean (legit async script loader, different CDN) |
| benign/legit-wp-plugin-upload.js | clean (first-party plugin, no wm.zip / no sendibt1) |

Result: all specimens hit, both benign files clean.

## Suricata

All five signatures load cleanly under `suricata -T` on this host. Coverage:
DNS query and TLS SNI to the sendibt1.com staging CDNs, the injected `/f.js`
loader fetch, the `/api/v1/<hex>` C2 endpoints, and the `wm.zip` WordPress
backdoor-plugin fetch.

## Design notes

- `ClickFix_Injected_Loader` keys on the injected `createElement("script")`
  loader pointing at a sendibt1.com `/f.js` — the reusable behavioural anchor.
- `IOC` needs >=2 hard indicators (staging CDNs, hex C2 endpoints, `wm.zip`
  path) to stay clean on IOC docs.
- The sendibt1.com infra went NXDOMAIN after 2026-09-15, so the network rules
  are retro/hunt value; the injected-loader YARA rule is the forward detector.

## Corpus FP test

Corpus false-positive scan pending.
