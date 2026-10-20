# UpdraftCentral UDRPC backdoor — YARA test results

Family: `updraftcentral-udrpc-backdoor`
Rule file: `updraftcentral-udrpc-backdoor.yar`
Author: synthetic-detections
Date: 2026-10-20
Disclosure: 2026-10-19 (TeamUpdraft key compromise; CVE-2026-10795 exploitation since July 2026)

## Rules

1. `UpdraftCentral_UDRPC_Webshell` (critical, behavioural) — detects both webshell variants
   by operational shape. Variant A (OffSeq): `postpass2` + `admin888` + one of (`myXorSecret`,
   `system(`, `b64data`). Variant B (auth-cookie backdoor): `wp_set_auth_cookie` + `hash_equals`
   + `pre_user_query` + `pre_count_users`. Either variant fires independently.
2. `UpdraftCentral_UDRPC_IOC` (high) — campaign-specific IOCs. The globally unique description
   `Small maintenance toolkit: keeps option storage tidy.` fires standalone. Other tokens
   (User-Agent, UDRPC callback, command names, usernames) require co-occurrence clusters.
3. `UpdraftCentral_UDRPC_Specimen` (critical, specimen-pin) — SHA-256 pins for 9 known samples
   (6 from October Wordfence PSA, 3 from OffSeq CVE-2026-10795 analysis), plus a size-band
   (3000–5000 bytes) + `postpass2` + `system(` heuristic for the compact webshell family.

## Recorded hashes

October campaign (Wordfence PSA):
- opt4fix 2.9.2: `54ca7b2d…7d8d5c`
- js-fix-757a 2.8.3: `2cdf3f2a…12b47a`
- lazy-tool-3055 1.3.8: `1821a58e…62969ec`
- cache-smith 1.3.1: `43dc88fd…69c49`
- style-bridge-8f5 2.6.6: `0290c2ba…fdacde`
- style-bridge-8f5/uninstall.php: `99a7fb44…5a0a5`

CVE-2026-10795 campaign (OffSeq):
- PHP payload: `ac87d574…3a6cabe`
- ZIP package: `8e8d8887…fdacde`
- POST body: `3b321d1d…f243a4`

## In-repo smoke test

Command: `yara -r updraftcentral-udrpc-backdoor.yar specimens/` and `… benign/`

Specimens (should match — all pass):
- `specimens/variant-a-webshell.php` → `UpdraftCentral_UDRPC_Webshell` + `UpdraftCentral_UDRPC_IOC` (via description string) ✅
- `specimens/variant-b-authcookie.php` → `UpdraftCentral_UDRPC_Webshell` ✅
- `specimens/campaign-ioc-log.txt` → `UpdraftCentral_UDRPC_IOC` ✅
- Rule 3 (`UpdraftCentral_UDRPC_Specimen`) fires only on exact hashes or the size-band
  heuristic; synthetic specimens do not match by design (their hashes differ from
  the in-the-wild samples). The hash pins are validated by construction from public
  disclosures.

Benign (structurally similar — must NOT match, all clean):
- `benign/legitimate-user-query-filter.php` — legitimate plugin using `pre_user_query` and
  `pre_count_users` for admin-screen filtering, without auth-cookie or hash-validation calls.
  Confirms rule 1 variant B requires the full four-string conjunction. ✅ no match
- `benign/updraftplus-legitimate-rpc.php` — legitimate UpdraftPlus code fragment showing the
  UDRPC callback registration (`updraft_central_ajaxcallback`). Contains the callback string
  but lacks `plugin.upload_plugin` and the malicious User-Agent, so the IOC rule's cluster
  guard prevents a match. ✅ no match
- `benign/generic-system-info.php` — legitimate plugin using `system()` for server diagnostics.
  Has the exec call but none of the OffSeq webshell markers. ✅ no match

Result: 4/4 specimen-rule matches across the expected rules; 0/3 benign files matched.

## Known residual FP risk

`UpdraftCentral_UDRPC_Webshell` variant A fires on any PHP file under 100 KB containing
`postpass2` + `admin888` + one of the operational strings. These are distinctive enough that
benign collision is unlikely, but a security-test harness or writeup embedding these markers
in a single PHP file could produce a match. Accepted as behavioural coverage.

`UpdraftCentral_UDRPC_IOC` fires standalone on the description `Small maintenance toolkit:
keeps option storage tidy.` — this is a vendor-reported exact string from the campaign. A
benign plugin using that exact description would be a false positive, which is implausible.

## Corpus FP test

PENDING — samples not yet available on MalShare; corpus scan will be recorded when specimens
are obtainable or the next corpus refresh includes this campaign window.
