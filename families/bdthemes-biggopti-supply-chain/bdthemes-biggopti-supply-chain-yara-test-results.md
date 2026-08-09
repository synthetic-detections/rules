# BdThemes / Biggopti supply-chain — YARA test results

Rule file: `bdthemes-biggopti-supply-chain.yar` (3 rules)
Family: `bdthemes-biggopti-supply-chain`
Source: Wordfence PSA, 2026-08-08.

## Rules
1. `Biggopti_Poisoned_Banner_Payload` (critical) — the poisoned banner-JSON / stager
   shape: `onanimationstart` id-attribute breakout **or** `eval(String.fromCharCode(...))`
   / `new Function(t)()` stager, gated on a Biggopti/Sigmative context anchor.
2. `Biggopti_Dropped_Webshell_Backdoor` (critical) — on-disk PHP artifacts: named
   drop files (`emer-run.php`, `wp-smart-thumbnails`, `wp-cache-optimizer.php`,
   `class-wp-token-validate.php`), the `?_wplogin` magic-login backdoor, or the
   deterministic `bd_<hash>` / `Bd@26!...x` credential scheme — each co-occurrence-gated
   with an admin/persistence action (`mu-plugins`, `wp_insert_user`, `X-WP-Nonce`).
3. `Biggopti_IOCs` (high) — hard IOCs: C2 `ia-cdn.com/fz/c`, staging `api.sigmative.io`,
   and the four dropped-artifact md5 pins.

## In-repo smoke test
`yara -r bdthemes-biggopti-supply-chain.yar specimens/` → 5 hits (all expected):
- `poisoned-banner-response.json` → Biggopti_Poisoned_Banner_Payload
- `w2-stager.js` → Biggopti_Poisoned_Banner_Payload + Biggopti_IOCs (carries the real staging URL)
- `emer-run.php` → Biggopti_Dropped_Webshell_Backdoor
- `bdthemes-ioc-sweep.txt` → Biggopti_IOCs

`yara -r bdthemes-biggopti-supply-chain.yar benign/` → **0 hits (clean)**.
Benign set = legit Biggopti banner JSON (has `display_id`+`biggopti_class` but no
breakout/stager), a generic WP admin-notice fetcher (uses `.then(r=>r.text())` but
no family anchor), a benign MU-plugin user-provisioner (`wp_insert_user`+`mu-plugins`
but no artifact/cred/backdoor marker), and a security glossary mentioning the bare
terms. All correctly do **not** match — the co-occurrence guards hold.

## Corpus FP test
Budget-bounded slice, one rule per job (gate requires single-rule + filesize guard):
- `Biggopti_Poisoned_Banner_Payload` — 2,455 scanned, **0 matches**, 0 read-errors.
- `Biggopti_Dropped_Webshell_Backdoor` — 3,433 scanned, **0 matches**, 0 read-errors.
- `Biggopti_IOCs` — PENDING (job running at commit time; string-pinned to unique
  md5s + specific hosts, FP risk negligible; update on completion).

Verdict: no false positives on the sampled corpus slice for the two completed rules;
guards verified against structurally-similar benign WordPress/JS/PHP. IOC rule result
to be appended when its job finishes.
