# TerminalFix Reverse Tunnel — YARA Test Results

Rules: `TerminalFix_DLL_Sideload`, `TerminalFix_IOC`, `TerminalFix_Lure_Page`.

YARA 4.5.2, Linux x86_64, 2026-09-12.

## Specimen matrix

| File | Expected rule(s) | Actual | Result |
|------|-------------------|--------|--------|
| `specimens/terminalfix_sideload_synth.bin` | DLL_Sideload + IOC | DLL_Sideload, IOC | PASS |
| `specimens/terminalfix_tunnel_synth.py` | DLL_Sideload + IOC | DLL_Sideload, IOC | PASS |
| `specimens/terminalfix_lure_synth.html` | Lure_Page | Lure_Page | PASS |
| `benign/legit_cloudflare_page.html` | (none) | (none) | PASS |
| `benign/random_noise.bin` | (none) | (none) | PASS |

## Why benign cases don't false-positive

- **legit_cloudflare_page.html**: Has "Cloudflare" and "Verify you are human" (`$captcha_*` match) but has NO `navigator.clipboard.writeText` or `clipboard.write` (`$clip_*`), and no terminal/paste instructions (`$instr_*`). The Lure_Page rule requires all three categories.
- **random_noise.bin**: 2048 bytes of urandom — no ASCII strings match any pattern.

## Matched strings detail

**terminalfix_sideload_synth.bin** (DLL_Sideload):
- `$name_dui70`, `$desc_directui`, `$sideload_host` → 2-of-3 sideload anchor fires
- Also: `$steg_func`, `$persist_bat`, `$persist_lockscreen`

**terminalfix_tunnel_synth.py** (DLL_Sideload):
- `$tunnel_client`, `$tunnel_server`, `$tunnel_uuid`, `$tunnel_cert` (3 of 4) + `$ws_tunnel` → reverse tunnel condition fires
- Also: `$recon_trusts`, `$recon_admins`, `$recon_adsi` → AD recon condition fires independently

**terminalfix_lure_synth.html** (Lure_Page):
- `$clip_write` + `$clip_api` → clipboard API
- `$captcha_verify`, `$captcha_turnstile`, `$captcha_cloudflare`, `$captcha_check` → fake CAPTCHA branding
- `$instr_winr`, `$instr_terminal`, `$instr_powershell`, `$instr_paste`, `$instr_enter` → terminal instructions

## Caveats

- All specimens are synthetic. No real TerminalFix samples were available for testing at rule authoring time.
- The DLL_Sideload rule's sideload-host condition (`2 of ($name_dui70, $desc_directui, $sideload_host)`) could match legitimate `dui70.dll` (Windows DirectUI Engine). However, a real `dui70.dll` would not contain `Extract-RawFileFromImage`, `client.py`, or AD recon commands — it would only match the 2-of-3 anchor path, not the other disjuncts.
- The Lure_Page rule catches the clipboard-hijack pattern generically; it will match ClickFix lures too (not just TerminalFix). This is intentional — the social-engineering vector is the same.
- IOC rule will go stale on infrastructure rotation. The DLL_Sideload and Lure_Page rules target structural/behavioural patterns and should survive rotation.

## MalShare corpus FP test

| Rule | Samples scanned | Matches | Duration | Result |
|------|-----------------|---------|----------|--------|
| DLL_Sideload | 5,934 | 0 | 10m55s | PASS |
| IOC | 8,295 | 0 | 14m43s | PASS |
| Lure_Page | 6,834 | 0 | 14m22s | PASS |

Zero false positives across all three rules. Scanned 2026-09-12 against the MalShare corpus (~497k samples).
