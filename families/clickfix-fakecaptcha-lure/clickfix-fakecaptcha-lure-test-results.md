# Test transcript — `clickfix-fakecaptcha-lure.yar`

## Environment

- Engine: **YARA 4.x**
- Date: 2026-09-26
- References: MITRE ATT&CK **T1204.004** (Malicious Copy and Paste) ·
  <https://www.proofpoint.com/us/blog/threat-insight/security-brief-clickfix-social-engineering-technique-floods-threat-landscape> ·
  <https://attack.mitre.org/techniques/T1204/004/>

## What it detects

ClickFix / FakeCAPTCHA **lure pages** (HTML/JS): a fake "verify you are human" /
reCAPTCHA / Cloudflare page that copies a PowerShell/mshta/curl command to the
clipboard (the `stageClipboard` routine) and instructs the victim to paste it
into the Windows Run dialog (Win+R), PowerShell, or the File Explorer address bar
("FileFix" variant). Coined by Proofpoint; in the wild since 2024-03
(TA571/ClearFake); by 2025 the #1–2 initial-access vector industry-wide.

**Detection key / FP control:** the discriminator is clipboard-staging of a
shell command (or the near-unique `stageClipboard` routine) plus fake-verify
framing — **not** the CAPTCHA text alone. A legitimate reCAPTCHA or Cloudflare
Turnstile page also says "verify you are human" / "I'm not a robot", but never
copies a command to the clipboard or tells the user to press Win+R, so it does
not match.

## Rules

| Rule | Fires on |
|---|---|
| `clickfix_stageclipboard_routine` | the near-unique `stageClipboard` / `setClipboardCopyData` routine |
| `clickfix_clipboard_staged_cradle` | clipboard-copy of an obfuscated/remote-exec cradle (`-enc`, `mshta http`, `iwr\|iex`, `curl\|bash`) |
| `clickfix_fakecaptcha_verify_ploy` | fake-verify ploy string + clipboard staging or a command cradle |
| `clickfix_run_dialog_instructions` | Win+R / File Explorer / PowerShell paste-and-run steps + a cradle + verify framing |

## Specimens & benign (shipped, synthetic)

| File | Expected |
|---|---|
| `specimens/lure-fake-recaptcha.html` | match (stageClipboard + ploy + Win+R + `-enc` cradle) |
| `specimens/lure-fake-cloudflare-verify.html` | match (execCommand copy + mshta + "Cloud Identificator") |
| `benign/legit-recaptcha.html` | clean (real g-recaptcha, no clipboard cmd) |
| `benign/legit-cloudflare-turnstile.html` | clean (real Turnstile — says "Verify you are human" but no cmd) |
| `benign/it-runbook-powershell.html` | clean (real admin PowerShell + Win+R mention, no staging/ploy) |

Result: both specimens match; all three benign files stay clean, **including the
Cloudflare Turnstile page** (the key false-positive trap).

## Validation against real samples

Beyond the shipped synthetic specimens, the rules were validated against a corpus
of **1,513 real harvested ClickFix lure pages** collected from public open-source
ClickFix analyzer/reproduction repositories (ClickGrab, clickfix-wiki and
others). Result:

```
caught 1,219 / 1,513 real lure pages = 80.6% recall
false positives on the legitimate-CAPTCHA / admin-runbook benign set = 0
```

The ~19% misses are predominantly the **FileFix** variant and lures whose staged
command is fully obfuscated/dynamically fetched (no literal cradle token and no
verify-ploy string), which cannot be matched without raising the legitimate
"copy this command" false-positive rate. Precision was prioritised: the rules
add no match on legitimate reCAPTCHA/Turnstile pages.

## Notes / limitations

- Detects the **lure page**, not the downstream payload. Pair with payload
  detections for the delivered families (Lumma, StealC, AMOS, AsyncRAT, etc.).
- Homoglyph evasion: some lures substitute Cyrillic look-alikes in "reCAPTCHA".
  Normalize/Unicode-fold before scanning, or extend with homoglyph variants.
