# APT28 PROMPTSTEAL / LAMEHUG — YARA test results

**YARA version:** 4.5.2 (classic)
**Platform:** Linux 6.12.88+deb13-amd64
**Date:** 2026-06-16
**Rule file:** `apt28-promptsteal.yar` (3 rules)

## Specimens

| # | File | Type | Purpose |
|---|------|------|---------|
| 1 | `specimens/promptsteal-v1-mock.py` | synthetic Python | v1 structure: plaintext prompts, SFTP exfil, paramiko |
| 2 | `specimens/promptsteal-v2-mock.py` | synthetic Python | v2 structure: base64 prompts, HTTP POST exfil |
| 3 | `specimens/ioc-report-mock.txt` | synthetic text | Threat-intel IOC listing |
| 4 | `benign/huggingface-client.py` | synthetic Python | Legitimate HuggingFace API client |
| 5 | `benign/random.bin` | urandom 8KB | Noise baseline |

All specimens are synthetic (non-functional). No real malware samples committed.

## Results

| File | LLM_Behavior | IOCs | Script_Shape | Expected |
|------|:---:|:---:|:---:|---|
| v1-mock.py | MATCH | MATCH | MATCH | all 3 |
| v2-mock.py | MATCH | MATCH | MATCH | all 3 |
| ioc-report-mock.txt | -- | MATCH | -- | IOCs only |
| huggingface-client.py | -- | -- | -- | none |
| random.bin | -- | -- | -- | none |

All results match expectations.

## Why the benign cases don't false-positive

**huggingface-client.py** contains `router.huggingface.co`, the `/hyperbolic/v1/chat/completions` API path, and the `Qwen2.5-Coder-32B-Instruct` model string — satisfying `2 of ($api_*, $model, $role)` in rule 1. However, it lacks ALL of:
- Staging directory strings (`Programdata\info`)
- Prompt tail strings (`Return only commands, without markdown`)

So the second condition `1 of ($staging_*, $prompt_*)` fails. This is the design: the HuggingFace+Qwen combination is legitimate; the co-occurrence with the staging directory or the specific prompt text is not.

Rule 2 (IOCs): the benign client contains no C2 domains, IPs, or delivery filenames.

Rule 3 (Script_Shape): the benign client contains no PROMPTSTEAL function names (`LLM_QUERY_EX` etc.).

**random.bin** matches nothing (no meaningful ASCII strings).

## YARA 4.5.2 modifier quirk

During development, discovered that `ascii base64` in YARA 4.5.2 means "search for the base64 encoding of the ascii-interpreted input" — it does NOT add an ascii plaintext search alongside the base64 search. To match both forms, separate string definitions are required:

```
$prompt_v1a = "..." ascii     // catches v1 (plaintext prompts)
$prompt_v2a = "..." base64    // catches v2 (base64-encoded prompts)
```

This differs from YARA-X where `ascii base64` searches for both forms. The rule was updated to use separate strings after initial testing showed the behavioral rule missing v1 specimens.

## Staging directory double-backslash handling

Python source files contain escaped backslashes (`Programdata\\info`), while PyInstaller bytecode contains single backslashes (`Programdata\info`). The rule includes both `$staging_dbl` (double-backslash, for source) and `$staging_sgl` (single-backslash, for bytecode). The `$staging_sgl` pattern is a substring of `$staging_dbl`, so source files match via `$staging_dbl` regardless.

## Caveats

- **All specimens are synthetic.** Function names, API URLs, and prompt strings are taken from public reporting (ThreatLocker, Cato CTRL, CERT-UA, GTIG) but the specimens are not real malware.
- **PyInstaller bundles not tested.** The real v1/v2 samples are PyInstaller-packaged executables. String literals survive in bytecode, but offset and context differ from raw source. Rules should be validated against VT-confirmed samples when available.
- **Post-disclosure rotation.** APT28 will change function names, C2 infrastructure, and possibly the LLM model after public reporting. The behavioral rule (LLM_Behavior) anchors on the HuggingFace API + staging pattern, which is harder to rotate without rewriting the core approach. The IOC rule will go stale first. The Script_Shape rule depends entirely on function name stability.
- **Known hashes for YARA-CI.** Four SHA256 hashes are listed in the IOC rule's `meta:` block for future VT validation:
  - `766c356d...b777` (Dodatok.pif, v1)
  - `d6af1c9f...db2e` (AI_generator v0.9, v2)
  - `bdb33bbb...aa3` (AI_image_generator v0.95, v2)
  - `384e8f3d...5715` (image.py, v1)

## Raw output

```
=== SHOULD-MATCH: v1 mock ===
APT28_PROMPTSTEAL_LLM_Behavior specimens/promptsteal-v1-mock.py
0x197:$api_chat: hyperbolic/v1/chat/completions
0x14b:$api_image: nebius/v1/images/generations
0x135:$api_host: router.huggingface.co
0x181:$api_host: router.huggingface.co
0x1c5:$model: Qwen2.5-Coder-32B-Instruct
0x346:$role: Windows systems administrator
0x389:$prompt_v1a: Return only commands, without markdown
0x1f0:$staging_dbl: Programdata\\info
APT28_PROMPTSTEAL_IOCs specimens/promptsteal-v1-mock.py
0x294:$sftp_ip: 144.126.202.227
APT28_PROMPTSTEAL_Script_Shape specimens/promptsteal-v1-mock.py
0x308:$fn_llm: LLM_QUERY_EX
0x435:$fn_llm: LLM_QUERY_EX
0x22a:$fn_xlsx: xlsx_open
0x24d:$fn_qimage: query_image
0x464:$fn_qimage: query_image
0x275:$fn_sshsend: ssh_send
0x20e:$var_xlsxb: xlsx_base
0x11c:$var_imgapi: Image_API_URL
0x477:$var_imgapi: Image_API_URL
0x414:$thread_llm: llm_query_thread
0x447:$thread_img: image_thread

=== SHOULD-MATCH: v2 mock ===
APT28_PROMPTSTEAL_LLM_Behavior specimens/promptsteal-v2-mock.py
0x18e:$api_chat: hyperbolic/v1/chat/completions
0x1dd:$api_image: nebius/v1/images/generations
0x178:$api_host: router.huggingface.co
0x1c7:$api_host: router.huggingface.co
0x209:$model: Qwen2.5-Coder-32B-Instruct
0x43c:$role: Windows systems administrator
0x2c8:$prompt_v2a: UmV0dXJuIG9ubHkgY29tbWFuZHMsIHdpdGhvdXQgbWFya2Rvd2
0x30f:$prompt_v2b: UmV0dXJuIG9ubHkgY29tbWFuZCwgd2l0aG91dCBtYXJrZG93b
0x26c:$staging_dbl: Programdata\\info
APT28_PROMPTSTEAL_IOCs specimens/promptsteal-v2-mock.py
0x23a:$c2_domain: stayathomeclasses.com
0x3b4:$c2_domain: stayathomeclasses.com
0x24f:$c2_path: /slpw/up.php
0x3c9:$c2_path: /slpw/up.php
APT28_PROMPTSTEAL_Script_Shape specimens/promptsteal-v2-mock.py
0x3fe:$fn_llm: LLM_QUERY_EX
0x522:$fn_llm: LLM_QUERY_EX
0x34a:$fn_xlsx: xlsx_open
0x36d:$fn_qimage: query_image
0x551:$fn_qimage: query_image
0x280:$var_xlsxb: xlsx_base
0x1ae:$var_imgapi: Image_API_URL
0x501:$thread_llm: llm_query_thread
0x534:$thread_img: image_thread

=== SHOULD-MATCH: IOC report ===
APT28_PROMPTSTEAL_IOCs specimens/ioc-report-mock.txt
0x6b:$c2_domain: stayathomeclasses.com
0x83:$c2_domain: stayathomeclasses.com
0x98:$c2_path: /slpw/up.php
0xa7:$sftp_ip: 144.126.202.227
0xc9:$infra_ip: 107.180.50.236
0xef:$fn_pif: Dodatok.pif
0xfd:$fn_gen09: AI_generator_uncensored_Canvas_PRO
0x12b:$fn_gen095: AI_image_generator_v0.95
0x16f:$email: boroda70@meta.ua

=== SHOULD-NOT-MATCH: benign HuggingFace client ===
(no output — correct)

=== SHOULD-NOT-MATCH: random binary ===
(no output — correct)
```
