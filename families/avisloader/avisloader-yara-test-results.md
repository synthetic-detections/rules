# AvisLoader — YARA test results

**Date:** 2026-10-13
**Source:** https://www.bleepingcomputer.com/news/security/inside-avisloader-a-windows-malware-loader-built-to-resist-disruption/
**Varonis:** https://www.varonis.com/blog/meet-avisloader-a-windows-loader-built-to-outlast-a-takedown

## Environment

- YARA 4.5
- Debian Linux 6.12

## Known samples (SHA-256)

| File | SHA-256 | Role |
|---|---|---|
| 78324.exe | 35dd164a7f5d8b42b9870c7009f7425b1c8cb771280c9e6c525e09f3dd13c2cc | Main loader (Tox client, 3.4 MB, 64-bit) |
| auto.exe | f0a6870cb774a55775eda15fd39e8a17eb3169d5b9365186dae8edff07ff3975 | UAC bypass helper (UACME #41) |
| hmn_hook.dll | cd1e835f52e5f55279dcdf3857e11bc9298ea6caa88eb214ea2d40ff5d38b5f5 | Process-hiding DLL (NtQuerySystemInformation hook) |

## Compile check

```
$ yara -w avisloader.yar /dev/null
(clean, exit 0)
```

## Specimen tests

```
$ yara -r -s avisloader.yar specimens/

AvisLoader_Behavioral specimens/avisloader-loader.bin
  build_path, hook_start, hook_status, hook_stop, ntquery, vlc_assistant
AvisLoader_IOC specimens/avisloader-loader.bin
  unique_build, hmn_start, hmn_status, hmn_stop, anchor_vlc

AvisLoader_Behavioral specimens/avisloader-uac-bypass.bin
  build_path, vlc_assistant, icmluautil, com_clsid
AvisLoader_IOC specimens/avisloader-uac-bypass.bin
  unique_build, anchor_vlc, anchor_clsid, anchor_icm

AvisLoader_Behavioral specimens/avisloader-panel.bin
  build_path, panel_brand
AvisLoader_IOC specimens/avisloader-panel.bin
  unique_build, unique_panel
```

All 3 specimens match both Behavioral and IOC rules.

## Benign tests

```
$ yara -r -s avisloader.yar benign/
(silent — no matches)
```

Benign files tested:
- vlc-media-player.bin (VLC strings + NtQuerySystemInformation alone)
- tox-client-legitimate.bin (c-toxcore mention without build path)
- upx-packed-legitimate.bin (packer section names + ICMLuaUtil alone)

## Linter

yara-linter unavailable (broken symlink). Skipped.

## Corpus FP test

PENDING — yaragate unavailable (502). Scan to be retried when service is restored.
