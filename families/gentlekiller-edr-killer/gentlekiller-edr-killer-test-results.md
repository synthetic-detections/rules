# GentleKiller EDR-Killer YARA Rule Test Results

- **YARA version:** 4.5.2
- **Platform:** Linux 6.12.90+deb13.1-amd64 (Debian)
- **Date:** 2026-06-22
- **Author:** synthetic-detections
- **Rules file:** `gentlekiller-edr-killer.yar`

## Summary

| File | Type | Expected Rule(s) | Actual Result |
|---|---|---|---|
| `specimens/specimen_killlist.bin` | should-match | GentleKiller_EDR_KillList | MATCH |
| `specimens/specimen_variant.bin` | should-match | GentleKiller_Variant_Artifacts | MATCH (also IOC) |
| `specimens/specimen_ioc_staging.txt` | should-match | GentleKiller_IOC | MATCH |
| `benign/benign_sysmon.bin` | should-not-match | (none) | NO MATCH |
| `benign/benign_random.bin` | should-not-match | (none) | NO MATCH |

**Result: 3/3 should-match specimens triggered expected rules. 0/2 benign specimens false-positived. All tests PASS.**

## Specimen Descriptions

### specimen_killlist.bin (100 KB)

Synthetic PE binary with MZ+PE header and 10 EDR vendor process name strings (CSFalconService, CSAgent, SentinelAgent, SentinelHelperService, MsMpEng, MsSense, SophosHealth, SophosFileScanner, CylanceSvc, CbDefense) plus "DeviceIoControl". Remainder padded with random bytes.

### specimen_variant.bin (100 KB)

Synthetic PE binary with MZ+PE header and BYOVD driver filenames (eb.sys, nseckrnl.sys, G11.sys, ThrottleBlood.sys) alongside variant executable names (Kasps.exe, FaceIT1.exe). Remainder padded with random bytes. Also triggers GentleKiller_IOC due to 4 driver names (3+ threshold) and 2 variant filenames.

### specimen_ioc_staging.txt (1.3 KB)

Synthetic incident report text containing the "GentlemenCollection" staging directory path, 6 variant filenames (Kasps.exe, FaceIT1.exe, Valorant2.exe, BitD1.exe, Deletor.exe, MB2.exe), 6 driver names, and OxideHarvest reference (buildx641.exe).

### benign_sysmon.bin (100 KB)

Synthetic PE binary with MZ+PE header and 3 process name strings: MsMpEng, csrss, svchost. Only MsMpEng is an $edr_* string; csrss and svchost are not in the kill-list. Remainder padded with random bytes.

### benign_random.bin (4 KB)

Pure urandom bytes with no structure or meaningful strings.

## Raw YARA Output

```
$ yara -s gentlekiller-edr-killer.yar specimens/

GentleKiller_EDR_KillList specimens//specimen_killlist.bin
0x100:$edr_cs1: CSFalconService
0x171:$edr_cs3: CSAgent
0x197:$edr_s1a: SentinelAgent
0x1b8:$edr_s1b: SentinelHelperService
0x23c:$edr_def1: MsMpEng
0x277:$edr_def2: MsSense
0x2ae:$edr_soph1: SophosHealth
0x2e7:$edr_soph3: SophosFileScanner
0x31a:$edr_pa1: CylanceSvc
0x393:$edr_cb2: CbDefense
0x3ba:$api_ioctl: DeviceIoControl

GentleKiller_Variant_Artifacts specimens//specimen_variant.bin
0x100:$drv_eb: eb.sys
0x175:$drv_nsec: nseckrnl.sys
0x1d7:$drv_g11: G11.sys
0x1fa:$drv_throttle: ThrottleBlood.sys
0x267:$var_kasp: Kasps.exe
0x2b7:$var_faceit: FaceIT1.exe

GentleKiller_IOC specimens//specimen_variant.bin
0x267:$fn_kasps: Kasps
0x2b7:$fn_faceit: FaceIT1
0x100:$drv_eb: eb.sys
0x175:$drv_nsec: nseckrnl.sys
0x1d7:$drv_g11: G11.sys
0x1fa:$drv_throttle: ThrottleBlood.sys

GentleKiller_IOC specimens//specimen_ioc_staging.txt
0x120:$staging: GentlemenCollection
0x15d:$fn_kasps: Kasps
0x1a3:$fn_faceit: FaceIT1
0x1e6:$fn_valorant: Valorant2
0x22b:$fn_bitd: BitD1
0x2a9:$fn_mb2: MB2
0x273:$fn_deletor: Deletor
0x321:$drv_eb: eb.sys
0x351:$drv_nsec: nseckrnl.sys
0x385:$drv_g11: G11.sys
0x3b1:$drv_throttle: ThrottleBlood.sys
0x3ea:$drv_havoc: havoc.sys
0x416:$drv_baidu: googleApiUtil64.sys
0x512:$oxide: buildx641.exe

$ yara -s gentlekiller-edr-killer.yar benign/

(no output — no matches)
```

## Why Benign Cases Don't False-Positive

### benign_sysmon.bin

- **GentleKiller_EDR_KillList:** Requires `8 of ($edr_*)` or `5 of ($edr_*) and $api_ioctl`. This file contains only 1 matching $edr_* string (MsMpEng). The strings "csrss" and "svchost" are generic Windows process names that do not appear anywhere in the rule's string definitions. Threshold not reached.
- **GentleKiller_Variant_Artifacts:** Requires at least one $drv_* and one $var_*, or 2+ $drv_*, or $oxide + $drv_*. This file contains none of those strings.
- **GentleKiller_IOC:** Requires $staging, or 3+ $fn_*, or 3+ $drv_*, or $oxide + another indicator. This file contains none of those strings.

### benign_random.bin

- **All three rules:** No MZ header (fails `uint16(0) == 0x5A4D` for Rules 1-2), no meaningful strings, file is only 4 KB (below 20 KB minimum for Rules 1-2). The IOC rule has no MZ requirement but none of its target strings appear in random data.

## Caveats

1. **Synthetic specimens are not real malware.** These files contain planted strings in minimal PE scaffolding. They validate rule logic (string matching, thresholds, conditions) but do not represent actual packed/obfuscated GentleKiller binaries. Real-world samples will be Enigma- or Themida-packed and require memory dumping or unpacking before Rules 1-2 fire.

2. **PE module not exercised.** The rules import the `pe` module but the current conditions only use `uint16(0) == 0x5A4D` for the PE check, not `pe.is_pe()`. The synthetic PE headers are minimal stubs (MZ + e_lfanew + PE signature) — they satisfy the uint16 check but would fail full PE parsing. If rules are later updated to use `pe.is_pe()`, these specimens would need richer PE headers.

3. **specimen_variant.bin triggers GentleKiller_IOC as a side effect.** This is expected and correct: 4 driver filenames exceed the `3 of ($drv_*)` threshold in the IOC rule. This overlap is by design — real GentleKiller binaries would similarly match multiple rules.

4. **Case sensitivity.** Many strings use `nocase`, so the specimens use mixed-case as written in the rules. Real malware may use all-lowercase or all-uppercase; the `nocase` modifier handles this, but it is not explicitly tested here with alternate casings.

5. **Wide string encoding not tested.** Several rule strings include the `wide` modifier (UTF-16LE). The synthetic specimens embed only ASCII strings. Real PE binaries often store resource strings as wide; a more thorough test suite would include wide-encoded variants.

6. **Filesize boundaries not tested.** Rules 1-2 require `filesize > 20KB and filesize < 10MB`. Rule 3 requires `filesize < 50MB`. Edge-case testing at exactly 20KB, 10MB, and 50MB boundaries is not included.
