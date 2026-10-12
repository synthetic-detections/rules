# kimsuky-gitpower YARA Test Results

**Date:** 2026-10-12
**Rule file:** `kimsuky-gitpower.yar`
**Source:** https://www.genians.co.kr/en/blog/threat_intelligence/operation-gitpower

## Rules

| # | Rule name | Type | Severity |
|---|-----------|------|----------|
| 1 | Kimsuky_GitPower_Behavioral | behavioural | critical |
| 2 | Kimsuky_GitPower_IOC | IOC sweep | high |
| 3 | Kimsuky_GitPower_Specimen | specimen pin | critical |

## Compile check

```
yara -w kimsuky-gitpower.yar /dev/null
(no output — clean compile)
```

## Specimen tests (must alert)

| Specimen | Rule matched |
|----------|-------------|
| specimen_behavioral_delivery.bin | Kimsuky_GitPower_Behavioral |
| specimen_behavioral_schtask.bin | Kimsuky_GitPower_Behavioral |
| specimen_behavioral_exfil.bin | Kimsuky_GitPower_Behavioral |
| specimen_behavioral_exfil_path.bin | Kimsuky_GitPower_Behavioral |
| specimen_ioc_serveirc.bin | Kimsuky_GitPower_IOC |
| specimen_ioc_gitlab.bin | Kimsuky_GitPower_IOC |
| specimen_ioc_freehost.bin | Kimsuky_GitPower_IOC |
| specimen_ioc_ip_cooccur.bin | Kimsuky_GitPower_IOC |
| specimen_ioc_pwd_email.bin | Kimsuky_GitPower_IOC |
| specimen_ioc_obf_cluster.bin | Kimsuky_GitPower_IOC |
| specimen_specimen_lnk.bin | Kimsuky_GitPower_Specimen |
| specimen_specimen_lnk_ukr.bin | Kimsuky_GitPower_Specimen, IOC |
| specimen_specimen_vbe.bin | Kimsuky_GitPower_Specimen |

**Result: 13/13 specimens matched expected rules. PASS.**

## Benign tests (must be silent)

| Benign file | Result |
|-------------|--------|
| benign_zoom_installer.bin | no alert |
| benign_serveirc.bin | no alert |
| benign_freehost.bin | no alert |
| benign_gitlab_random.bin | no alert |
| benign_powershell_admin.bin | no alert |
| benign_ini_config.bin | no alert |
| benign_wolf_string.bin | no alert |
| benign_ip_address.bin | no alert |
| benign_korean_conference.bin | no alert |
| benign_ukrainian_text.bin | no alert |

**Result: 0/10 benign files triggered. PASS.**

## Corpus FP test

PENDING — scans launched, awaiting results.
