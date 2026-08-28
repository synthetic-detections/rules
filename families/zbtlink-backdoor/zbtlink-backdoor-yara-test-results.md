# SPEAKINGSTONE / DARKLANTERN (Zbtlink router backdoor) — YARA test results

Rule file: `zbtlink-backdoor.yar` (3 rules)
Source: VulnCheck, "ZBT / DarkLantern / SpeakingStone" (2026-08-27)
Authored: 2026-08-28
Environment: YARA 4.5.2, Linux x86-64

## Rules

1. **Zbtlink_Backdoor_Behaviour** (critical) — ELF magic + filesize < 8MB, then the
   implant constellation: a proto tag (`revProto` / `zbtProtocol`) co-occurring with the
   MD5 salt `mqonu.com`, the exec prefix `/etc/exec/cmd`, an implant binary name
   (`yunmgrd` / `infosrvd` / `inetdetect`) or `/tmp/yunclient.conf`; OR salt + exec
   together; OR two implant binary names. No single generic token fires alone.
2. **Zbtlink_Backdoor_IOC** (high) — `any of` the implant-specific tokens, OEM contact
   `sales03@zbt-china.com`, and C2 domains `ac-link[.]com` / `findmyipaddr[.]com`. The
   generic router paths `/tmp/info.txt` / `/tmp/mac.txt` and the shared-hoster IP
   `47.107.224.89` are credited only when paired (they alias legitimate content and the
   IP is shared with `endlessdoors-zbtlink-backdoor`).
3. **Zbtlink_Backdoor_Specimen_Pin** (critical) — pins the three VulnCheck SHA-256
   (`yunmgrd`/SPEAKINGSTONE, `infosrvd`/DARKLANTERN, `inetdetect`) with an ELF magic +
   filesize < 8MB pre-gate.

No live samples were held at authoring time (all three SHA-256 absent from the malware
corpus), so specimens are synthetic ELFs carrying the vendor-reported strings. The
specimen-pin rule therefore does **not** fire on the synthetic ELFs — expected, since it
is keyed on the real file hashes.

## In-repo smoke test

```
$ yara -r zbtlink-backdoor.yar specimens/
Zbtlink_Backdoor_IOC        specimens/mock-ioc-report.txt
Zbtlink_Backdoor_Behaviour  specimens/mock-darklantern-infosrvd.elf
Zbtlink_Backdoor_IOC        specimens/mock-darklantern-infosrvd.elf
Zbtlink_Backdoor_Behaviour  specimens/mock-speakingstone-yunmgrd.elf
Zbtlink_Backdoor_IOC        specimens/mock-speakingstone-yunmgrd.elf
Zbtlink_Backdoor_Behaviour  specimens/mock-inetdetect.elf
Zbtlink_Backdoor_IOC        specimens/mock-inetdetect.elf

$ yara -r zbtlink-backdoor.yar benign/
(clean — no matches)
```

Each ELF specimen hits Behaviour + IOC; the IOC report text hits IOC. The specimen-pin
rule stays silent on the synthetic ELFs (real hashes only).

### Why the benign cases stay clean

- `legit-busybox-router.elf` — a router BusyBox build that references `/etc/exec`
  (not the full `/etc/exec/cmd`), the word `protocol` (not `revProto`/`zbtProtocol`) and
  the vendor domain `www.zbt-china.com` (not `sales03@zbt-china.com` and not a C2 domain).
  No implant token; Behaviour needs a proto tag or the salt+exec pair.
- `legit-netmon-daemon.elf` — references `/tmp/info.txt` alone. The IOC generic-path
  guard needs a second marker; Behaviour needs the proto/salt/exec constellation.
- `legit-zbt-firmware-banner.txt` — legitimate ZBT vendor banner with `www.zbt-china.com`
  and `support@zbt-china.com`; carries neither the `sales03@` OEM string, a C2 domain,
  nor a proto tag.

## Corpus FP test

Status: **PENDING** — the highest-FP-risk rule (`Zbtlink_Backdoor_IOC`, the string/`any of`
match) was submitted to the corpus scanner (label `zbtlink-backdoor-ioc`,
`--max-hits 40 --budget 15m`). Any corpus hit on this recent family is a candidate FP to
investigate and tighten; result to be recorded here when the scan completes. The Behaviour
and Specimen-Pin rules are ELF-magic + filesize gated, so broad FPs are unlikely.

## Coverage caveats

- Specimens are synthetic; the real MIPS/ARM router binaries were not available.
- Post-disclosure C2 rotation will erode the IOC domain/IP matches; the Behaviour rule
  (proto/salt/exec/binary-name constellation) is the rotation-resistant anchor.
- Firmware images are often compressed (SquashFS/LZMA); the ELF-magic rules match only an
  unpacked rootfs or the extracted binary, not the packed image.
