# KeyDrift SD-WAN — YARA test results

**Family:** keydrift-sdwan
**Rules:** 3 (Behaviour / IOC / Packed_Loader)
**Date:** 2026-10-30
**Source:** Cisco Talos — "Inside KeyDrift: Analyzing historical UAT-11473 activity on Cisco SD-WAN" (2026-10-28)

## Environment

- YARA 4.5.x, Debian bookworm amd64
- yara-linter applied (--align --multiline --brace-newline --explicit-parens)

## Source artifacts

Talos did not publish file hashes, C2 addresses, or domain names for the
KeyDrift components. Rules are built from distinctive file paths, component
names, protocol byte markers, and structural characteristics described in
the report. No real-world samples are available for specimen testing.

## Compile check

```
yara -w keydrift-sdwan.yar /dev/null → OK (no warnings)
```

## Specimen test

| File | Rule hits |
|---|---|
| keydrift-polyflame-sim.bin | Behaviour, IOC |
| keydrift-aaamgrd-sim.bin | Packed_Loader |

Both synthetic specimens match expected rules. The Packed_Loader rule
fires on the aaamgrd-sim specimen (ELF64, no section headers, TracerPid
+ aaamgr strings). The Behaviour and IOC rules fire on the polyflame-sim
specimen (ELF with vdaemon paths, component names, and protocol markers).

## Benign test

| File | Rule hits |
|---|---|
| legit-elf-sshd.bin | (none) |
| legit-elf-network.bin | (none) |

No false positives on structurally similar benign ELFs containing
overlapping strings (TracerPid, /bin/sh, sshd, runit paths).

## Corpus FP test

Corpus FP scan pending.
