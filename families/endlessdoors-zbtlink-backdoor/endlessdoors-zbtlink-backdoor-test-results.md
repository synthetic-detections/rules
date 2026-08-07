# ENDLESSDOORS (Zbtlink router backdoor) — YARA test results

Rule file: `endlessdoors-zbtlink-backdoor.yar` (3 rules)
Source: VulnCheck (CVE-2026-66747), disclosed 2026-08-06
Authored: 2026-08-07

## Rules

1. **ENDLESSDOORS_Implant_Behavior** (critical) — the rctl-derived ELF implant.
   Gated on the ELF magic plus the implant-specific rctl protocol strings
   (`rctlbash`, `run this as root`) OR the kworker-masquerade paths co-occurring
   with `librctl.so`/`popen`. The bare kernel-thread name `kworker` never fires
   alone — the implant paths/protocol must be present.
2. **ENDLESSDOORS_IOC** (high) — C2 domains (`zbtctl.epplink[.]net`,
   `online-string[.]com`, `rbdg4nzqadui.wikaba[.]com`) and IPs (2-of guard to
   avoid single shared-host FPs).
3. **ENDLESSDOORS_Artifacts** (critical) — the implant filesystem-path
   constellation (`/etc/init.d/skworker`, `/usr/lib/librctl.so`,
   `/etc/kworker.cfg`, `/usr/sbin/kworker`), 3-of, to pin a firmware image or
   unpacked rootfs even without the ELF present.

No file hashes were published by VulnCheck, so the rules anchor on the
filesystem paths, rctl protocol vocabulary, and C2 — not sample hashes.

## In-repo smoke test

```
$ yara -r endlessdoors-zbtlink-backdoor.yar specimens/
ENDLESSDOORS_IOC              specimens/mock-ioc-report.txt
ENDLESSDOORS_Implant_Behavior specimens/mock-endlessdoors-implant.elf
ENDLESSDOORS_IOC              specimens/mock-endlessdoors-implant.elf
ENDLESSDOORS_Artifacts        specimens/mock-endlessdoors-implant.elf
ENDLESSDOORS_Artifacts        specimens/mock-firmware-rootfs-listing.txt

$ yara -r endlessdoors-zbtlink-backdoor.yar benign/
(clean — no matches)
```

Each specimen hits its intended rule; the two structurally-similar benign files
(a real `ps` listing full of legitimate `kworker/*` kernel threads, and a benign
OpenWrt init script that mentions `kworker` and a 35s interval) stay clean —
confirming the kworker-masquerade guard holds.

## Corpus FP test

**PENDING** — the corpus-scan service was unreachable at author time (connection
refused). Re-run when it is back:
`scan --rule-file endlessdoors-zbtlink-backdoor.yar --max-hits 40 --budget 15m`.
The Implant_Behavior rule is ELF-gated and the Artifacts rule needs 3 distinct
implant paths, so broad FPs are unlikely, but the IOC domain strings should be
checked against benign corpus text.
