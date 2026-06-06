# Test transcript — `moonlight-maze-loki2-penquin.yar`

## Environment

- YARA: `4.5.2`
- Date: 2026-06-07
- Sources:
  - <https://securelist.com/penquins-moonlit-maze/>  (Kaspersky + King's College London, 2017)
  - <https://securelist.com/the-penquin-turla-2/67962/>  (Kaspersky, 2014)
  - <https://phrack.org/issues/51/6.html>  (LOKI2 source — Phrack 51 #6, 1997)
  - <https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+%E2%80%9CPenquin_x64%E2%80%9D.pdf>  (Leonardo S.p.A., April 2020)
  - <https://en.wikipedia.org/wiki/Moonlight_Maze>

## Corpus

| File | Kind | Intended rule | Expected |
|---|---|---|---|
| `specimens/loki2-strings.elf` | synthetic ELF64 with verbatim Phrack-51 LOKI2 format strings | `MoonlightMaze_LOKI2` | match |
| `specimens/penquin-x64-strings.elf` | synthetic ELF64 with Penquin_x64 anchor strings (Leonardo) | `Penquin_Turla_LinuxBackdoor` | match |
| `specimens/penquin-2014era.elf` | synthetic ELF64 with 2014 C2 + glibc/openssl/libpcap + sh wrapper | `Penquin_Turla_2014Era` | match |
| `specimens/penquin-magic-packet.elf` | synthetic ELF64 with 2014 BPF filter expressions + 2020 0xbdbd0560 mask (both endians) + pcap_setfilter/eth0 | `Penquin_Turla_MagicPacket` | match |
| `specimens/penquin-opcode.elf` | synthetic ELF64 embedding the first three Leonardo opcode sequences | `Penquin_Turla_Opcode_Leonardo` | match |
| `specimens/ioc-dump.txt` | reference IOC dump (LOKI2 strings + 8 SHA-256 + campaign names) | `MoonlightMaze_LOKI2` + `MoonlightMaze_Penquin_IOC` | match |
| `benign/normal-sshd.elf` | synthetic ELF64 with generic OpenSSH-style strings | none | no match |
| `benign/random.bin` | 5 KiB urandom | none | no match |

The two build helpers (`build-elf-specimens.py`, `build-benign-elf.py`)
sit at the family root, not in `specimens/` or `benign/`. The lesson
from earlier families holds: helpers that embed campaign strings as
Python bytes literals will themselves match the rule if scanned in the
corpus.

## Compile check

```
$ yara -w families/moonlight-maze-loki2-penquin/moonlight-maze-loki2-penquin.yar /dev/null && echo OK
COMPILE_OK
```

## Run — should-match

```
$ yara -r families/moonlight-maze-loki2-penquin/moonlight-maze-loki2-penquin.yar \
        families/moonlight-maze-loki2-penquin/specimens/
MoonlightMaze_LOKI2              …/loki2-strings.elf
Penquin_Turla_LinuxBackdoor      …/penquin-x64-strings.elf
Penquin_Turla_2014Era            …/penquin-2014era.elf
Penquin_Turla_MagicPacket        …/penquin-magic-packet.elf
Penquin_Turla_Opcode_Leonardo    …/penquin-opcode.elf
MoonlightMaze_LOKI2              …/ioc-dump.txt
MoonlightMaze_Penquin_IOC        …/ioc-dump.txt
```

`ioc-dump.txt` matches `MoonlightMaze_LOKI2` (it quotes the verbatim
Phrack-51 strings as anchor references) and `MoonlightMaze_Penquin_IOC`
(it carries the SHA-256 list and the campaign names). Both expected.

## Run — should-not-match

```
$ yara -r families/moonlight-maze-loki2-penquin/moonlight-maze-loki2-penquin.yar \
        families/moonlight-maze-loki2-penquin/benign/
(no output — clean)
```

## Result summary

| File | Expected | Observed | Result |
|---|---|---|---|
| `loki2-strings.elf` | `MoonlightMaze_LOKI2` | fired | PASS |
| `penquin-x64-strings.elf` | `Penquin_Turla_LinuxBackdoor` | fired | PASS |
| `penquin-2014era.elf` | `Penquin_Turla_2014Era` | fired | PASS |
| `penquin-magic-packet.elf` | `Penquin_Turla_MagicPacket` | fired | PASS |
| `penquin-opcode.elf` | `Penquin_Turla_Opcode_Leonardo` | fired | PASS |
| `ioc-dump.txt` | `MoonlightMaze_LOKI2` + `MoonlightMaze_Penquin_IOC` | both | PASS |
| `normal-sshd.elf` | clean | clean | PASS |
| `random.bin` | clean | clean | PASS |

## Why the benign cases don't false-positive

- **`normal-sshd.elf`** — has the ELF magic and a small inventory of
  generic OpenSSH-style strings (`OpenSSH_9.6p1`, `/var/run/sshd.pid`,
  `connect to host %s port %d`, etc.). None of these match a
  Phrack-51 LOKI2 format string verbatim, none match a Penquin_x64
  anchor, and the file contains no SHA-256, no campaign names, and no
  `/var/tmp/` operator-convention path. The LOKI2 rule's `any of ($s_*)`
  branch fails because no LOKI2 strings are present; the source-tree
  + function co-occurrence branch fails; the `L_TAG` regex fails. The
  Penquin rule needs ≥4 of 10 specific strings — gets 0. IOC rule
  needs a campaign name / SHA-256 / `LOKI2 + /var/tmp/` co-occurrence
  — gets 0.
- **`random.bin`** — urandom; probability of any multi-byte literal
  appearing is negligible.

## Caveats

- **Penquin Turla anchors are republished community signatures.** The
  10 strings in rule 2 trace to Leonardo S.p.A.'s public YARA from
  2026-04-24 (also in `Neo23x0/signature-base/yara/apt_turla_penquin.yar`).
  Acknowledged in the rule's `meta:` and the file-header comment.
- **LOKI2 source-code matching cuts both ways.** The Phrack-51
  publication is widely mirrored on GitHub for historical / educational
  reasons (e.g. `JeremyNGalloway/LOKI2`). Anyone who clones such a
  mirror onto disk will trip the rule. That's intentional — staging
  LOKI2 source is part of the operator's threat model — but treat
  hits in `/home/<user>/projects/...` and similar with context.
- **The Moonlight Maze ↔ Penquin Turla link is circumstantial.**
  The Kaspersky + KCL paper presents the LOKI2 code reuse as a strong
  but circumstantial bridge from 1998 to modern Turla. The rule file
  reflects that: it detects the artefacts, not the attribution.
- **No SPARC/MIPS gate.** The original Moonlight Maze binaries were
  compiled for Sun Solaris (SPARC). Modern Penquin samples are Linux
  ELF64 / ELF32. Rule 2 explicitly gates on ELF magic; rule 1 is
  format-agnostic and will match LOKI2 strings inside SPARC, MIPS, or
  x86 binaries alike.
- **`MoonlightMaze_Penquin_IOC` is `severity = "high"`** because
  public writeups (including this transcript and the in-repo
  `ioc-dump.txt`) contain the SHA-256 and campaign names. Triage by
  file context.

## Not covered

- **Penquin_x64 opcode patterns.** Leonardo S.p.A.'s second rule
  (`APT_MAL_LNX_Turla_Apr202004_1_opcode`) keys on seven hex byte
  sequences inside Penquin samples. Not reproduced here — the value
  of duplicating it would be marginal; deploy Leonardo's rule alongside
  this file for the opcode coverage.
- **Network-side detection.** LOKI2 tunnels data over ICMP echo with
  `L_TAG = 0xf001` in the sequence field. A Snort rule on ICMP echo
  with the magic in the sequence position would catch live LOKI2 / 
  derivative traffic; out of scope for filesystem YARA. Could be
  added as a sibling Snort family later.
- **Storm Cloud.** The Securelist paper references a post-1999
  evolution of the Moonlight Maze toolkit codenamed "Storm Cloud"
  whose binaries leaked in 2003. No public signatures published; no
  rule possible without samples.
