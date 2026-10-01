# Star Blizzard RedFlick / CosmicPulse — YARA Test Results

## Environment

- YARA 4.5.2
- Debian 13 (trixie), x86_64

## Sources

- Microsoft Threat Intelligence, 2026-09-29:
  https://www.microsoft.com/en-us/security/blog/2026/09/29/star-blizzard-refines-phishing-and-malware-delivery-with-the-redflick-technique/

## Rules

| # | Rule | Severity | Description |
|---|------|----------|-------------|
| 1 | StarBlizzard_RedFlick_Behavior | critical | .mollis registry key, scheduled task names, CPL+Python bundling, WebDAV UNC, CosmicPulse markers |
| 2 | StarBlizzard_RedFlick_IOCs | high | C2 domains + IPs with co-occurrence guards |
| 3 | StarBlizzard_RedFlick_Specimens | critical | Exact SHA-256 hash matches for 5 known samples |

## Compile check

```
$ yara -w star-blizzard-redflick.yar /dev/null
(clean — no errors, no warnings)
```

## Specimens (should match)

| File | Rule | Result |
|------|------|--------|
| redflick-behavior-specimen.txt | StarBlizzard_RedFlick_Behavior | MATCH |
| redflick-ioc-specimen.txt | StarBlizzard_RedFlick_Behavior | MATCH |
| redflick-ioc-specimen.txt | StarBlizzard_RedFlick_IOCs | MATCH |

### Match detail — redflick-behavior-specimen.txt

StarBlizzard_RedFlick_Behavior fires via multiple paths:
- Path 1: `$reg_mollis1` + `$task1`/`$task2`/`$task3`
- Path 3: three scheduled task names co-occurring
- Path 4: `$cp_marker1` (CosmicPulse) + `$reg_mollis1`
- Path 5: `$cpl_entry` + `$python38` + `$webdav1`
- Path 7: `$cp_marker1` + `$cp_marker2` (two aliases)

Matched strings: `$reg_mollis1`, `$reg_mollis2`, `$task1`, `$task2`, `$task3`,
`$chain_ssh`, `$chain_cmd`, `$chain_msi`, `$cpl_entry`, `$cp_marker1`,
`$cp_marker2`, `$cp_marker3`, `$python38`, `$python38z`, `$webdav1`,
`$webdav2`, `$webdav3`.

### Match detail — redflick-ioc-specimen.txt

StarBlizzard_RedFlick_Behavior fires via:
- Path 1: `$reg_mollis1` + `$task1`
- Path 3: all three `$task*`

StarBlizzard_RedFlick_IOCs fires via:
- Co-occurrence: 6 domains + 4 IPs (>= 2 of `$dom*`/`$ip*`)
- Also: `$dom1` + `$reg_mollis`

## Benign (should NOT match)

| File | Rule | Result |
|------|------|--------|
| legit-sysadmin-scripts.txt | all | CLEAN |

Benign file contains: generic scheduled task names (Windows Update Health Check,
Disk Cleanup Service), generic registry paths, Python 3.11 runtime, WebDAV shares
to internal servers, DLL exports. None of the campaign-specific indicators.

## Rule design notes

**Tier 1 (technique-level, durable):** StarBlizzard_RedFlick_Behavior — anchors on
the distinctive `.mollis` registry extension (unique to this campaign), the three
specific scheduled task names used for persistence, CPL applet + Python 3.8 bundling
pattern, WebDAV UNC path C2, and CosmicPulse/YESROBOT/BAITSWITCH family names.
Seven detection paths with co-occurrence requirements on each to prevent FPs.

**Tier 2 (indicator-level, moderate):** StarBlizzard_RedFlick_IOCs — six C2 domains
and four IPs. Co-occurrence guard requires either two network indicators together,
or one network indicator alongside a campaign artifact (.mollis key or task name).
Short domain names like `groy.cc` could appear in unrelated contexts; the guard
prevents standalone matches.

**Tier 3 (specimen-pin, fragile):** StarBlizzard_RedFlick_Specimens — five exact
SHA-256 hashes. Will match only the known campaign artifacts; useful for retro hunts
on known samples.

## Campaign context

- Actor: Star Blizzard (COLDRIVER / SEABORGIUM), FSB Centre 18
- Aliases: CosmicPulse = YESROBOT = BAITSWITCH
- Technique: RedFlick — LNK in password-protected archive -> conhost -> cmd -> SSH/curl -> MSI -> CPL DLL -> Python backdoor
- Persistence: scheduled tasks + CPL applet masquerading
- C2: WebDAV UNC paths
- MITRE: T1566.001 (spearphishing attachment), T1059.003 (cmd), T1218.002 (CPL), T1053.005 (scheduled task), T1547.001 (registry run key), T1071 (WebDAV C2)
- Sibling in repo: midnight-blizzard-gtg20006

## Corpus FP test

PENDING — no corpus scan performed yet.
