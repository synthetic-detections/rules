# ClawHavoc YARA rule — test transcript

Companion to `clawhavoc.yar`. Records the smoke-test results so the
rule's expected behaviour is documented alongside the rule itself.

> **No on-disk samples committed.** The original test used *notional*
> specimens (see revision history below). Background research and
> related notes live in `~/repos/another repo/agent-skill-supply-chain/`
> (campaign writeups, IOC dumps); only the rule and this transcript
> moved here. If you want to re-run the smoke test against real samples,
> drop them into a local `specimens/` and `benign/` and follow the
> commands in the table below.

## Environment

| Item | Value |
|---|---|
| YARA version | 4.5.2 (classic), 1.17.0 (YARA-X) |
| Platform | Debian 13 (Linux 6.12) |
| Test date | 2026-05-30 |

## Revision history

| Date | Change |
|---|---|
| 2026-05-30 | Initial 5-file smoke test (notional specimens) |
| 2026-05-30 | Performance hardening — dropped `nocase` from 5 distinctive literals (`$s_phrase_agent_utility`, `$s_important_marker`, `$glot`, `$repo`, `$uploader`); added `filesize < 10MB` upper bound to rule 3 to keep DMG-sized scans fast; verified YARA-X 1.17.0 compatibility with `yr check` (PASS). |

## Test corpus

Five files: three should match, two should not.

| File | Expected | Got |
|---|---|---|
| `specimens/SKILL.md` — malicious skill manifest with verbatim ClawHavoc Prerequisites section | Match `ClawHavoc_SKILL_Prerequisites` + `ClawHavoc_IOCs` | ✓ both |
| `specimens/ioc-dump.txt` — flat IOC list (one C2 IP, repo, uploader) | Match `ClawHavoc_IOCs` only | ✓ |
| `specimens/dropper.macho` — synthetic Mach-O (FAT magic + `jhzhhfomng` signing ID) | Match `ClawHavoc_macOS_Binary` only | ✓ |
| `benign/SKILL.md` — clean youtube-summarizer skill (innocuous Prerequisites referring to env var) | No match | ✓ no match |
| `benign/random.bin` — 5KB urandom | No match | ✓ no match |

## Why the benign SKILL.md doesn't false-positive

The benign skill has its own `Prerequisites` section, references no
binaries, and contains none of:
- The `openclaw-agent utility` phrase (rule 1 anchor)
- `glot.io/snippets/...` (matched by rule 1's `$s_macos_paste_terminal`
  regex and by rule 2's `$glot` literal)
- The `openclaw-agent.zip ... pass: \`openclaw\`` co-occurrence (rule 1's
  Windows leg)
- Any of the C2 IPs, uploader account, or base64 payload (rule 2)

Rule 1's condition requires `$s_phrase_agent_utility` AND one of the two
delivery regexes AND one of the two section-context anchors. A skill
that happens to have a `Prerequisites` section but no
malicious-distribution mechanism (the common case) doesn't satisfy the
middle requirement and is correctly skipped.

## Coverage notes

- **High-confidence campaign matching**: rule 1 will catch SKILL.md
  files that follow the ClawHavoc template even if the operator
  rotates the glot.io snippet ID or the GitHub repo (the regex covers
  the structural pattern, not the specific identifiers).
- **IOC-based corroboration**: rule 2 is the catch-all for any file
  containing the known infrastructure strings. Will fire on threat-
  intel notes legitimately containing the IOCs — this is expected and
  the severity is set to `high` rather than `critical` to reflect it.
- **Mach-O dropper**: rule 3 requires the FAT magic at file offset 0
  AND one of the binary-identifier strings. The `cafebabe` magic alone
  is shared with legitimate universal binaries, so the `jhzhhfomng`
  signing ID (or one of the observed filename hashes) is required to
  fire.

## Caveats

1. The synthetic `dropper.macho` is not a real Mach-O — it's the FAT
   header byte sequence followed by random padding and the signing-ID
   string. A real test should be run against a verified-malicious AMOS
   sample from VT (look up the published hashes: `1e6d4b...e2298` or
   `0e5256...4dd65`).
2. Rule 1 is tuned for the verbatim Koi-Security-disclosed template. If
   the operator rewrites the Prerequisites prose (and they likely will,
   post-disclosure), the `$s_phrase_agent_utility` anchor will start
   missing. Rule 2's IOC list compensates until the infrastructure also
   rotates.
3. None of the rules cover the **Windows binary** specifically — only
   the social-engineering chain that points at it. Pair with a separate
   AMOS-Windows detection rule if you have one in your stack.

## How to invoke

```bash
yara -r -s rules/clawhavoc.yar /path/to/scan/target/
```

For a CI-style gate on a skill registry:

```bash
yara -r rules/clawhavoc.yar /path/to/registry/skills/ \
  | tee /var/log/clawhavoc-scan.log \
  | while read -r match; do echo "FLAG: $match"; done
```

The `-s` flag enables string-output for forensic triage; drop it in
automated pipelines for one-line-per-match output.
