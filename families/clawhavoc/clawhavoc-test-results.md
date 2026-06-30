# ClawHavoc YARA rule — test transcript

Companion to `clawhavoc.yar`. Records the smoke-test results so the
rule's expected behaviour is documented alongside the rule itself.

## Environment

| Item | Value |
|---|---|
| YARA version | 4.5.2 (classic) |
| Platform | Debian 13 (Linux 6.12) |
| Test date | 2026-06-30 |

## Revision history

| Date | Change |
|---|---|
| 2026-05-30 | Initial 3-rule set, 5-file smoke test (notional specimens) |
| 2026-06-30 | Major expansion: 3 → 4 rules. Added 10+ C2 IPs, 13 domains, 6 GitHub repos, 7 ClawHub accounts, 12 URL path slugs, 3 base64 payloads, 9 binary names, paste-site patterns, Windows artifacts (mutexes, persistence, GhostClaw). Rule 1 generalized from template-specific to behavioral pattern matching. Sources: Unit 42, Huntress, Intel 471, JFrog, Antiy, SlowMist, glueckkanja, Pedrinazzi. |

## Test corpus

Five files: three should match, two should not.

| File | Expected | Got |
|---|---|---|
| `specimens/SKILL.md` | Match `ClawHavoc_SKILL_Dropper` + `ClawHavoc_IOCs` | both |
| `specimens/ioc-dump.txt` | Match `ClawHavoc_IOCs` only | match |
| `specimens/dropper.macho` | Match `ClawHavoc_macOS_Binary` only | match |
| `benign/SKILL.md` | No match | no match |
| `benign/random.bin` | No match | no match |

## Rule coverage summary

### Rule 1: ClawHavoc_SKILL_Dropper (behavioral)

Catches malicious SKILL.md / README files with three detection paths:
- **High confidence**: `openclaw-agent utility` phrase + any dropper delivery mechanism
- **Broad behavioral**: Prerequisites/Setup/Installation section header + 2 or more dropper patterns (curl to bare IP, pipe to bash/python, base64 decode pipe, glot.io snippet, rentry.co paste, password-protected ZIP)
- **Anchor-based**: Known campaign phrases (`**IMPORTANT**: This skill requires`, `paste it into Terminal`) + any delivery mechanism

Compared to v1 (which required the exact `openclaw-agent utility` anchor), this catches:
- Skills using rentry.co instead of glot.io
- Skills with rewritten prose but same delivery pattern
- Post-disclosure variants that drop the OpenClaw branding
- Comment-campaign variants (linhui1010-style)

### Rule 2: ClawHavoc_IOCs

Expanded from 8 to 70+ IOC strings across:
- 17 C2 IPs (core + ClickFix + fake-installer campaigns)
- 13 domains (exfil, C2, distribution, fake sites)
- 4 paste-site URLs (glot.io, rentry.co)
- 6 GitHub repos
- 7 ClawHub publisher accounts
- 12 URL path slugs on the primary C2
- 3 base64 payloads
- GhostClaw campaign ID, webhook exfil URL, npm package name

### Rule 3: ClawHavoc_macOS_Binary

Expanded with:
- 9 binary names (was 2)
- 4 AMOS staging paths
- 3 sandbox serial numbers (anti-analysis)
- AMOS exfil endpoint (socifiapp.com)
- VM detection strings for compound conditions

### Rule 4: ClawHavoc_Windows_Artifacts (NEW)

Covers the Windows side of the campaign:
- Stealth Packer mutexes (3)
- Persistence keys and scheduled tasks
- Fake installer binary names (5)
- GhostSocks binary names
- Stealc/AMOS build IDs
- GhostClaw npm RAT persistence artifacts

## Caveats

1. Test specimens are synthetic/notional — real samples should be
   validated from MalShare or VT using the SHA256 hashes documented
   in the research notes.
2. Rule 1's broad behavioral path (header + 2 delivery patterns) could
   false-positive on security-research documents that include both a
   "Prerequisites" section and multiple dropper command examples. The
   256KB filesize cap and requirement for 2+ delivery patterns mitigate
   this in practice.
3. Rule 2 fires on threat-intel documents containing the IOCs — this is
   expected; severity is `high` not `critical`.
4. Rule 4 has not been tested against real Windows PE samples.

## How to invoke

```bash
yara -r -s clawhavoc.yar /path/to/scan/target/
```
