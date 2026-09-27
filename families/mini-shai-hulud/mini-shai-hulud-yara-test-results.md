# Mini Shai-Hulud — YARA test results

Family: `mini-shai-hulud`
Date: 2026-09-27
Rule file: `mini-shai-hulud.yar`

## In-repo smoke test

### Specimens (should match)

| File | Rule(s) matched |
|------|----------------|
| `specimens/core-payload-markers.txt` | `MiniShaiHulud_CorePayload` |
| `specimens/deaddrop-markers.js` | `MiniShaiHulud_CorePayload` |
| `specimens/github-action-ioc.yml` | `MiniShaiHulud_GitHubAction_IOC` |
| `specimens/fbi-flash-hash-dump.txt` | `MiniShaiHulud_SpecimenPin` |

All 4 specimens matched expected rules. **PASS**

### Benign (should NOT match)

| File | Rule(s) matched |
|------|----------------|
| `benign/legitimate-github-action.yml` | (none) |
| `benign/legitimate-credential-config.js` | (none) |
| `benign/legitimate-vscode-tasks.json` | (none) |

All 3 benign files clean. **PASS**

## Corpus FP test

Corpus FP scan pending.

## Design notes

Three-rule shape:

1. **MiniShaiHulud_CorePayload** (critical) — behavioural: hardcoded string constants shared across ALL delivery variants (encryption salt `svksjrhjkcejg`, dead-man's-switch string, `FIRESCALE` C2 keyword, repo marker, PyPI marker, service persistence names, payload filenames + credential-sweep co-occurrence). Any single high-confidence marker fires; weaker signals require co-occurrence of 2+ persistence/dead-drop markers or payload filenames + credential targets.

2. **MiniShaiHulud_GitHubAction_IOC** (high) — IOC: covers the actions-cool/issues-helper and maintain-one-comment GitHub Action hijack vector, the exfil domain `m-kosche.com`, and dev-config poisoning paths (`.claude/settings.json`, `.vscode/tasks.json`). Co-occurrence guards prevent firing on legitimate uses of individual action references or dev config paths.

3. **MiniShaiHulud_SpecimenPin** (critical) — hash pin: FBI FLASH-20260702-01 published SHA-256 values for three core TeamPCP payloads. Fires on any match.

## Sibling families

- `miasma-redhat-npm` — @redhat-cloud-services npm preinstall variant
- `miasma-azure-aiagent` — Azure durabletask AI-agent-config trigger variant
- `miasma-v2-phantom-gyp` — binding.gyp + forged SLSA variant
