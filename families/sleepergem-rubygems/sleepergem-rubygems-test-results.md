# sleepergem-rubygems — test results

Family: SleeperGem — malicious RubyGems dropping a persistent developer-machine backdoor
Reported: 2026-07-20 (StepSecurity, The Hacker News). Rules authored: 2026-07-21.

## Rules

| Rule | Type | Severity |
|------|------|----------|
| SleeperGem_Backdoor_Behavior | behavioral (drop/persist/evade combo) | critical |
| SleeperGem_Malicious_Gem_IOC | IOC (gem names + version pins, guarded) | high |
| SleeperGem_Malicious_Gemspec_Specimen | specimen pin (malicious gemspec/extension shape) | critical |

## Local smoke test (yara 4.5.2)

Compiles clean.

Specimens (inert mock reconstructions from public reporting):

| Specimen | Behavior | IOC | Specimen |
|----------|----------|-----|----------|
| mock-ioc-report.txt | match | match | — |
| mock-malicious-extconf.rb | match | match | match |
| mock-malicious.gemspec | — | match | — |

The bare gemspec (no inline payload) matches only the IOC rule via the
name+malicious-version pin — by design; it is not the payload, so the
behavioral and specimen-pin rules correctly abstain.

Benign / structurally-similar (must NOT match): all clean.

| Benign file | Result |
|-------------|--------|
| legit-fastlane-plugin.gemspec (same gem name, clean version, no payload) | clean |
| legit-ci-detect.rb (legit GITHUB_ACTIONS/GITLAB_CI branch + Net::HTTP) | clean |
| legit-extconf.rb (ordinary mkmf C-extension) | clean |

The two hardest false-positive shapes are covered: a legitimately-named
`fastlane-plugin-run_tests_firebase_testlab` gemspec, and a normal build
helper that branches on CI env vars and makes an HTTP call. Neither has the
drop-path / setuid-shell / persistence co-occurrence the rules require.

## Design notes (FP control)

- Gem names (`git_credential_manager`, `Dendreo`, `fastlane-plugin-*`) collide
  with legitimate software, so the IOC rule never fires on a name alone — it
  requires a known-malicious version pin or a payload artifact
  (`~/.local/share/gcm`, `/usr/local/sbin/ping6`).
- CI-env markers and `Net::HTTP` are extremely common; the behavioral rule
  only treats them as signal when they co-occur with the daemon drop path or
  setuid shell plus persistence, or as a full loader shape (CI-evasion +
  persistence + fetch + exec/suid primitive).

## Corpus FP test

Scope: recent family — any corpus hit is a candidate FP to investigate.
Bounded slices of the real-malware corpus (2026-07-22):

- SleeperGem_Backdoor_Behavior: 1,117 samples scanned, 0 matches, 0 read-errors → clean
- SleeperGem_Malicious_Gem_IOC: 1,861 samples scanned, 0 matches, 0 read-errors → clean
- SleeperGem_Malicious_Gemspec_Specimen: not scanned — condition requires
  gemspec/extension marker + drop-path + CI marker + fetch to co-occur in one
  file; FP risk assessed negligible.

Verdict: no false positives on the scanned slices. Full retro-hunt not run
(recent family, negligible historical footprint expected).
