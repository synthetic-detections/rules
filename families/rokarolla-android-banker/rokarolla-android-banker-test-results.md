# Rokarolla Android Banker — Test Results

First Android/APK family in the repository.

## YARA scan results

### Specimens (should match)

| File | Rule | Result |
|------|------|--------|
| mock-rokarolla-dex-behavior.txt | Rokarolla_Banker_Behavior | MATCH (8 typos, 8 unique compounds, 4 overlay, 2 gplay) |
| mock-rokarolla-dex-protocol.txt | Rokarolla_Banker_Behavior | MATCH (via Path 2: $ru_domen + $uniq_keepon) |
| mock-rokarolla-dex-protocol.txt | Rokarolla_Command_Protocol | MATCH (40+ of 42 strings, all 8 capability groups) |
| mock-rokarolla-ioc-report.txt | Rokarolla_IOC | MATCH (4 C2 domains, 1 dist URL, 3 hashes) |

### Benign (should NOT match)

| File | Rule | Result |
|------|------|--------|
| legit-android-accessibility-service.xml | all | CLEAN |
| legit-sms-banking-app.txt | all | CLEAN |

`legit-sms-banking-app.txt` contains 11 individual command strings (`send_sms`, `request_pin`, `unlock_phone`, etc.) but does not trigger any rule — below the 15-string density threshold for Command_Protocol, and missing all typo/unique-compound strings for Banker_Behavior.

## Rule design notes

**Tier 1 (technique-level, durable):** Rokarolla_Banker_Behavior — anchored on developer typos (`distrub_mode`, `disabe_calls`, `stop_keyloger`, `notification_clian`, `noitificationp`, `unlocktraker`) and the Russian loanword `update_config_domen`. These persist across all known samples because fixing them would require refactoring the command dispatcher. 8 typo strings across 6 distinct misspellings.

**Tier 2 (implementation-level, moderate):** Rokarolla_Command_Protocol — catches the 137-command C2 protocol shape. Requires 15+ command strings from the protocol, or specific capability group combinations (credential triad + control, full surveillance suite, overlay hardening). Would survive typo fixes but not a protocol redesign.

**Tier 3 (indicator-level, fragile):** Rokarolla_IOC — C2 domains and sample hashes. 4 domains, 1 distribution URL, 15 of 40 known APK hashes. Will break when infrastructure rotates.

## Campaign context

- No known overlaps with existing families in the repo (first Android family)
- Attribution: unknown; Russian-speaking developer indicators (typos, "domen" loanword)
- 217 targeted banking/crypto apps, 137 commands (more than HOOK's 107)
- Distribution: fake TikTok/Chrome sites → dropper masquerading as Google Play Protect
- IOC source: Zimperium zLabs (github.com/Zimperium/IOC/tree/master/2026-06-Rokarolla/)
