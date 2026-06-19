# Rokarolla Android Banker — Test Results

First Android/APK family in the repository.

## YARA scan results

### Mock specimens (should match)

| File | Rule | Result |
|------|------|--------|
| mock-rokarolla-dex-behavior.txt | Rokarolla_Banker_Behavior | MATCH (8 typos, 8 unique compounds, 4 overlay, 2 gplay) |
| mock-rokarolla-dex-protocol.txt | Rokarolla_Banker_Behavior | MATCH (via Path 2: $ru_domen + $uniq_keepon) |
| mock-rokarolla-dex-protocol.txt | Rokarolla_Command_Protocol | MATCH (40+ of 42 strings, all 8 capability groups) |
| mock-rokarolla-ioc-report.txt | Rokarolla_IOC | MATCH (4 C2 domains, 1 dist URL, 3 hashes) |

### Real samples from MalwareBazaar (should match)

| Hash | Pkg name | Banker_Behavior | Command_Protocol | IOC |
|------|----------|-----------------|------------------|-----|
| be8573...d378d34 | com.fav.qca | MATCH (Path 7: comp_overlay + comp_smsrecv wide) | no (packed) | MATCH ($pkg_fav) |
| fe41e6...f3dadf | com.oel.myx | MATCH (Path 7: comp_overlay + comp_smsrecv wide) | no (packed) | MATCH ($pkg_oel) |

Command_Protocol does not fire on packed APKs — by design. The command strings are encrypted inside Cyrillic-obfuscated asset paths and only visible after runtime unpacking. Rules 1 and 3 provide coverage for the distributed form.

### Benign (should NOT match)

| File | Rule | Result |
|------|------|--------|
| legit-android-accessibility-service.xml | all | CLEAN |
| legit-sms-banking-app.txt | all | CLEAN |

`legit-sms-banking-app.txt` contains 11 individual command strings (`send_sms`, `request_pin`, `unlock_phone`, etc.) but does not trigger any rule — below the 15-string density threshold for Command_Protocol, and missing all typo/unique-compound strings for Banker_Behavior.

## Rule design notes

**Tier 1 (technique-level, durable):** Rokarolla_Banker_Behavior — two detection surfaces:
- *Unpacked DEX:* developer typos (`distrub_mode`, `disabe_calls`, `stop_keyloger`, `notification_clian`, `noitificationp`, `unlocktraker`) and the Russian loanword `update_config_domen`. 8 typo strings across 6 distinct misspellings.
- *Packed APK:* component names in UTF-16LE string pool (`MyOverlayActivity` + `SmsChangeReceiver`) persist across both observed variants despite code-level packing. Path 8 adds root detection libraries as supporting signal. Path 9 requires 3+ of 4 component names.

**Tier 2 (implementation-level, moderate):** Rokarolla_Command_Protocol — catches the 137-command C2 protocol shape. Requires 15+ command strings from the protocol, or specific capability group combinations. Fires on unpacked DEX only.

**Tier 3 (indicator-level, fragile):** Rokarolla_IOC — C2 domains, sample hashes, and observed package names (`com.fav.qca`, `com.oel.myx`). Package names likely rotate per build. Will break when infrastructure rotates.

## Sample analysis notes

Two of 40 Zimperium-published hashes found on MalwareBazaar (0 on MalShare). Both APKs are heavily packed:
- AndroidManifest.xml uses non-standard ZIP compression method 61923
- Asset paths contain Cyrillic obfuscation characters (Ы¦, Ы–, Ы«)
- DEX files are stub loaders — no Rokarolla command strings visible via `strings`
- Target app list (217 banking/crypto apps) is not embedded; fetched at runtime from C2 via `monitored_app_full` command
- Root detection present in second variant (rootcloak, koushikdutta.superuser, noshufou.android)
- App masquerades as Reface (face-swap app) in first variant

## Campaign context

- No known overlaps with existing families in the repo (first Android family)
- Attribution: unknown; Russian-speaking developer indicators (typos, "domen" loanword)
- 217 targeted banking/crypto apps, 137 commands (more than HOOK's 107)
- Distribution: fake TikTok/Chrome sites → dropper masquerading as Google Play Protect
- IOC source: Zimperium zLabs (github.com/Zimperium/IOC/tree/master/2026-06-Rokarolla/)
