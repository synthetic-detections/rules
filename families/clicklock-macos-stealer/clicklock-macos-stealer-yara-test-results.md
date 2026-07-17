# clicklock-macos-stealer — YARA test results

Family: ClickLock macOS infostealer (Group-IB, disclosed 2026-07-16). Delivered via ClickFix;
osascript password coercion + process kill-loop; Keychain/browser/wallet theft; GSocket backdoor.

Rules:
- `ClickLock_macOS_Stealer_Behavior` (critical) — orchestrator/module shell + osascript patterns.
- `ClickLock_macOS_Stealer_IOC` (high) — C2 domains, LaunchAgent labels, sample SHA1 hashes.
- `ClickLock_macOS_Stealer_Specimen` (critical) — tight distinctive-artifact pin.

## In-repo smoke test
- **Specimen (1):** `clicklock_orchestrator_reconstructed.sh` — a reconstruction from the public
  Group-IB artifacts (not the original sample; strings/paths/hashes mirror the documented orchestrator
  and modules). Matches **all three rules**.
- **Benign (1):** `legit-app-postinstall.sh` — a structurally similar legitimate macOS post-install
  script (installs a LaunchAgent, calls `osascript`, queries the Keychain). **Clean** — confirms the
  co-occurrence guards (ClickFix banner / kill-loop sleep / `.cacheb` staging / `com.authirity`+
  `com.chromer` labels) separate the malware from ordinary installer behaviour.

## Detection artifacts (Group-IB)
- LaunchAgents: `com.authirity.plist`, `com.chromer.plist`
- Staging: `~/.cacheb/`, `~/.cacheb/<user>-chrome-key.txt`, `finder_output.txt`,
  `Application Support/iCloudsync` (GSocket disguise)
- Kill-loop: `killall` of Finder/Dock/Activity Monitor/… on `0.210`s (200ms in Keychain module)
- Keychain theft: `security find-generic-password -wa "Chrome"`
- ClickFix banners: "Verifying you are not a bot", "Collecting browser signals",
  "CLOUDFLARE CAPTCHA ACCESS CONTROL"
- C2: `panalobet[.]ph`, `store.grafsynergy[.]com`, `cottonbox[.]co[.]il`, `gsnc[.]eu:67`,
  `api.telegram.org` (exfil)
- Sample SHA1: script.sh, chromer.txt, zsh.txt, finderv2.jpg, goyim (5 hashes pinned in the IOC rule)

## Corpus false-positive scan
Scanned against the broad malware corpus (recent slice). Both rules clean:
- `ClickLock_macOS_Stealer_Behavior`: 11,839 samples scanned, **0 matches**, 0 read-errors.
- `ClickLock_macOS_Stealer_IOC`: 11,171 samples scanned, **0 matches**, 0 read-errors.

No candidate false positives. The Behavior rule's co-occurring ClickFix-banner + kill-loop/Keychain
guards and the IOC rule's exact-hash / domain+label co-occurrence held up across the slice.
