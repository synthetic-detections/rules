#!/bin/bash
# Legitimate macOS app post-install: sets up a helper LaunchAgent and caches assets.
mkdir -p "$HOME/Library/Application Support/MyApp"
cat > "$HOME/Library/LaunchAgents/com.myapp.helper.plist" <<'PL'
<?xml version="1.0"?><plist><dict><key>Label</key><string>com.myapp.helper</string>
<key>RunAtLoad</key><true/></dict></plist>
PL
osascript -e 'display notification "MyApp installed successfully" with title "MyApp"'
launchctl load "$HOME/Library/LaunchAgents/com.myapp.helper.plist"
security find-generic-password -s "MyApp" -w 2>/dev/null || true
