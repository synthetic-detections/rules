#!/bin/sh
# Benign macOS app installer that writes its own (non-disguised) LaunchAgent.
# Uses LaunchAgents dir + launchctl but does NOT impersonate WindowServer and
# has no anti-analysis / beacon artifacts.
AGENT="$HOME/Library/LaunchAgents/com.examplecorp.updater.plist"
cat > "$AGENT" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>com.examplecorp.updater</string>
  <key>ProgramArguments</key><array><string>/Applications/ExampleCorp.app/Contents/Helpers/updater</string></array>
  <key>StartInterval</key><integer>86400</integer>
</dict></plist>
PLIST
launchctl load "$AGENT" 2>/dev/null
