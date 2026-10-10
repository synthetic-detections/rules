#!/bin/bash
# Mock TraderTraitor FLATROOF loader
# Tests: TraderTraitor_FLATROOF_Behavioral (paths 1, 2, 4, 5, 7, 8)

# Loader AES key for decrypting .woff payloads
AES_KEY="PTa3WZPQZAjj55t@"

# Config decryption key
CONFIG_KEY="u73adF39ZT"

# Config AES key
CONFIG_AES="a9d932dcfa3289a6"

# End-of-font marker that terminates encrypted payloads
ENDFONT_MARKER="@@ENDFONT@@"

# Run-once marker
LOCKFILE="session.lock"

# Install paths (cross-platform logic)
LINUX_PATH=".config/git/update"
MACOS_PATH="Library/com.apple.iTunesCloud/SystemUpdate"
WINDOWS_PATH="AppData/Local/Microsoft/Edge/service.exe"

# Persistence names
PERSIST_SNAP="snap-imagent"
PERSIST_MACOS="imagent"
PERSIST_WIN="powershell-config-service"

# Wallet targets
TARGET1="MetaMask"
TARGET2="Phantom"
TARGET3="Trust Wallet"
TARGET4="Rabby"
