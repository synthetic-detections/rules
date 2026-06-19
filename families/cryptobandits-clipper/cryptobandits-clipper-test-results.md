# CryptoBandits Clipper — Test Results

## YARA scan results

### Specimens (should match)

| File | Rule | Result |
|------|------|--------|
| mock-cryptobandits-clipper.js | CryptoBandits_Clipper_Behavior | MATCH |
| mock-cryptobandits-clipper.js | CryptoBandits_Worm_Structure | MATCH |
| mock-cryptobandits-ioc-report.txt | CryptoBandits_IOC | MATCH |

### Benign (should NOT match)

| File | Rule | Result |
|------|------|--------|
| legit-clipboard-utility.js | all | CLEAN |
| legit-tor-browser-config.txt | all | CLEAN |

Initial draft had false positive on `legit-clipboard-utility.js` via Worm_Structure Path 3 (.lnk + WSH) and Path 6 (ActiveXObject + schtasks + .lnk) — tightened to require `\Users\Public\Documents\` staging path or `.onion` C2 indicators alongside .lnk creation.

## Rule design notes

**Tier 1 (technique-level, durable):** CryptoBandits_Clipper_Behavior — C2 protocol action codes (GUID/SEED/PKEY/REPL/EVAL/GOOD), Tor SOCKS5 proxy via localhost:9050, renamed Tor binary (ugate.exe), anti-analysis via WMI Win32_Process Task Manager detection, clipboard crypto monitoring (bc1q/bc1p/BIP39/WIF).

**Tier 2 (implementation-level, moderate):** CryptoBandits_Worm_Structure — JavaScript payload staged in `\Users\Public\Documents\`, scheduled task XML wrapping, USB .lnk worm propagation, curl-to-.onion C2 pattern, clipboard get/set + screenshot + AV exclusion path.

**Tier 3 (indicator-level, fragile):** CryptoBandits_IOC — 10 Tor .onion C2 domains, 16 SHA-256 hashes (8 worm + 8 clipper), ugate.exe filename.

## Campaign context

- No known overlaps with existing families in the repo
- Attribution: unattributed; active since February 2026
- Microsoft detection names: Trojan:Win32/CryptoBandits.A/.B, Trojan:JS/CryptoBandits.A/.B
- Targets: Bitcoin (legacy/P2SH/Bech32/Taproot), Tron, Monero wallets + BIP39 seed phrases
- Propagation: USB .lnk worm + scheduled task persistence
- C2: HTTP over Tor hidden services (10 .onion domains), EVAL command = full RCE
- MITRE: T1091 (removable media), T1059 (scripting), T1115 (clipboard), T1113 (screen capture), T1090 (Tor proxy)
