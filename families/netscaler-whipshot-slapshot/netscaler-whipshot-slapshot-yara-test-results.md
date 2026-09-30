# netscaler-whipshot-slapshot — YARA test results

Family: WHIPSHOT (PHP web shell) + SLAPSHOT (Python SOCKS tunneler), post-exploitation on
Citrix NetScaler ADC/Gateway after CVE-2026-88771 / CVE-2026-88772 (mass exploitation 2026-09-29).
Rules: `NetScaler_WHIPSHOT_SLAPSHOT_Behavior` (critical), `NetScaler_WebShell_httpd_Handler_Abuse`
(high), `NetScaler_WHIPSHOT_WebShell_SpecimenPin` (critical, SHA-256 pin).

## Smoke test
- specimens/ (should match):
  - `whipshot_receiver.php`  → NetScaler_WHIPSHOT_SLAPSHOT_Behavior ✓
  - `slapshot_daemon.py`     → NetScaler_WHIPSHOT_SLAPSHOT_Behavior ✓
  - `malicious_httpd.conf`   → NetScaler_WebShell_httpd_Handler_Abuse ✓
- benign/ (should NOT match) — all clean:
  - `normal_app.php` (legit fsockopen to a DB), `socks_proxy.py` (generic SOCKS relay, no UXD
    markers/IPC), `normal_httpd.conf` (standard Apache config with .php handler + AliasMatch) ✓
Specimens are reconstructed from published Mandiant/GreyNoise string IOCs (no public sample hashes
for WHIPSHOT/SLAPSHOT were released; the SpecimenPin uses the one GreyNoise web-shell SHA-256).

## Corpus FP test
- `NetScaler_WHIPSHOT_SLAPSHOT_Behavior`: recent-corpus slice (~1,000 samples), 0 matches — no
  candidate false positives; the co-occurrence guards (header dispatch + `/tmp/.uxd*` IPC + socket,
  or the UXD env marker + IPC + ≥3 SLAPSHOT verbs) hold up.
- `NetScaler_WebShell_httpd_Handler_Abuse`: recent-corpus slice (~1,600 samples), 0 matches — no candidate false positives; the `.deb`/`.sig`→PHP handler + NetScaler-path scoping avoids normal Apache configs.
- `NetScaler_WHIPSHOT_WebShell_SpecimenPin`: exact-hash rule, no false-positive surface.

Notes: rules bound by `filesize` (< 80KB / 64KB); the handler-abuse rule is scoped to the
NetScaler-specific `.deb`/`.sig`→PHP handler abuse + NetScaler staging paths so a normal Apache
`.php` AddHandler + AliasMatch does not trip it (verified in benign/).
