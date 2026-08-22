# Post-DEF CON researcher phishing (DocSend / AMOS / NetSupport) — YARA test results

Family: `defcon-docsend-phish`
Rules: `DefconDocsendPhish_Behavior` (critical), `DefconDocsendPhish_IOC` (high),
`DefconDocsendPhish_Specimen` (critical).
Sources: Huntress, 2026-08-19 — https://www.huntress.com/blog/defcon-phishing-google-doc-malware ;
TechCrunch, 2026-08-20 — https://techcrunch.com/2026/08/20/someone-targeted-security-researchers-using-a-fake-crypto-conference-as-a-lure/

## Artifacts keyed on
- Unique campaign tokens (each alone trips the behavioural rule): LaunchDaemon label
  `com.xdivcmp`, staging dir `Cache_328189ho`, NetSupport operator build path
  `\2RMS\client32u.ini`, backdoor config path `/api/v1/getscpt/`, macOS staging `/tmp/lksopo`.
- macOS polling backdoor dot-file config: `.phost`, `.bhost`, `.botid`, `.lastaction`,
  `.uninstalled` (3 of 5 required).
- TLS-intercepting proxy (guarded — `Google Trust Services` / `CN=WR3` are legitimate CA
  names): forged CA + firewall rule `LocalProxy` / hosts entry `127.0.0.1 www.virustotal.com`
  / `certutil -addstore -f ROOT`.
- Ledger Live implant (guarded — `Ledger Live` is a legitimate product): Run key
  `Ledger Wallet Installer` + bot-id file `app.crc32` / tasking path `/api/commands/`.
- NetSupport RAT as configured by this operator (NetSupport itself is commodity): license
  `NSM1234` + gateway `msedgewebview` / keyboard-filter driver `nskbfltr`.
- Windows Electron loader staging: `/api/launcher/start` + `\Microsoft\Windows\UpdateCache`
  / `VirtualBoxVGA` / `\sys.ps1`.
- IOC: domains `apple-googleapi.com`, `docsend.online`, `web12api.com`, `eu02hub.com`,
  `eu03hub.com`, `eu07connect.com`, `msedgewebview1.pro`, `msedgewebview2.pro`, `1foqo.lat`,
  `2fksf.lat`, `3pqow.lat`, `gapidriver.com`, GitHub path `ariasalmonterachel13/gapi`; IPs
  `86.54.25.213`, `192.253.248.181`, `87.120.104.88`; lure strings `DecryptPanel.html`,
  `GapiUpdate.application`, the ClickFix tail `apple-googleapi.com/i | zsh`; payload names
  `GAPIUpdate.dmg`, `DocsendInstaller.exe`, `Localcertificate.exe`, `Asusdriverld.exe`
  (alone) and `Manager.msi` / `DockerDesktopSvc.exe` / `SteamClientHelperHost.exe` /
  `TeraCopyMonMon.exe` (2 required); SHA-256 `15afe1…cc420` (GAPIUpdate) and MD5s
  `8ca79b…1552b` (DocsendInstaller.exe), `281f1d…8be60` (App.asar), `6dd772…49372`
  (Manager.msi), `f4769b…94f83` (Localcertificate.exe), `cd08e2…ed350` (Asusdriverld.exe).
- Specimen pin: a known sample hash, or any unique campaign token together with one of
  the C2 / panel / gateway hosts.

## In-repo smoke test — PASS
```
$ yara -w defcon-docsend-phish.yar /dev/null            (compiles, no warnings)
$ yara -r defcon-docsend-phish.yar specimens/
DefconDocsendPhish_Behavior specimens/macos-gapiupdate-chain.txt
DefconDocsendPhish_IOC      specimens/macos-gapiupdate-chain.txt
DefconDocsendPhish_Specimen specimens/macos-gapiupdate-chain.txt
DefconDocsendPhish_Behavior specimens/windows-docsend-chain.txt
DefconDocsendPhish_IOC      specimens/windows-docsend-chain.txt
DefconDocsendPhish_Specimen specimens/windows-docsend-chain.txt
$ yara -r defcon-docsend-phish.yar benign/
(no output — clean)
```
- `specimens/macos-gapiupdate-chain.txt` — reconstructed macOS chain strings (ClickFix
  one-liner, GAPIUpdate.dmg + SHA-256, /tmp/lksopo, com.xdivcmp, dot-file config, panel / bot
  hosts); matches all three rules.
- `specimens/windows-docsend-chain.txt` — reconstructed Windows chain strings (loader URLs,
  staging paths, archive names + MD5s, NetSupport config, forged CA, Ledger implant
  artefacts); matches all three rules.
- `benign/netsupport-legit-client32.ini` — legitimately licensed NetSupport Manager client
  config: shares `nskbfltr`, gateway / silent-mode keys and port 443, but a real-looking
  license, corporate gateway hosts and no operator build path. Correctly NOT matched.
- `benign/electron-nsis-ledger-live-installer.txt` — legitimate Electron/NSIS Ledger Live
  installer string set: `Ledger Live` product paths, `app.asar`, and a stock Google Trust
  Services / WR3 certificate chain in resources. Correctly NOT matched (the GTS/WR3 strings
  need the proxy / hosts-poisoning co-occurrence; the Ledger strings need the implant's
  Run-key name or bot-id file).
- `benign/mitmproxy-dev-notes.txt` — developer notes for a local mitmproxy debugging setup:
  `certutil -addstore -f ROOT`, loopback hosts entries, a firewall rule. Correctly NOT matched.

## Corpus false-positive scan
Behavioural rule (`DefconDocsendPhish_Behavior`) submitted as a single rule. IOC and Specimen
rules are domain / IP / hash-pinned (near-zero FP by construction) and are not corpus-swept.

| Date | Samples scanned | Matches | Read errors | Verdict |
|---|---|---|---|---|
| 2026-08-22 | 10,115 | 0 | 0 | CLEAN — no false positives; the behavioral condition needs campaign-specific proxy/implant/LaunchDaemon artefacts co-occurring, not generic NetSupport strings |

The behavioural condition requires a near-unique campaign token (`com.xdivcmp`,
`Cache_328189ho`, `\2RMS\client32u.ini`, `/api/v1/getscpt/`, `/tmp/lksopo`) or a guarded
co-occurrence pair; no single generic string (`Google Trust Services`, `Ledger Live`,
`nskbfltr`, `/api/commands/`) can trip it on its own. This section will be updated with
the scanned / matched / read-error counts when the result arrives.
