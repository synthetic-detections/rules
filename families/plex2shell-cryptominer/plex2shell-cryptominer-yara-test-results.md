# Plex2Shell — YARA test results

Rule file: `plex2shell-cryptominer.yar` (3 rules)
Family: `plex2shell-cryptominer`
Sources: The Hacker News, Security Affairs, SecurityWeek, cybercrime.club.

## Rules
1. `Plex2Shell_Proxyware_Behavior` (critical) — AISURU residential proxy
   consent banner "Running this software on any of your devices makes you
   agree to the potential external use of your internet traffic" or the
   myawesomeproxy process name with proxystream infrastructure strings.
2. `Plex2Shell_Miner_Behavior` (high) — XMRig miner with campaign-specific
   indicators: mylovelyminer/x12345 process names co-occurring with the
   ota.proxystream.st mining pool or XMRig config patterns (algo, randomx,
   stratum).
3. `Plex2Shell_Campaign_IOCs` (high) — SHA256 hashes of post-exploitation
   binaries (x12345 miner + myawesomeproxy backdoor) + C2/mining IPs
   (217.60.194.116, 91.92.40.202, 176.65.139.228, 45.194.92.222) +
   proxystream.st domains. Atomic, decay expected.

Not covered (by design): the exploit chain itself (SSRF → token leak →
transcoder SSRF → Codecs .so write) produces no static file artifacts
amenable to YARA. The chain is covered by Suricata rules in the .rules
file. The malicious .so dropped into the Codecs directory is campaign-
specific and no sample is publicly available.

## In-repo smoke test

Environment: YARA 4.5.2, Linux x86_64, 2026-10-27.

`yara -r plex2shell-cryptominer.yar specimens/` → 5 hits:

| Specimen | Rule(s) matched |
|---|---|
| `proxyware-consent-banner.bin` | `Plex2Shell_Proxyware_Behavior` + `Plex2Shell_Campaign_IOCs` |
| `miner-config-fragment.json` | `Plex2Shell_Miner_Behavior` + `Plex2Shell_Campaign_IOCs` |
| `campaign-ioc-sweep.txt` | `Plex2Shell_Campaign_IOCs` |

`yara -r plex2shell-cryptominer.yar benign/` → **0 hits (clean)**.

Benign set: `legit-plex-plugin.txt` contains "Protocol: http" and
"Proxy: false" but no campaign-specific strings.

## Corpus FP test

PENDING — jobs 47, 50-52 submitted to yaragate, awaiting results.
