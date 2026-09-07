# StyleSmuggler — YARA/Suricata test results

Family: `stylesmuggler-magento-backdoor`
Rules: `stylesmuggler-magento-backdoor.yar` (3), `stylesmuggler-magento-backdoor.rules` (Suricata, 2)
Source: Sansec, https://sansec.io/research/stylesmuggler (disclosed 2026-09-05)

## Rules
1. `StyleSmuggler_Rust_Backdoor_HostArtifacts` (critical) — requires >=2 of four on-disk
   artifact categories: `[kworker/u:8:0]` process masquerade, `~/.local/share/.gvfsd/`
   persistence dir/binary, StyleSmuggler-specific hidden `/tmp/.kw_` `/tmp/.fc-` drops, and
   crontab persistence lines. The 2-category floor keeps a lone `fc-cache` reference from firing.
2. `StyleSmuggler_C2_Infrastructure` (high) — typosquat C2 + download hosts
   (windwsecurity.run, ntp.timesysnc.net, time.microsft.run, pool.microsft.studio, *.to NTP
   fallbacks, 247.cdnflare.xyz). Co-occurrence guard: >=2 C2 indicators, or 1 C2 + an implant
   marker, so a single incidental domain does not fire.
3. `StyleSmuggler_Backdoor_KnownHashes` (critical) — SHA-256 pins for the four Sansec builds
   (Rust backdoor + variant + kworker-linux x64/arm64).

## Smoke test
- `specimens/synthetic_stylesmuggler_implant.txt` (reconstructed host artifacts from the Sansec
  IOC list; no live sample was available) → **StyleSmuggler_Rust_Backdoor_HostArtifacts** and
  **StyleSmuggler_C2_Infrastructure** both fire. PASS.
- Hash-pin rule does **not** match the synthetic specimen (expected — it pins the real sample
  SHA-256s; the four hashes were absent from public sample stores at authoring time).
- `benign/benign_fontconfig_fccache.txt` (legitimate `fc-cache`/fontconfig maintenance, normal
  `[kworker/0:1]` kernel thread, `/tmp/fontbuild-*`, `/var/cache/fontconfig/`) → **clean**. PASS.

## Corpus FP test
- Corpus false-positive scan pending; results to be recorded here on completion.

## Notes
- Suricata sigs (`.rules`) target the HTTP exploit: the `styles[...]` GraphQL PHP injection and
  the `/paypal/transparent/response/` `eval(base64_decode(...))` payload. Private SID range.
- The email trigger ("Payment Transaction Failed Reminder") is server-internal render, not a
  network artifact, so it is documented but not signatured.
