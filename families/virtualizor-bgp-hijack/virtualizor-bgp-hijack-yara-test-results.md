# virtualizor-bgp-hijack — YARA test results

## Rules
- `Virtualizor_BGP_Hijack_Implant_Behaviour` (critical) — injected loader / persistence constellation
- `Virtualizor_BGP_Hijack_IOC` (high) — ne-rat C2 domains + attacker SSH/provider IPs
- `Virtualizor_BGP_Hijack_Payload_Pin` (critical) — SHA-256 hash pin of the published Java payload

## Smoke test
- `specimens/injected-loader-stub.sh` (reconstructed behavioural stub from advisory) →
  matches `Behaviour` + `IOC`. Expected.
- `benign/legit-jre-cron.sh` (legit java-version check + real admin authorized_keys +
  normal /usr/local/virtualizor path) → clean. Expected.

Both results as intended: the behaviour rule needs the ne-rat C2 vocabulary or the
service+account+SSH constellation to co-occur, so an isolated `authorized_keys` edit or a
plain `java -version` on a healthy Virtualizor host does not fire.

## Corpus FP test
Corpus FP scan pending (corpus service unreachable at scan time). To be run and the
slice-size / hits / verdict recorded here once the corpus is reachable.

## Notes
- `globals.php` / `_universal.php` are legitimate Virtualizor filenames; the specimen pins
  the injected loader behaviour, not the whole file. The hash pin targets the published
  payload (`b81a4e1f…`), not the host PHP files.
