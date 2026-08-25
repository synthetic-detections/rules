# gunra-ransomware — YARA test results

Source: CISA/FBI/DoD/NSA/USSS + KNPA joint #StopRansomware advisory **AA26-222A**
(2026-08-10). Gunra is a Conti-derived double-extortion RaaS (alias "Golden
Community"); ChaCha20 + RSA-4096; `.ENCRT` extension (older `.CRYPT`), `R3ADM3.txt`
note; Fortinet CVE-2024-55591 / CVE-2025-24472 for initial access.

## Rules

| Rule | Severity | Keys on |
|------|----------|---------|
| Gunra_Encryptor | critical | PE + .ENCRT/.CRYPT ext + R3ADM3 note name |
| Gunra_Ransom_Note | high | note body: .ENCRT + qTox + one of (Client ID / Tor / R3ADM3) |
| Gunra_Campaign_C2 | high | ≥2 of the advisory C2 IPs + datapub.news mirror |

## In-repo smoke test

```
$ yara -r gunra-ransomware.yar specimens/
Gunra_Encryptor specimens//gunra_encryptor.bin
Gunra_Campaign_C2 specimens//c2_list.txt
Gunra_Ransom_Note specimens//R3ADM3.txt

$ yara -r gunra-ransomware.yar benign/
(no output — clean)
```

Gunra is Conti-derived, so the benign set includes a **generic Conti-style ransom
note** (`.locked` ext, no Gunra markers) to prove the rules don't fire on the
shared lineage; plus a normal anti-debug PE (has `IsDebuggerPresent` but no
`.ENCRT`/`R3ADM3`) and a single-C2-IP note (guards the ≥2 count).

Note: the ransom note is the file *named* `R3ADM3.txt`; its body does not
necessarily contain the literal string `R3ADM3`, so Gunra_Ransom_Note keys on the
extortion text co-occurrence (`.ENCRT` + `qTox` + Client ID/Tor) rather than the
filename, which YARA does not see.

## Corpus FP test

PENDING — corpus-scan service unavailable at authoring time (DNS resolution
failure to the scan host). Higher latent FP risk than the other two families
because of the Conti lineage, so the encryptor rule requires the Gunra-specific
`.ENCRT`/`.CRYPT` **and** `R3ADM3` co-occurrence, never generic Conti strings.
Re-run per rule on a recent slice once reachable; any hit is a candidate FP.

## Notes

- Hashes are in the advisory's downloadable IOC package (not the HTML body); add
  to the digest hash store when retrieved.
- Attribution: financially motivated RaaS, Conti code lineage; no state nexus.

## Update 2026-08-22 — FP tightening
C2 condition changed from `2 of them` to `filesize < 2MB and ($mirror or 3 of ($i*))`: the IP strings are substring matches (23.239.119.2 ⊂ 23.239.119.20-29), so a bare 2-of false-positived on asset inventories/netflow. Now requires the distinctive clearnet DLS mirror or three co-occurring C2 IPs under a filesize guard. Smoke test re-run: specimens hit, benign clean.

## Update 2026-08-25 — fullword anchoring on C2 IPs
The 3-of count guard alone did not close the substring class: $i1–$i5 are the
contiguous block 23.239.119.2..6, and each is a substring of longer IPs in the
same /24, so a benign subnet inventory listing e.g. 23.239.119.20 / .35 / .48
matched $i1/$i2/$i3 and satisfied `3 of ($i*)`. All thirteen IP strings now
carry `fullword` (the same anchoring the dynowiper/gentlekiller siblings use),
so a match requires non-alphanumeric boundaries on both sides.

Regression sample added: `benign/subnet_inventory.txt` — a netflow/asset
inventory with five adjacent-/24 IPs (23.239.119.20/.35/.48/.57/.63). The
pre-fix rule fires Gunra_Campaign_C2 on it (three substring hits); the fixed
rule is silent, so `yara -r gunra-ransomware.yar benign/` catches any
reintroduction of the substring match.

The `yara` binary was unavailable in the authoring session, so the smoke test
could not be re-run locally; string semantics were verified with boundary
regexes (`(^|[^0-9A-Za-z])<ip>($|[^0-9A-Za-z])`): zero fullword hits in
`benign/subnet_inventory.txt`, and `specimens/c2_list.txt` still matches $i1,
$i6, and $mirror (fires via $mirror regardless). CI smoke test validates on
push.
