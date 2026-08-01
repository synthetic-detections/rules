# genielocker-ransomware - test results

Family: GenieLocker (Toy Ghouls / Bearlyfy) cross-platform ransomware
Disclosed: 2026-07-31 (Kaspersky GReAT); active since 2026-03
Rules authored: 2026-08-01

## Rules
- `GenieLocker_Ransomware_Behavior` (critical) - anchors on campaign-unique constants: the
  `.03ffc1c4a3da0f02` extension, `VCJOURN` journal magic, exact process/service kill-list fragments,
  and the ESXi `/etc/vmware/welcome` rewrite + `Curve25519-XSalsa20-Poly1305` key-wrap combo. MZ/ELF
  gated. Does NOT key on generic libsodium/XChaCha20 strings.
- `GenieLocker_IOC` (high) - encrypted-file extension, C2 89.125.66[.]101, and 5 representative MD5
  pins (of 24 recorded to the digest hash store).

## Smoke test (in-repo)
Specimens (should match):
```
GenieLocker_IOC                     specimens/iocs.txt
GenieLocker_Ransomware_Behavior     specimens/genielocker.elf.bin
GenieLocker_IOC                     specimens/genielocker.elf.bin
```
Benign (should NOT match): clean - `benign/legit_libsodium_tool.elf.bin` (real libsodium/XChaCha20
backup tool, none of the campaign constants). This is the key FP guard: GenieLocker uses stock
libsodium primitives, so the rules must anchor on the unique extension/journal-magic/kill-lists, not
the crypto. Confirmed clean.
Result: PASS on first compile.

## Corpus FP test
PENDING - the corpus-scan service unreachable during the autonomous-run week. Re-run:
a corpus false-positive scan.
Low FP risk: the extension and VCJOURN magic are campaign-unique; the kill-list fragments are the
exact GenieLocker strings.

## Notes
- 24 MD5 hashes recorded to the digest store (family=genielocker); all absent on MalShare at
  authoring time.
- No ransom note is dropped and no exfiltration (single-extortion), so there is no note-filename or
  onion-URL artifact to pin.
- Related in-repo ransomware: prinz-eugen-ransomware.
