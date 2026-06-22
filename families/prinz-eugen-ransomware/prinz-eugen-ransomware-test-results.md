# Prinz Eugen Ransomware -- YARA Rule Test Results

**Author:** synthetic-detections
**Date:** 2026-06-22
**YARA version:** 4.5.2
**Platform:** Linux 6.12.90+deb13.1-amd64 x86_64

---

## Test Matrix

| File | Type | Expected Rule(s) | Result |
|---|---|---|---|
| `specimens/specimen_encryptor.bin` | Synthetic Go PE (200 KB) | PrinzEugen_Encryptor_Behavior | PASS |
| `specimens/specimen_encrypted.bin` | Synthetic encrypted file (4 KB) | PrinzEugen_Encrypted_File | PASS |
| `specimens/specimen_ioc_report.txt` | Plaintext IOC report (1.8 KB) | PrinzEugen_IOC | PASS |
| `benign/benign_go_binary.bin` | Generic Go PE, no PE indicators (200 KB) | (none) | PASS |
| `benign/benign_random.bin` | Random bytes (4 KB) | (none) | PASS |

**Result: 5/5 PASS -- all rules fire on intended specimens, zero false positives on benign files.**

---

## Specimen Descriptions

### Should-Match

1. **specimen_encryptor.bin** -- Simulated Go PE binary with MZ/PE header. Embeds all Prinz Eugen behavioral strings: `scorched-earth-ausfc` package name, `EncryptFileToKey`, `VerifyEncryptedWithKey`, `.prinzeugen` extension, `CHV1` magic, self-delete pattern, backdoor command. Padded to 200 KB with random bytes.

2. **specimen_encrypted.bin** -- Starts with `CHV1` at offset 0, followed by a simulated version byte, 24-byte nonce, and random ciphertext padding to 4 KB. Mimics the on-disk format of a Prinz Eugen encrypted file.

3. **specimen_ioc_report.txt** -- Plaintext threat intelligence report containing C2 IP `212.80.7.74`, domains (`stndrdbnk.cc`, `g-captchafestung.sbs`, `festung-e.duckdns.org`), stager paths, email addresses, BTC wallet, TOX ID, onion addresses, self-delete command, backdoor command, and actor handles.

### Should-Not-Match (Benign)

1. **benign_go_binary.bin** -- MZ/PE header with Go-like strings (`main.go`, `runtime.go`, `EncryptFile`, `VerifySignature`, `golang.org/x/crypto/nacl`). No Prinz Eugen-specific indicators. Padded to 200 KB.

2. **benign_random.bin** -- 4 KB of pseudorandom bytes. No CHV1 header, no IOC strings.

---

## Raw YARA Output

```
=== SPECIMENS (should-match) ===

$ yara -s prinz-eugen-ransomware.yar specimens/specimen_encryptor.bin
PrinzEugen_Encryptor_Behavior specimens/specimen_encryptor.bin
0x32c:$pkg_name: scorched-earth-ausfc
0x341:$pkg_name: scorched-earth-ausfc
0x361:$func_encrypt: EncryptFileToKey
0x372:$func_verify: VerifyEncryptedWithKey
0x389:$ext: .prinzeugen
0x395:$ext: .prinzeugen
0x3a5:$magic: CHV1
0x3aa:$self_del: ping 127.0.0.1 -n 2
0x3be:$backdoor: admin germania
0x395:$tmp_ext: .prinzeugen.tmp

$ yara -s prinz-eugen-ransomware.yar specimens/specimen_encrypted.bin
PrinzEugen_Encrypted_File specimens/specimen_encrypted.bin
0x0:$magic: CHV1

$ yara -s prinz-eugen-ransomware.yar specimens/specimen_ioc_report.txt
PrinzEugen_IOC specimens/specimen_ioc_report.txt
0x1f6:$c2_ip: 212.80.7.74
0x372:$c2_ip: 212.80.7.74
0x396:$c2_ip: 212.80.7.74
0x3b7:$c2_ip: 212.80.7.74
0x260:$dom_bank: stndrdbnk.cc
0x28f:$dom_captcha: g-captchafestung.sbs
0x2bc:$dom_dyndns: festung-e.duckdns.org
0x37d:$stager_ps1: /serverscan.ps1
0x3a1:$stager_mini: /stager/mini
0x3c2:$stager_main: /stager/ps1
0x482:$tox: 496187425B2944D73FBB17CAF3F9FD569B9ED3A08A497A8314CB4F27A51E65081ACEE1E22F21
0x444:$email_tor: prinzeugen@mail2tor.co
0x464:$email_cock: standardbankcc@cock.li
0x4f6:$btc: bc1q2ztpcvqdaptej6uu2ywt9mrlatx6envu34rf0v
0x546:$onion_active: prinzfkbjiazbrur4mjje6mntjc4vydx3iatkkzycufoylqcoo4y7pqd
0x587:$onion_down: 6cudc5cqa2bjpwdhcwm2lj6dbqejjjqzeo6ipwvmbazr6cgu7vfk3dad
0x5fe:$self_del: cmd.exe /C ping 127.0.0.1 -n 2
0x64b:$backdoor_cmd: net user admin germania /add
0x685:$handle_root: ROOTBOY
0x696:$handle_germ: GERMANIA

=== BENIGN (should-not-match) ===

$ yara -s prinz-eugen-ransomware.yar benign/benign_go_binary.bin
(no output -- no rules matched)

$ yara -s prinz-eugen-ransomware.yar benign/benign_random.bin
(no output -- no rules matched)
```

---

## Why Benign Cases Don't False-Positive

**benign_go_binary.bin:**
- Contains `EncryptFile` but NOT `EncryptFileToKey` -- the rule requires the exact Go symbol name with the `ToKey` suffix.
- Contains `VerifySignature` but NOT `VerifyEncryptedWithKey`.
- Has no `scorched-earth-ausfc` package name, which is the primary anchor for Path 1 of `PrinzEugen_Encryptor_Behavior`.
- Has no `.prinzeugen` extension string or `CHV1` magic, which are required for Path 2.
- Contains no IOC strings (no C2 IPs, domains, emails, BTC wallet, or TOX ID), so `PrinzEugen_IOC` cannot fire.
- File does not start with `CHV1` at offset 0, so `PrinzEugen_Encrypted_File` cannot fire.

**benign_random.bin:**
- First 4 bytes are random (not `CHV1`), so `PrinzEugen_Encrypted_File` cannot match (requires `$magic at 0`).
- At 4 KB the file is below the 100 KB minimum for `PrinzEugen_Encryptor_Behavior`.
- Random bytes are astronomically unlikely to contain any of the long, specific IOC strings needed for `PrinzEugen_IOC`.

---

## Caveats

1. **Synthetic specimens are not real malware.** These files contain embedded strings but lack functional code. They validate that YARA string matching and condition logic work correctly, but do not prove detection of live samples with obfuscation, packing, or string encryption.

2. **PrinzEugen_Encryptor_Behavior imports the `pe` module** but the condition does not gate on `pe.is_pe()`. The rule currently fires on any file in the 100 KB--30 MB range that contains the required string combinations, regardless of whether it is a valid PE. This is intentional (catches memory dumps and unpacked payloads) but worth noting.

3. **PrinzEugen_Encrypted_File has a broad condition** -- `CHV1` at offset 0 plus `filesize > 128` and `< 500MB`. Any non-Prinz-Eugen file that happens to start with the ASCII bytes `CHV1` would match. The 4-byte magic is short enough that false positives on arbitrary file collections are possible, though the string is uncommon in practice.

4. **PrinzEugen_IOC matches on individual IOC strings** like the C2 IP or any domain. In a large corpus of threat reports, security logs, or sandbox output, this rule will fire on any document referencing these IOCs -- this is by design (IOC sweep), not a false positive.

5. **No anti-evasion testing.** These specimens do not test string-splitting, XOR encoding, or other obfuscation techniques that a real operator might use to evade static YARA detection.
