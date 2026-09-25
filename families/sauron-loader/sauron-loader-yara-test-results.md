# sauron-loader — YARA test results

Family: `sauron-loader`
Rule file: `sauron-loader.yar`
Author: synthetic-detections
Date: 2026-09-25
Rules: `SauronLoader_Behavioral` (critical), `SauronLoader_IOC` (high),
`SauronLoader_Specimen` (critical).
Disclosure: 2026-09-24 — DCSO CyTec, "Sauron Loader: a new loader lurking in underground forums".
Sources:
- https://medium.com/@DCSO_CyTec/sauron-loader-a-new-loader-lurking-in-underground-forums-e91fa70db537
- https://malware.news/t/sauron-loader-a-new-loader-lurking-in-underground-forums/125861
- https://github.com/DCSO/Blog_CyTec/tree/main/2026_09__sauron_loader (config extractor + IOC event)

Environment: YARA 4.5.2 (modules `pe`, `hash`), Debian 13.

## Artifacts keyed on

- **Config stub selector** (DCSO): `E8 00 00 00 00 58 48 83 F9 00 74 06 48 83 F9 01 74 05
  48 8D 40 1A C3 48 8D 80 0D 09 00 00 C3` — call $+5 / pop rax / cmp rcx,0 / cmp rcx,1 /
  lea rax,[rax+imm8] / lea rax,[rax+disp32]. The rule wildcards both branch targets, the imm8
  and the disp32, so a rebuild with a different blob offset still matches.
- **Decrypted config**: Salsa20 blob (16-byte key, 8-byte nonce, size, ciphertext); plaintext
  magic `0xBAADF00D`, flags byte (0x80 CIS check, 0x40 gov-domain check), 1..16 header DWORDs,
  length-prefixed DER RSA private key (1192 B) and RSA-2048 SPKI (294 B), UTF-16 group/build
  IDs, UTF-16 C2 URL array.
- **User-Agent format strings**: Edge 143
  (`Mozilla/5.0 (Windows NT %d.%d; Win64; x64) … Edg/143.0.3650.96`) and IE11/Trident
  (`Mozilla/5.0 (Windows NT %d.%d; Trident/7.0; rv:11.0) like Gecko`), plus the decoy C2
  query vocabulary (`request_id`, `api_key`, `session_token`, `encryption_key`, …).
- **Host artifacts**: `C:\ProgramData\keyroll\` with `rnpkeys.exe` (legitimate RNP side-load
  host), `rnp.dll` (loader), `tdwp.dll` (decrypter / scheduler); scheduled task `keyroll`;
  string `Sauron`; forum alias `S4ur0n`.
- **C2**: `api.namsb-show[.]com`, `api.quinlantours[.]com`, `api.virtual-magic[.]com`,
  `api.lahaina-shores[.]com`, `api.mythicinsights[.]com`.
- **Imphashes**: `cc4a762bd1b2eb3b54dfa46a33d5a50f`, `85b55a5c926f8ef8f4f5f7ca2070c775`,
  `fd90e5c28f1b4156ae7a40859b11e11c`, `f9e79734109d56f4dd73964feeaeffc0` (IOC rule, gated).
- **SHA-256 pins**: seven loader / `tdwp.dll` DLLs and the dropper `test.msi`
  (`ee727d63…d8f2`). The legitimate `rnpkeys.exe` is deliberately not pinned.

## Rule logic

1. `SauronLoader_Behavioral` fires on any one of: the stub selector inside a PE32+ DLL; a
   decrypted config (magic + flags + DER private key at the header offset, with an RSA-2048
   SPKI within 4200 bytes); both UA format strings plus 4 of the decoy query parameters in a
   PE; an MSI (OLE) carrying `keyroll` + `rnpkeys.exe` + `rnp.dll` + `tdwp.dll`.
2. `SauronLoader_IOC` needs two C2 domains, or one C2 domain plus a family anchor (keyroll
   path, `tdwp.dll`, Edge 143 UA, `S4ur0n`, config IDs, or `Sauron` inside a PE), or the
   keyroll path plus `tdwp.dll`, or a published imphash plus a family string in a 64-bit DLL.
   One C2 string alone never fires.
3. `SauronLoader_Specimen` is a SHA-256 pin with a < 1 MB filesize band.

## In-repo smoke test — PASS

```
$ yara -w sauron-loader.yar /dev/null      # compile check
(OK — no warnings)

$ yara -r sauron-loader.yar specimens/
SauronLoader_Behavioral specimens/sauron-config-memdump-synthetic.bin
SauronLoader_IOC        specimens/sauron-config-memdump-synthetic.bin
SauronLoader_Behavioral specimens/sauron-keyroll-dropper-synthetic.msi
SauronLoader_IOC        specimens/sauron-keyroll-dropper-synthetic.msi
SauronLoader_IOC        specimens/sauron-loader-iocs.txt
SauronLoader_Behavioral specimens/sauron-rnp-rotated-synthetic.dll
SauronLoader_Behavioral specimens/sauron-rnp-unpacked-synthetic.dll

$ yara -r sauron-loader.yar benign/
(no output — clean)
```

Specimens (synthetic, structurally correct — no real samples are held):
- `sauron-rnp-unpacked-synthetic.dll` — valid PE32+ DLL with the exact DCSO stub selector, a
  Salsa20-shaped blob, `Sauron`, both UA format strings (UTF-16) and the C2 path/query
  vocabulary. Behavioural (selector and UA branches). IOC does not fire: the C2 hosts are
  only inside the encrypted config, as in the real loader.
- `sauron-rnp-rotated-synthetic.dll` — PE32+ DLL with the selector re-laid out (different
  branch targets, imm8 and disp32) and no plaintext strings. Behavioural only; proves the
  wildcarded selector survives a rebuild.
- `sauron-config-memdump-synthetic.bin` — decrypted config as seen in a memory dump:
  `0xBAADF00D`, flags 0x40, version 1.0.0, 1192-byte DER private key, 294-byte SPKI,
  `test_bot_group_uid` / `test_build_tag_uid`, four UTF-16 C2 URLs. Behavioural + IOC.
- `sauron-keyroll-dropper-synthetic.msi` — OLE header + MSI string-pool fragment installing
  the keyroll triad and a `schtasks /tn keyroll` action. Behavioural + IOC.
- `sauron-loader-iocs.txt` — plain IOC list. IOC.

The specimen-pin rule does not fire on synthetic specimens by design; it pins the published
hashes only.

Benign (structurally similar — must NOT match):
- `legit-telemetry-sdk.dll` — PE32+ DLL with a call/pop GetPC switch stub that compares
  `rcx,2` first (one byte away from the selector), a concrete (non-format) Edge 143 UA, a
  Chrome 142 UA format string and only 5 generic query parameters. Clean.
- `legit-rnp-openpgp-installer.msi` — MSI installing the real RNP tools (`rnpkeys.exe`,
  `rnp.exe`, `librnp.dll`) into Program Files with a "KeyRollover" task. Clean: no
  `tdwp.dll`, and `KeyRollover` / `librnp.dll` are not whole-word `keyroll` / `rnp.dll`.
- `heap-dump-baadf00d-fill.bin` — 1 KB of the Windows LocalAlloc `0xBAADF00D` fill next to an
  unrelated X.509 certificate, with an RSA SPKI far away. Clean: the config branch needs the
  length-prefixed private key right after the header and the SPKI within 4200 bytes.
- `maui-lotr-travel-newsletter.txt` — travel mail naming one C2 registrable domain and the
  word "Sauron" in text. Clean: one domain plus `Sauron` outside a PE is not enough.

Result: 5/5 specimens hit their intended rules (7 hits); 0/4 benign files matched.

## Known residual FP risk

- The stub selector is a generic GetPC + two-way switch idiom. It is only accepted inside a
  64-bit DLL and in the exact `cmp rcx,0` / `cmp rcx,1` / `lea rax,[rax+imm8]` /
  `lea rax,[rax+disp32]` order.
- The imphash branch alone is not trusted: imphashes can be shared by unrelated builds from
  the same toolchain, so it needs a family string or a C2 domain as well.

## Corpus FP test

Each string-based rule was submitted on its own against a down-sampled slice of a large
real-malware corpus (~497k files). `SauronLoader_Specimen` is hash-pinned and has no
false-positive surface, so it is not scanned.

| Rule | Corpus samples | Matches | Read errors | Verdict |
|---|---|---|---|---|
| SauronLoader_Behavioral | 4,479 | 0 | 0 | clean |
| SauronLoader_IOC | 9,275 | 0 | 0 | clean |

No candidate false positives; no tightening was needed. The family is too new to be in the
corpus, so zero hits is the expected result.
