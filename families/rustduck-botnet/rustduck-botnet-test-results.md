# RustDuck Botnet — YARA Test Results

**Date:** 2026-07-01
**YARA version:** 4.5.2 (classic), Linux x86_64
**Rule file:** `rustduck-botnet.yar`

## Specimen matrix

| File | Expected rule | Result |
|---|---|---|
| `specimens/rustduck-behavior-specimen.bin` | `RustDuck_Botnet_Behavior` | MATCH |
| `specimens/rustduck-loader-v3-specimen.bin` | `RustDuck_ELF_Loader` | MATCH |
| `specimens/rustduck-ioc-specimen.bin` | `RustDuck_IOC` | MATCH |
| `benign/benign-elf-tools.bin` | (none) | NO MATCH |
| `benign/benign-urandom.bin` | (none) | NO MATCH |

## Raw output

### Specimens

```
RustDuck_Botnet_Behavior rustduck-behavior-specimen.bin
0x74:$dbg_wireshark: wireshark
0x7e:$dbg_tcpdump: tcpdump
0x86:$dbg_gdb: gdb
0x8a:$dbg_ida: ida
0x90:$dbg_ida: ida
0x8e:$dbg_frida: frida
0x94:$proc_status: /proc/self/status
0xa6:$proc_maps: /proc/self/maps
0xb6:$hp_cowrie: /etc/cowrie/
0xc3:$vm_vbox1: virtualbox
0xce:$vm_vbox2: vbox
0xd3:$vm_bochs: bochs
0xd9:$vm_vmware: 08:00:27
0xe2:$env_sandbox: sandbox
0xea:$env_malware: malware
0xf2:$env_virus: virus
0xf8:$env_sample: sample
0xff:$cry_hkdf: HKDF
0x104:$cry_ascon: Ascon128
0x10d:$cry_chacha: ChaCha20
0x116:$cry_noise: Noise_IK

RustDuck_ELF_Loader rustduck-loader-v3-specimen.bin
0x523c:$magic_v3: ASHPCK\x01\x00
0x52c4:$lz4_decomp1: LZ4_decompress
0x52da:$cfg_loader: loader
0x52d3:$cfg_config: config
0x52e1:$kex_curve: curve25519

RustDuck_IOC rustduck-ioc-specimen.bin
0x30:$c2_01: gayporn.twilightparadox.com
0x16:$c2_05: qewqewqewqtq.duckdns.org
0x5b:$c2_11: criminalcloudflare.online
0x4c:$spread_ip: 176.65.139.204
```

### Benign

```
(no matches)
```

## Why benign cases don't false-positive

- **benign-elf-tools.bin:** Contains only 2 debugger names (`gdb`, `tcpdump`) — below the 3-of threshold in Path 1. Has `config`/`loader` strings but lacks magic bytes, crypto markers, and key exchange references. No path in either behavioral or structural rule is satisfied.
- **benign-urandom.bin:** Random data — no ELF magic, no recognisable strings. Fails the `uint32(0) == 0x464C457F` gate on behavioral and structural rules, and contains no IOC strings.

## Caveats

- **Synthetic specimens.** These are hand-crafted test files embedding extracted strings, not real RustDuck binaries. The XLab report provides SHA1 hashes only; real specimens should be fetched via MalShare/MalwareBazaar for validation when SHA256 hashes become available.
- **Post-disclosure rotation.** DDNS C2 domains will rotate; the behavioral and structural rules provide rotation-resistant detection while the IOC rule catches current infrastructure.
- **String-level detection.** If future RustDuck variants strip ASCII strings or use stack-string construction, the behavioral rule's process-name matching will break. The structural rule's magic bytes (`ASHPCK`, `iEMPK`) are more resilient since they are part of the binary format, not debug strings.
- **ELF-only.** Rules gate on ELF magic. If RustDuck ports to Windows PE (not currently observed), new structural conditions would be needed.

## Corpus FP scan (MalShare, 2026-07-01)

Each rule scanned individually (scanner gate requires single-rule submissions).

| Rule | Samples scanned | Hits | Elapsed |
|---|---|---|---|
| `RustDuck_Botnet_Behavior` | 5,249 | 1 | 10m34s |
| `RustDuck_ELF_Loader` | 8,337 | 0 | 12m26s |
| `RustDuck_IOC` | 11,428 | 0 | 14m42s |

**Behavioral rule hit:** `5b18eb5730b8f09de0a51cce5f7840666198222235affe24b0262309378cef24` — confirmed malware (in MalShare corpus), no public identification found. Likely a related IoT botnet with overlapping anti-analysis strings (debugger process names + `/proc` introspection). Not a benign false positive.

**Verdict:** Clean — 0 benign FPs. The single hit is on malware with behaviorally similar anti-analysis patterns, which is acceptable cross-detection for a behavioral rule.
