# Mistic (MLTBackdoor) — YARA Test Results

Rules: `Mistic_Sideload_Behavior`, `Mistic_IOC`, `Mistic_Specimen_Pin`.

YARA 4.5.2, Linux x86_64, 2026-10-04.

## Specimen matrix

| File | Expected rule(s) | Actual | Result |
|------|-------------------|--------|--------|
| `specimens/mistic_sideload_synth.bin` | All three | Sideload_Behavior, IOC, Specimen_Pin | PASS |
| `benign/legit_version_dll.bin` | (none) | (none) | PASS |
| `benign/random_noise.bin` | (none) | (none) | PASS |

## Why benign cases don't false-positive

- **legit_version_dll.bin**: Contains `version.dll`, `GetModuleFileNameW`, `LoadLibraryW`, `VirtualAlloc` — common legitimate Windows strings. But has NO `MpExtMs`, `EndpointDlp.dll`, kill-switch, persistence masquerade names, or C2 domains. Every condition path in Sideload_Behavior requires either `$host_mpextms` or `$dll_endpointdlp` as an anchor.
- **random_noise.bin**: 2048 bytes of urandom — no ASCII strings match.

## Matched strings detail

**mistic_sideload_synth.bin** (Sideload_Behavior):
- `$host_mpextms` + `$dll_endpointdlp` + `$dll_version` → sideload chain anchor
- Also: `$hook_getmodule`, `$hook_loadlib`, all `$persist_*`, `$kill_delete`, `$mem_exec`, `$mem_protect`, `$delivery_msi`

**mistic_sideload_synth.bin** (IOC):
- `$c2_authlogins`, `$c2_thomphon`, `$c2_grandeluna`, `$c2_updworelos`

**mistic_sideload_synth.bin** (Specimen_Pin):
- `$sideload_host` + `$payload_dll`

## Caveats

- All specimens are synthetic. No real Mistic samples were available at rule authoring time.
- The Specimen_Pin rule uses string anchors (`MpExtMs` + `EndpointDlp`) rather than true hash pinning since we lack the actual samples. When real specimens become available, the condition should be tightened to hash-only.
- Sideload_Behavior condition requires `$host_mpextms` or `$dll_endpointdlp` in every disjunct to avoid matching legitimate Windows binaries that contain `version.dll` + common API names.
- IOC rule will go stale on C2 rotation. Sideload_Behavior targets the structural sideloading chain and should survive.
- Mistic is ~95% junk-code obfuscation; on real samples the behavioural rule may need tuning once string-level artifacts are confirmed.

## Corpus FP test

Corpus FP scan pending (gate requires single-rule submission; will scan individually when available).
