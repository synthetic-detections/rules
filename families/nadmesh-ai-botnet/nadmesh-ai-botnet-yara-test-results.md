# NadMesh AI-Infra Botnet — YARA Test Results

**Date:** 2026-07-19
**YARA version:** 4.5.2 (classic), Linux x86_64
**Rule file:** `nadmesh-ai-botnet.yar`

## Specimen matrix

| File | Expected rule(s) | Result |
|---|---|---|
| `specimens/nadmesh-behavior-specimen.bin` | NadMesh_Botnet_Behavior (+Agent_Specimen) | MATCH |
| `specimens/nadmesh-ioc-specimen.bin` | NadMesh_IOC (+Agent_Specimen) | MATCH |
| `specimens/nadmesh-agent-specimen.bin` | NadMesh_Agent_Specimen (+IOC) | MATCH |
| `benign/benign-ai-infra-tool.bin` (names ollama/ComfyUI/redis/docker, no mesh marker/IOC) | (none) | NO MATCH |
| `benign/benign-go-tool.bin` | (none) | NO MATCH |
| `benign/benign-random.bin` | (none) | NO MATCH |

The structurally-similar benign is the key FP control: a legitimate AI-infra manager
that references the very same platforms (Ollama/ComfyUI/Redis/Docker) does NOT match,
because Rule 1 requires the `n4d mesh` control marker to co-occur with the targeting
strings, and Rule 2 requires a family marker to co-occur with the network IOCs.

## Raw output

### Specimens (expect matches)
```
NadMesh_Botnet_Behavior specimens//nadmesh-behavior-specimen.bin
NadMesh_Agent_Specimen specimens//nadmesh-behavior-specimen.bin
NadMesh_IOC specimens//nadmesh-ioc-specimen.bin
NadMesh_Agent_Specimen specimens//nadmesh-ioc-specimen.bin
NadMesh_IOC specimens//nadmesh-agent-specimen.bin
NadMesh_Agent_Specimen specimens//nadmesh-agent-specimen.bin
```

### Benign (expect clean)
```
(no output = clean)
```

## Corpus FP test

Rule tested: `NadMesh_Botnet_Behavior` (the behavioral rule; the IOC and specimen
rules are pinned to specific IOCs/hashes and are near-zero-FP by construction).

- Samples scanned: 6,532
- Matches: 0
- Read errors: 0
- Verdict: **CLEAN** — no false positives against the real-malware corpus. The
  `n4d mesh` marker + AI-targeting + exposed-service co-occurrence is specific enough
  that no unrelated sample triggered it.
