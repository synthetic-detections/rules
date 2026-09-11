# brazetsu — test results

Family: BraZetsu AI-enhanced IAB framework (Exilware, Brazil)
Disclosed: 2026-09-03 (Group-IB). Rules authored: 2026-09-10.

## Rules

| Rule | Type | Severity |
|------|------|----------|
| BraZetsu_Behavioural | behavioral (XOR key, persistence, filenames) | critical |
| BraZetsu_IOC | IOC (C2 domains + IP) | high |
| BraZetsu_Specimen | hash pins (16 SHA-256) | critical |

## Local smoke test (yara 4.5.2)

Compiles clean (`yara brazetsu.yar`). `import "hash"` required for Specimen rule.

Specimens (mock reconstructions from public reporting — inert):

| Specimen | Behavioural | IOC | Specimen |
|----------|-------------|-----|----------|
| xor_key.bin | match | — | — |
| combined_strings.bin | match | — | — |
| c2_domain.bin | — | match | — |

Benign controls (must NOT match) — all clean:

| Benign | Result | Purpose |
|--------|--------|---------|
| clean.txt | no match | generic text with no malware indicators |
| partial_match.txt | no match | lone "MonitorSystem" without CNAB must not trigger |
| ip_superstring.txt | no match | `138.242.246.176` / `38.242.246.1760` must not trigger the `fullword` C2 IP string |

## FP-avoidance notes

The XOR key `p4st3_s3cr3t_k3y` is highly campaign-specific and unlikely to
appear in legitimate software. The Behavioural rule anchors on this key, or
the `MonitorSystem` registry name combined with the CNAB financial format
marker, or the distinctive agent DLL names (`temp_agente.dll`,
`agenteV2_historico_detect.dll`). Lone partial matches do not trigger.

The IOC rule is infrastructure-pinned — all five indicators are directly
attributed to the campaign by Group-IB. The `installscenter.com` domain
uses a typosquat pattern unlikely to collide with legitimate infrastructure.

## Corpus FP test

No automated corpus scan available at authoring time. The Behavioural rule's
XOR key and agent DLL names are sufficiently specific that false positives
against commodity malware are unlikely. The IOC rule is infrastructure-pinned
and should not match unrelated samples.

The 16 hashes in the Specimen rule were verified against the Group-IB report
and cross-checked in MalShare — none present at authoring time.
