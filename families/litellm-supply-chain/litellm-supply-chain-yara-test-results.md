# litellm-supply-chain — YARA test results

## Environment

- YARA 4.5.2
- Debian 13 (trixie), Linux 6.12
- Date: 2026-10-24

## Source

- [Rescana — LiteLLM 1.107.0 supply-chain compromise](https://www.rescana.com/post/litellm-1-107-0-supply-chain-compromise-october-2026)
- [OSV MAL-2026-2144](https://osv.dev/vulnerability/MAL-2026-2144)

## Rules

| Rule | Type | Severity |
|---|---|---|
| LiteLLM_SupplyChain_Privcollect | Behavioural | Critical |
| LiteLLM_SupplyChain_IOC | IOC / co-occurrence | High |
| LiteLLM_SupplyChain_Specimen | Hash pin | Critical |

## Compile check

```
$ yara -w litellm-supply-chain.yar /dev/null
(clean)
```

## Specimen test

```
$ yara -r -s litellm-supply-chain.yar specimens/
LiteLLM_SupplyChain_Privcollect specimens/cook_specimen.py
  — 11 string matches (privcollect, .pc_once_, /healthcheck, 6 cred paths)
LiteLLM_SupplyChain_IOC specimens/cook_specimen.py
  — 2 string matches (litellm.dev, marker_file)
LiteLLM_SupplyChain_IOC specimens/sitecustomize_specimen.py
  — 3 string matches (dead_drop, lock_file, codepy_path)
```

All three rules fire on expected specimens. Specimen pin rule cannot fire on reconstructed specimens (different hashes from originals).

## Benign test

```
$ yara -r -s litellm-supply-chain.yar benign/
(clean — zero alerts)
```

Benign corpus: `legit_sitecustomize.py` (vanilla Python encoding setup), `legit_cloud_tool.py` (legitimate AWS credential reader). Neither triggers.

## Corpus FP test

| Rule | Samples scanned | Hits | Verdict |
|---|---|---|---|
| LiteLLM_SupplyChain_Privcollect | 6,583 | 0 | Clean |
| LiteLLM_SupplyChain_IOC | 11,642 | 0 | Clean |
| LiteLLM_SupplyChain_Specimen | — | — | Hash-only, not scanned |
