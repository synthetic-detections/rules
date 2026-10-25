# k0t / Stray Cat — YARA test results

**Family:** k0t-stray-cat
**Source:** https://www.group-ib.com/blog/stray-cat-network-edge/
**Date:** 2026-10-25

## Environment

- YARA 4.5.x
- Rules: `k0t-stray-cat.yar` (3 rules: behavioural, IOC co-occurrence, specimen pin)

## Compile check

```
yara -w k0t-stray-cat.yar /dev/null
→ clean (no warnings, no errors)
```

## Specimen test

No real specimens available for download at time of writing.
SHA-256 hashes recorded in `specimens/README.md`.

## Benign test

```
yara -r -s k0t-stray-cat.yar benign/
→ 0 hits (clean)
```

## Co-occurrence guard verification

- File with 2 indicators (e.g. `fort.py` + `buttruyen.com`): fires rule 2 ✓
- File with 1 indicator only: silent ✓
- Rule 1 requires AdaptixC2 string + infra co-occurrence: confirmed

## Corpus FP test

| Rule | Corpus size | Hits | Verdict |
|------|------------|------|---------|
| K0t_StrayCat_AdaptixC2_Beacon | 11,599 | 0 | Clean |
| K0t_StrayCat_IOC_CoOccurrence | 11,599 | 0 | Clean |
| K0t_StrayCat_Specimen_Pin | n/a | n/a | Hash-only |
