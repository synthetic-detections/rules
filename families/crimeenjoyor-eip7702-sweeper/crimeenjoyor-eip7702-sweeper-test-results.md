# crimeenjoyor-eip7702-sweeper — test results

## 2026-07-17 update — v1 bytecode-only detection + new IOCs

A corpus sweep of ~318K unique mainnet contract bytecodes surfaced v1 CrimeEnjoyor clones that the
rule was **missing**: ownerless `destination()`+`initialize(address)` sweepers that carry no English
revert string ("Already initialized", or none at all), so the error-string-gated Path 11 never
fired.

**Change:** added **Path 11b** to `CrimeEnjoyor_Sweeper_Behavior` — matches the exact
`destination()` (0xb269681d) + `initialize(address)` (0xc4d66de8) selector pair in a `< 3 KB`
runtime blob that carries **no** `owner()` / `transferOwnership()` selector. This is the minimal
EIP-7702 sweeper shape; the ownerless + small-size constraints keep it off legitimate
init+destination contracts (which are Ownable). Five new clone addresses added to `CrimeEnjoyor_IOC`
(`$addr11`–`$addr15`).

### Smoke test
- **Specimens (4):** v1, v2, v3, v3b all still match (no regression).
- **Benign:** existing benign + two Ownable ERC-20 tokens — all clean (Path 11b excludes owner-bearing
  contracts).
- **5 newly-catalogued clones:** all now match (were `NO MATCH` before).

### Bytecode corpus
- Path 11b matches **37 unique bytecodes** across the ~318K corpus — **12 beyond the original
  123-contract family set** (the 5 named clones plus 7 further byte-variants). Tight and on-target,
  no false-positive balloon (37 ≈ the known v1 population).

### Malware-corpus false-positive scan
Submitted against the large malware corpus. **PENDING** (running at commit time). The changed rule
is EVM-selector-anchored, so cross-hits on non-EVM samples are expected to be negligible. Result to
be recorded on completion.
