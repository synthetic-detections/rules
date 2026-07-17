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

## 2026-07-17 update 2 — v3 obfuscated-variant detection (XOR destination hook)

The v3 variants hide the theft address instead of embedding it: `PUSH32 a; PUSH32 b; XOR`
reconstructs the 20-byte destination at runtime (the two constants share their high 12 bytes, which
cancel). Prevalence study over the ~318K bytecode corpus:

| pattern | corpus prevalence | usable as a hook? |
|---|---|---|
| any `XOR` opcode | 9.3% | no — far too common |
| `XOR` near a ≥20-byte PUSH constant | 1.51% | too broad standalone |
| **`PUSH32 PUSH32 XOR` adjacency** | **0.045% (142/318K)** | rare, but only 19% are sweepers — not standalone |
| **`PUSH32 PUSH32 XOR` + 2 v3 selectors** | **48/318K, 0 FP** | **yes — surgical** |

Within the family the XOR primitive is 100% v3-specific (30/33 v3, 0/51 v1, 0/11 v2). Standalone it
is not malware-specific (115 of the 142 anchor hits are unrelated legitimate contracts that XOR two
words). Paired with the v3 sweeper selectors it is surgical.

**Change:** added `$xor_deob = { 7f [32] 7f [32] 18 }` and **Path 14**
(`$xor_deob and 2 of ($sel_v3_*) and filesize < 8KB`). Catches obfuscated v3 clones carrying too few
recognised selectors for Path 10 (needs 3). Corpus: **48 matches — 47 family + 1 new** obfuscated
clone `0xc474aefd…` (ownerless, executeCall+transferTokens, XOR destination, added as `$addr16` and
a specimen). **Zero false positives.** All 18 specimens match, benign clean.

### Malware-corpus false-positive scan
`CrimeEnjoyor_Sweeper_Behavior` scanned against the broad malware corpus (real samples) — result
recorded on completion. All added paths (11b, 14) are EVM-selector/opcode-anchored and verified
0-FP against the ~318K EVM bytecode corpus, so non-EVM cross-hits are expected to be negligible.
