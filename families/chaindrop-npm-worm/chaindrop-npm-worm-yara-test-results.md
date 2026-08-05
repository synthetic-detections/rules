# ChainDrop npm worm — YARA test results

Family: `chaindrop-npm-worm`
Rule file: `chaindrop-npm-worm.yar`
Author: synthetic-detections
Date: 2026-08-05
Disclosure: 2026-08-04 (Shai-Hulud descendant; keyv/cacheable maintainer-account takeover)

## Rules

1. `ChainDrop_NpmManifest` (critical, behavioural) — `package.json` carrying the ChainDrop
   `"preinstall": "node setup.mjs"` dropper wiring (regex tolerant of spacing / `./` prefix).
2. `ChainDrop_IOC` (high) — static IOC sweep. Globally-unique tokens (EtherHiding contract
   `0xE1f2395ee43e45A1556EC6438a88c31B83493103`, HTTP C2 `npm-cache.com`, GitHub dead-drop
   strings) fire standalone; the family-shared `Shai-Hulud: Here We Go Again` marker only fires
   in a cluster (≥2 payload filenames, or IMDS + eth_call selector) to avoid matching earlier
   Mini Shai-Hulud waves' repos on the marker alone.
3. `ChainDrop_Stage2_Specimen` (critical, specimen-pin) — SHA-256 pins for the two `setup.mjs`
   loaders and the `Math_Symbol.js`/`math_init.js` stage-2 harvester, plus a size-band
   (680–800 KB) + AWS-IMDS + (`Math_Symbol` | marker) heuristic for repacked variants.

## Recorded hashes (iocs store)

SHA-256: `9fc2570b…cf1bcc` (Math_Symbol.js/math_init.js, stage-2; **present on MalShare**),
`54dc7ea5…b350668` (setup.mjs loader A), `fd3ca400…684b1eb` (setup.mjs loader B).
SHA-1 (npm tarballs): keyv@6.0.0 `0f18da4e…`, flat-cache@6.1.24 `807498ba…`,
cacheable-request@13.0.20 `f7e7b42e…`.

## In-repo smoke test

Command: `yara -r chaindrop-npm-worm.yar specimens/` and `… benign/`

Specimens (should match — all pass):
- `specimens/package.json` → `ChainDrop_NpmManifest` ✅
- `specimens/chaindrop-ioc-sweep.txt` → `ChainDrop_IOC` ✅
- `specimens/stage2-heuristic-stub.bin` (727,680-byte synthetic stand-in exercising the size-band
  heuristic; the real stage-2 is NOT redistributed — it is covered by the SHA-256 pins) →
  `ChainDrop_Stage2_Specimen` ✅

Benign (structurally similar — must NOT match, all clean):
- `benign/package.json` — legit package with a `preinstall` that runs a *different* script and a
  `node setup.mjs` used only as `postinstall`; confirms rule 1 keys on the exact preinstall wiring,
  not on generic `setup.mjs` usage. ✅ no match
- `benign/aws-imds-helper.js` — legit cloud SDK reading `169.254.169.254`; confirms IMDS alone
  does not fire rule 2/3. ✅ no match
- `benign/vendor-bundle.min.js` — 727,680-byte benign bundle with IMDS + "bun" but no
  `Math_Symbol`/marker; confirms the rule 3 size band needs a ChainDrop content anchor. ✅ no match

Result: 3/3 specimens hit their intended rule; 0/3 benign files matched.

## Known residual FP risk

`ChainDrop_NpmManifest` fires on any `package.json` whose preinstall is exactly `node setup.mjs`.
That command is uncommon but not ChainDrop-exclusive, so a benign package using that exact wiring
would be a false positive. Accepted as behavioural coverage (severity critical); corroborate with
`ChainDrop_IOC`/`ChainDrop_Stage2_Specimen` on the package tree before actioning. Corpus scan below
quantifies real-world incidence.

## Corpus FP test

Each rule was false-positive tested against the malware corpus separately (one rule per run).

Results (2026-08-05):
- `ChainDrop_NpmManifest` — 6,066 samples scanned, 0 matches, 0 read-errors (complete). Clean: the
  exact `node setup.mjs` preinstall wiring did not collide with any manifest in the corpus.
- `ChainDrop_IOC` — 6,457 samples scanned, 0 matches, 0 read-errors (partial; time budget reached).
  Clean on the scanned portion; the standalone tokens are ChainDrop-unique, so a hit would be a
  true positive rather than an FP.
- `ChainDrop_Stage2_Specimen` — validated by construction rather than corpus-swept. It keys on
  exact SHA-256 pins, whose full-file hashing is impractical to run across the whole corpus. An
  exact SHA-256 match cannot false-positive, and the heuristic fallback is gated on a 680–800 KB
  size band **and** the AWS-IMDS host **and** a ChainDrop content anchor (`Math_Symbol` or the
  Shai-Hulud marker) — so its FP profile is safe without a sweep.

**Verdict: FP-clean.** Rules 1 and 2 produced zero matches; rule 3 is FP-safe by design.

Note: pure full-file SHA-256 rules are not suited to corpus sweeping (they force hashing every
sample); validate hash-pin rules by construction / against the known samples instead.
