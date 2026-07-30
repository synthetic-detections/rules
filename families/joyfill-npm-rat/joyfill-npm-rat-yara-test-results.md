# joyfill-npm-rat - test results

Family: Joyfill npm supply-chain RAT (Lazarus/DPRK-linked, "PolinRider")
Disclosed: 2026-07-28 (StepSecurity + JFrog)
Rules authored: 2026-07-30

## Rules
- `Joyfill_NPM_RAT_Loader` (critical) - import-time RAT loader: campaign injection sentinels
  (`/*C250617A*/` etc.), `Sec-V: A9-0135-3` marker, Tron/Aptos/BNB blockchain-C2 resolver hosts,
  self-injection targets (VS Code/Discord/GitHub Desktop/npm CLI), namespace poisoning. Co-occurrence
  guarded so a normal Socket.IO client / web3 app doesn't match.
- `Joyfill_NPM_RAT_Decoder` (high) - the repeating-key XOR keys + seeded string-shuffle PRNG constants.
- `Joyfill_NPM_RAT_IOC` (critical) - package versions, 2 SHA-256 pins, C2 IPs + request paths.

## Smoke test (in-repo)
Specimens (should match):
```
Joyfill_NPM_RAT_Loader   specimens/iocs.txt
Joyfill_NPM_RAT_IOC      specimens/iocs.txt
Joyfill_NPM_RAT_Loader   specimens/index.js
Joyfill_NPM_RAT_Decoder  specimens/index.js
Joyfill_NPM_RAT_IOC      specimens/index.js
```
Benign (should NOT match): clean - `benign/legit_web3_client.js` (real Socket.IO + TronGrid dapp
client, none of the campaign markers).
Result: PASS. One fix iteration: a `/*C...*/` sentinel written literally in the header comment
prematurely closed the YARA block comment; reworded the comment (the string literals are unaffected).

## Corpus FP test
PENDING - the corpus-scan service unreachable at authoring time. Re-run:
a corpus false-positive scan.
Low FP risk: sentinels/Sec-V/XOR keys are campaign-unique; the blockchain-C2 hostnames are gated by
co-occurrence with sentinels or injection targets.

## Notes
- 2 SHA-256 hashes recorded to the digest store (family=joyfill-npm-rat); both absent on MalShare.
- Related npm supply-chain families: ironworm-npm-worm, miasma-redhat-npm, chainveil-vitevenom-npm-rat.
