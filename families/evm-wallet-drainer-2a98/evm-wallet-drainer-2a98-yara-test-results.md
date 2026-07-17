# evm-wallet-drainer-2a98 — YARA test results

Operator `0x2a98741765b58e4de3873b8783e750a2a4d40760` — hardcoded payout wallet across a ~23-contract
kit (5 CrimeEnjoyor v3 sweepers + ~18 drainer/exploit contracts). Surfaced 2026-07-17 by
shared-constant clustering over the ~318K-bytecode corpus.

Rules:
- `EVM_Drainer_2a98_Bytecode` (high) — contract bytecode embedding the payout wallet (raw 20-byte run,
  matches PUSH20 and padded PUSH32).
- `EVM_Drainer_2a98_Toolkit_Behavior` (critical) — wallet + ≥2 attack-TTP dispatcher selectors.
- `EVM_Drainer_2a98_IOC` (high) — wallet + known contract addresses (source/config/IOC lists).

## In-repo smoke test
- **Specimens (3, live bytecode):** all match.
  - `drainer_exploit_0x1448c499` (exploit()/targetWallet()) → Bytecode + Behavior
  - `drainer_recipient_0x453d46af` (RECIPIENT()/attacker()) → Bytecode + Behavior
  - `sweeper_v3_0x6799946b` (CrimeEnjoyor v3) → Bytecode
- **Benign (1):** `legit-ownable-kill_0x18e95cc9` — an owner-gated `kill()` contract that does *not*
  embed the wallet. **Clean.** Confirms the rules key on the operator wallet, not on attack-style
  function names (which are common in CTF/test contracts).

## Design note
Every rule is anchored on the operator payout wallet. Attack-style selectors (`exploit`, `victim`,
`attack`, `attacker`, `takeOwnership`, `RECIPIENT`, `TARGET`) are common in benign CTF/practice
contracts, so they are only used to *raise* confidence alongside the wallet, never as a standalone
signal. A broader operator-agnostic wallet-drainer heuristic is deliberately out of scope here.

## Corpus false-positive scan
`EVM_Drainer_2a98_Bytecode` and `..._Toolkit_Behavior` submitted against the broad malware corpus.
**PENDING** — the corpus-scan service unreachable at commit time (service socket timeout); to be run when it recovers. The anchor is a fixed 20-byte address run / a specific address string, so
cross-hits on unrelated samples are expected to be zero. Result recorded on completion.
