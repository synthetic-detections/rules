# evm-unguarded-selfdestruct — test results

Rules: `EVM_Unguarded_SelfDestruct_Bytecode`, `EVM_Unguarded_SelfDestruct_Source`.
Category: EVM audit / vulnerability-hunting (not a single malware family). Flags deployed
contract bytecode that exposes a caller-invocable self-destruct / drain function with no
access-control guard.

## In-repo smoke test
- **Specimens (3):** all match `EVM_Unguarded_SelfDestruct_Bytecode`.
  - `destroyMe_0xa3b8424b` (destroyMe()+gee() teardown kit)
  - `drain_target_0xc966a4df` (drain()+target() honeypot)
  - `kill_0xd9a4c3ed` (public kill())
- **Benign (2):** clean. Two Ownable ERC-20 tokens carrying `owner()` — confirm the rule does
  not fire on contracts whose destroy path is owner-gated.

## Ethereum bytecode corpus
Tested against ~318K unique mainnet contract bytecodes (metadata trailer stripped before opcode
analysis).
- `EVM_Unguarded_SelfDestruct_Bytecode` matches **113 unique bytecodes (0.036%)** — the expected
  hunting-rule population: ownerless contracts advertising a public teardown/drain surface
  (CTF/practice targets, deploy scaffolding, honeypots).
- The population is dominated by intentionally destroyable test/tooling contracts; treat a hit as
  a lead to confirm, not a confirmed bug. Per EIP-6780, on an already-deployed contract this only
  forwards the balance, so real exposure requires the contract to hold funds.

## Live validation
The rule was picked up by the streaming contract scanner and, within minutes, matched a live new
deployment on `kill()`. That contract turned out to carry `owner()` and multiple `CALLER` guards
(owner-gated kill = not unguarded), i.e. a false positive of the first draft. The rule was then
hardened to require **ownerless** (no `owner()` / `transferOwnership()` selector) on every path;
re-checked, the live contract is now clean and all specimens still match.

## Malware-corpus false-positive scan
Scanned against the broad malware corpus (real samples). Both rules clean:
- `EVM_Unguarded_SelfDestruct_Bytecode`: 5,520 samples scanned, **0 matches**, 0 read-errors.
- `EVM_Unguarded_SelfDestruct_Source`: 11,177 samples scanned, **0 matches**, 0 read-errors.

Confirms the EVM anchors (dispatcher preamble `60 80 60 40 52` at offset 0; Solidity `selfdestruct`
+ a public destroy declaration) do not cross-hit non-EVM malware.
