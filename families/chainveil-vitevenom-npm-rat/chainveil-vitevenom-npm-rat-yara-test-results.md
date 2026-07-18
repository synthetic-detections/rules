# chainveil-vitevenom-npm-rat — YARA test results

ViteVenom / ChainVeil npm supply-chain RAT with four-tier blockchain C2 (Checkmarx, 2026-07-17;
actor SuccessKey). Import-time execution, Tron/Aptos/BSC C2 retrieval, shell-rc persistence.

Rules:
- `ChainVeil_ViteVenom_Package_IOC` (high) — the 7 malicious npm package names.
- `ChainVeil_ViteVenom_Behavior` (critical) — blockchain-C2 query + shell-rc persistence + spawn.
- `ChainVeil_ViteVenom_Specimen` (critical) — tight artifact pin.

## In-repo smoke test
- **Specimens (2, reconstructed from public Checkmarx/THN artifacts — not the original packages):**
  - `malicious_package.json` (name `@vite-pro/vite-ui`) → `Package_IOC`
  - `index_reconstructed.js` (import-time TronWeb/Aptos C2 → `.bashrc`/`.zshrc`/`.profile` append →
    `spawn`) → `Behavior` + `Specimen`
- **Benign (2):** clean.
  - `legit-tronweb-app.js` — a legitimate dApp using TronWeb to read a balance (no shell-rc write, no
    spawn). Confirms the Behavior rule needs the *combination*, not merely a blockchain SDK.
  - `legit-vite-plugin_package.json` — a real Vite plugin manifest (no malicious package name).

## Detection artifacts
- Packages (2026-06-29 → 07-03): `@uw010010/vite-tree`, `@vite-tab/tab`, `@vite-ln/build-ts`,
  `@vite-mcp/vite-type`, `@vite-pro/vite-ui`, `@vitets/vite-ts`, `@vite-ts/vite-ui`
- Behavior: import-time exec; blockchain C2 (Tron wallet + Aptos account → BSC tx); Tron→Aptos→HTTP
  fallback; persistence appends to `.bashrc`/`.zshrc`/`.profile`
- No verbatim wallet/contract addresses or sample hashes were published in the sourced reporting;
  the rules therefore anchor on the package names (IOC) and the behavioral combination.

## Corpus false-positive scan
Submitted against the broad malware corpus. **PENDING** — the Package_IOC anchors on distinctive
squatted names and the Behavior rule requires blockchain-SDK + shell-rc-append + spawn together, so
incidental hits are expected to be low. Result recorded on completion. (the corpus-scan service availability at
commit time noted below.)
