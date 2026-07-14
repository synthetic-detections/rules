# Test transcript — `injective-npm-sdk-wallet-stealer.yar`

## Environment

- YARA: `4.5.2`
- Platform: `Linux localhost 6.12.90+deb13.1-amd64 x86_64 GNU/Linux`
- Date: 2026-07-11
- Sources:
  - <https://socket.dev/blog/compromised-injective-sdk-npm-package>
  - <https://www.stepsecurity.io/blog/injective-npm-supply-chain-attack-18-packages-backdoored-to-steal-crypto-wallet-keys>
  - <https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/>
  - <https://thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html>

## Corpus

| File | Kind | Intended rule | Expected |
|---|---|---|---|
| `specimens/malicious-accounts.cjs` | reconstructed trojanised accounts module — `trackKeyDerivation`, `fromMnemonic`/`fromHex` hooks, base64, exfil host, `"fm"`/`"fh"` markers | `…_KeyExfil_Behavior` (+ IOC via exfil host) | match |
| `specimens/package-injectivelabs.json` | `@injectivelabs/sdk-ts@1.20.21` manifest listing the two malicious dist filenames | `…_IOC` | match |
| `specimens/ioc-dump.txt` | text dump of package list, exfil endpoint, dist filenames, hashes | `…_IOC` (+ Behavior via handler+hook+host) | match |
| `benign/legit-injective-consumer.json` | real-shape consumer depending on `@injectivelabs/sdk-ts@1.20.20` (clean version) | none | no match |
| `benign/normal-accounts.cjs` | clean accounts module with the same legit `fromMnemonic`/`fromHex` names, no handler/exfil | none | no match |
| `benign/random-200k.bin` | 200 KiB urandom | none | no match |

The critical benign is `benign/legit-injective-consumer.json`: same scope and
package name as the malicious case, but the clean `1.20.20` pin and no exfil
endpoint / dist filenames — it proves the IOC rule does not fire on legitimate
consumers of the SDK (bare `@injectivelabs/` scope is never treated as an IOC;
the malicious `1.20.21` version, the crafted exfil host, or a unique hashed dist
filename must be present).

The `…_Specimen` rule pins the two **published** malicious SHA-256 artifacts
(`accounts-Cy0p4lLW.cjs` / `accounts-jQ1GSgaW.js`). The exact bytes are not
redistributed in-repo, so no in-repo specimen fires that rule by design — it is
verified by successful compilation and will match only the genuine artifacts.

## Compile check

```
$ yara -w families/injective-npm-sdk-wallet-stealer/injective-npm-sdk-wallet-stealer.yar /dev/null && echo "COMPILE OK"
COMPILE OK
```

## Run — should-match

```
$ yara -r injective-npm-sdk-wallet-stealer.yar specimens/
Injective_SDK_KeyExfil_Behavior specimens//malicious-accounts.cjs
Injective_SDK_IOC              specimens//malicious-accounts.cjs
Injective_SDK_KeyExfil_Behavior specimens//ioc-dump.txt
Injective_SDK_IOC              specimens//ioc-dump.txt
Injective_SDK_IOC              specimens//package-injectivelabs.json
```

All three specimens match their intended rule(s).

## Run — should-NOT-match

```
$ yara -r injective-npm-sdk-wallet-stealer.yar benign/
(no output — BENIGN CLEAN)
```

No benign file matches.

## Corpus FP test

- Status: **PENDING** — corpus scan unavailable at run time (2026-07-11).
- FP-risk assessment: low. All matching paths are anchored on high-specificity,
  non-dictionary tokens — the injected handler `trackKeyDerivation`, the crafted
  full exfil host `testnet.archival.chain.grpc-web.injective.network`, the two
  unique hashed dist filenames, or the `@injectivelabs/sdk-ts` + `1.20.21`
  co-occurrence. Re-run the corpus scan when available and record
  samples / hits / verdict here.
