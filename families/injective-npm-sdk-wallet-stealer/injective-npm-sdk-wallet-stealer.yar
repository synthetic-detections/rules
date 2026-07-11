/*
   Injective Labs SDK — npm supply-chain wallet-key stealer
   --------------------------------------------------------
   Disclosed 2026-07-09/10 (Socket, StepSecurity, BleepingComputer, The
   Hacker News). The GitHub repo behind Injective's TypeScript SDK was
   compromised and used to publish a trojanised `@injectivelabs/sdk-ts`
   at version 1.20.21 to npm on 2026-07-08, with the same version pinned
   across 18 total `@injectivelabs` scoped packages (utils, networks,
   wallet-core, wallet-strategy, wallet-private-key, and others).

   The injected code (handler `trackKeyDerivation`) hooks the SDK's
   `fromMnemonic()` and `fromHex()` key-derivation functions. On call it
   captures the full BIP-39 mnemonic seed phrase / private key, base64-
   encodes the record with a short type marker ("fm" = fromMnemonic,
   "fh" = fromHex), and POSTs it to a look-alike endpoint on Injective's
   own namespace: testnet.archival.chain.grpc-web.injective.network — from
   which the actor can regenerate the private key. The malicious logic
   ships in dist/cjs/accounts-Cy0p4lLW.cjs and dist/esm/accounts-jQ1GSgaW.js.
   ~50k weekly downloads; ~310 installs of the bad version before deprecation.

   Attribution: unattributed, financially-motivated crypto-supply-chain
   actor — no state/named-group linkage in current reporting.

   Rule 1 — behavioural: the injected exfil handler `trackKeyDerivation`
            co-occurring with a key-derivation hook and base64 exfil to the
            crafted grpc-web endpoint (matches the trojanised .cjs/.js).
   Rule 2 — IOC sweep: the crafted exfil endpoint, the two unique hashed
            dist filenames, and the malicious 1.20.21 version pin under the
            @injectivelabs scope — bare scope/name is NOT treated as an IOC.
   Rule 3 — specimen pin: exact SHA-256 of the two published malicious
            dist artifacts.

   Sibling families (npm/crypto supply-chain playbook):
     [[ironworm-npm-worm]], [[miasma-redhat-npm]], [[easydayjs-mastra-rat]]

   Sources:
     https://socket.dev/blog/compromised-injective-sdk-npm-package
     https://www.stepsecurity.io/blog/injective-npm-supply-chain-attack-18-packages-backdoored-to-steal-crypto-wallet-keys
     https://www.bleepingcomputer.com/news/security/injective-sdk-on-npm-infected-with-cryptocurrency-wallet-stealer/
     https://thehackernews.com/2026/07/injective-labs-github-compromise-pushes.html
*/

import "hash"

rule Injective_SDK_KeyExfil_Behavior
{
    meta:
        description = "Trojanised @injectivelabs/sdk-ts accounts module — trackKeyDerivation exfil handler hooking fromMnemonic/fromHex and base64-POSTing seed/key material to the crafted grpc-web endpoint"
        author      = "synthetic-detections"
        date        = "2026-07-11"
        severity    = "critical"
        family      = "injective-npm-sdk-wallet-stealer"
        reference   = "https://socket.dev/blog/compromised-injective-sdk-npm-package"

    strings:
        // Unique injected exfil handler name — not present in the clean SDK
        $handler = "trackKeyDerivation" ascii

        // Key-derivation functions the malware hooks (legit SDK names — used
        // here only as co-occurrence context, never alone)
        $hook_mnemonic = "fromMnemonic" ascii
        $hook_hex      = "fromHex" ascii

        // Exfil mechanics
        $exfil_host = "grpc-web.injective.network" ascii
        $b64        = "base64" ascii
        $marker_fm  = "\"fm\"" ascii
        $marker_fh  = "\"fh\"" ascii

    condition:
        filesize < 8MB
        and $handler
        and any of ($hook_mnemonic, $hook_hex)
        and (
            $exfil_host
            or ($b64 and any of ($marker_fm, $marker_fh))
        )
}

rule Injective_SDK_IOC
{
    meta:
        description = "Static IOC sweep for the Injective SDK compromise — crafted exfil endpoint, unique hashed dist filenames, and the malicious 1.20.21 version pin under @injectivelabs scope (bare scope names are not IOCs)"
        author      = "synthetic-detections"
        date        = "2026-07-11"
        severity    = "high"
        family      = "injective-npm-sdk-wallet-stealer"
        reference   = "https://www.stepsecurity.io/blog/injective-npm-supply-chain-attack-18-packages-backdoored-to-steal-crypto-wallet-keys"

    strings:
        // Crafted look-alike exfil endpoint (full host is the durable IOC)
        $exfil = "testnet.archival.chain.grpc-web.injective.network" ascii

        // The two unique hashed filenames carrying the malicious payload
        $dist_cjs = "accounts-Cy0p4lLW.cjs" ascii
        $dist_esm = "accounts-jQ1GSgaW.js" ascii

        // Scope + malicious version pin. The bare scope alone is legitimate
        // in any consumer lockfile, so it must co-occur with version 1.20.21.
        $scope   = "@injectivelabs/" ascii
        $badver  = "1.20.21" ascii
        $sdk_ts  = "@injectivelabs/sdk-ts" ascii

    condition:
        filesize < 50MB and (
            $exfil
            or any of ($dist_cjs, $dist_esm)
            or ($sdk_ts and $badver)
            or ($scope and $badver and $exfil)
        )
}

rule Injective_SDK_Specimen
{
    meta:
        description = "Exact SHA-256 pin on the two published malicious dist artifacts (accounts-Cy0p4lLW.cjs / accounts-jQ1GSgaW.js) of @injectivelabs/sdk-ts@1.20.21"
        author      = "synthetic-detections"
        date        = "2026-07-11"
        severity    = "critical"
        family      = "injective-npm-sdk-wallet-stealer"
        reference   = "https://socket.dev/blog/compromised-injective-sdk-npm-package"
        hash_cjs    = "103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0"
        hash_esm    = "9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9"

    condition:
        filesize > 256 and filesize < 8MB
        and (
            hash.sha256(0, filesize) == "103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0"
            or hash.sha256(0, filesize) == "9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9"
        )
}
