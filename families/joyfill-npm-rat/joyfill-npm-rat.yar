/*
   Joyfill npm supply-chain RAT (Lazarus/DPRK-linked, "PolinRider")
   (StepSecurity + JFrog, disclosed 2026-07-28)
   -----------------------------------------------------------------------
   Malicious beta releases of @joyfill/components and @joyfill/layouts with
   the payload compiled into the dist bundles (dist/index.js, .esm.js, .cjs.js,
   .es.js) so it runs AT IMPORT TIME - npm install --ignore-scripts does not
   stop it. A 77 KB Socket.IO Node.js RAT: host recon, remote shell/JS exec,
   browser/wallet/token/SSH/cloud-cred theft, self-injection into VS Code,
   Discord, GitHub Desktop and the npm CLI. Further payloads are resolved via
   Tron / Aptos / BNB Smart Chain transactions (blockchain C2), so operators
   rotate payloads without new npm releases. JFrog ties tradecraft to Lazarus
   npm operations (DPRK).

   NOTE: Socket.IO and blockchain RPCs are legitimate. Rules anchor on the
   campaign's own markers (the Sec-V header value, the C250617A-style injection
   sentinels, the XOR keys, the campaign C2 path set) and require co-occurrence,
   so a normal Socket.IO client or a legit web3 app does not match.

   Rule 1 - Behavioral: the injected RAT loader (campaign sentinels + Sec-V
            marker + blockchain-C2 resolver + injection targets).
   Rule 2 - Structural: the repeating-key XOR + string-shuffle decoder shape.
   Rule 3 - IOC: package versions, SHA-256 pins, C2 IPs/paths.

   Related supply-chain families in-repo:
     [[ironworm-npm-worm]] [[miasma-redhat-npm]] [[chainveil-vitevenom-npm-rat]]

   Sources:
     https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise
     https://thehackernews.com/2026/07/two-compromised-joyfill-npm-packages.html
*/

rule Joyfill_NPM_RAT_Loader
{
    meta:
        description = "Joyfill npm import-time RAT loader - campaign injection sentinels + Sec-V:A9-0135-3 marker + Tron/Aptos/BNB blockchain-C2 resolver + self-injection into VS Code/Discord/GitHub Desktop/npm CLI"
        author      = "synthetic-detections"
        date        = "2026-07-30"
        severity    = "critical"
        family      = "joyfill-npm-rat"
        reference   = "https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise"

    strings:
        // Campaign injection sentinels (unique markers left in bundles)
        $sent1 = "/*C250617A*/" ascii
        $sent2 = "/*C260512A*/" ascii
        $sent3 = "/*RS260605*/" ascii

        // Campaign vector id / request header
        $secv1 = "Sec-V: A9-0135-3" ascii nocase
        $secv2 = "A9-0135-3" ascii

        // Blockchain-C2 resolver endpoints
        $bc1 = "api.trongrid.io" ascii nocase
        $bc2 = "fullnode.mainnet.aptoslabs.com" ascii nocase
        $bc3 = "bsc-dataseed.binance.org" ascii nocase

        // Self-injection targets
        $inj1 = "@vscode/deviceid" ascii
        $inj2 = "npm/lib/cli.js" ascii
        $inj3 = "GitHub Desktop" ascii

        // Namespace poisoning + Socket.IO auto-install
        $np1 = "global[\"r\"] = require" ascii
        $np2 = "global[\"m\"] = module" ascii

    condition:
        filesize < 8MB
        and (
            any of ($sent*)                       // campaign sentinel = strong
            or $secv1
            or ( $secv2 and any of ($bc*) )       // vector id + blockchain C2
            or ( 2 of ($bc*) and any of ($inj*) ) // blockchain C2 + injection
            or ( all of ($np*) and any of ($bc*, $inj*) )
        )
}

rule Joyfill_NPM_RAT_Decoder
{
    meta:
        description = "Joyfill RAT string-obfuscation shape - seeded string-shuffle PRNG constants + repeating-key XOR keys used to decode the embedded implant"
        author      = "synthetic-detections"
        date        = "2026-07-30"
        severity    = "high"
        family      = "joyfill-npm-rat"
        reference   = "https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise"

    strings:
        // Repeating-key XOR keys observed in the loader
        $xor1 = "2[gWfGj;<:-93Z^C" ascii
        $xor2 = "m6:tTh^D)cBz?NM]" ascii
        // Seeded PRNG constants for the string-shuffle decoder
        $prng1 = "2857687" ascii
        $prng2 = "2667686" ascii

    condition:
        filesize < 8MB
        and ( any of ($xor*) or all of ($prng*) )
}

rule Joyfill_NPM_RAT_IOC
{
    meta:
        description = "Joyfill hard IOCs - compromised package versions, RAT/stealer SHA-256, C2 IPs and request paths"
        author      = "synthetic-detections"
        date        = "2026-07-30"
        severity    = "critical"
        family      = "joyfill-npm-rat"
        reference   = "https://www.stepsecurity.io/blog/joyfill-npm-supply-chain-compromise"

    strings:
        $pkg1 = "@joyfill/components" ascii nocase
        $pkg2 = "@joyfill/layouts" ascii nocase
        $ver  = "4.0.0-rc24-2773-beta" ascii nocase
        $ver2 = "0.1.2-2773.beta" ascii nocase

        $h1 = "26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18" ascii nocase
        $h2 = "36ff00b45e67baa7e3674b0c80f48e88737264c61e5c6b3b091200972de8157c" ascii nocase

        $ip1 = "166.88.134.62" ascii
        $ip2 = "23.27.13.43" ascii
        $ip3 = "198.105.127.210" ascii
        $ip4 = "23.27.202.27" ascii

        $p1 = "/$/boot" ascii
        $p2 = "/verify-human/" ascii

    condition:
        any of ($h*)
        or ( any of ($pkg*) and any of ($ver, $ver2) )
        or ( any of ($ip*) and any of ($p*) )
}
