/*
   Famous Chollima — Packagist roberts/leads compromise (disclosed 2026-05-30)
   ----------------------------------------------------------------------------
   tailwind.js inside a compromised PHP package hides a JS loader that:
     1. reconstructs require/module via global aliases,
     2. fetches a payload pointer from TRON (Aptos fallback),
     3. retrieves the next stage from BNB Smart Chain via eth_getTransactionByHash,
     4. XOR-decrypts with a hard-coded 16-byte key and eval()s the result,
     5. spawns a detached hidden Node child to harvest env / .env / SSH / tokens.
   Family: BeaverTail / DEV#POPPER / OmniStealer. Actor: Famous Chollima (DPRK).

   Rule 1 — behavioural: campaign markers OR family-shape co-occurrence
            (blockchain RPC + hidden detached spawn + dynamic eval).
   Rule 2 — IOC sweep: package/commit/wallets/keys/hashes.
   Rule 3 — specimen pin: exact SHA256 of tailwind.js, size-gated.

   Source: https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package
*/

import "hash"

rule FamousChollima_Packagist_TailwindJS_Loader
{
    meta:
        description = "Behavioural: blockchain-RPC-as-C2 pointer + XOR/eval + hidden detached spawn used by Famous Chollima in roberts/leads tailwind.js"
        author      = "synthetic-detections"
        date        = "2026-06-01"
        severity    = "critical"
        family      = "BeaverTail/DEV#POPPER"
        reference   = "https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package"
        actor       = "Famous Chollima (DPRK)"
    strings:
        // Campaign markers (global-alias bootstrap + obfuscator id + artefact)
        $m_global1 = "global['!']='9-0264-2'"
        $m_global2 = "global['_V']='A9-0264-2'"
        $m_obf_id  = "_$_1e42"
        $m_artef   = "rmcej%otb%"
        // Blockchain-RPC-as-C2 anchors
        $rpc_tron  = "trongrid"
        $rpc_aptos = "aptoslabs"
        $rpc_bsc1  = "bsc-dataseed"
        $rpc_bsc2  = "bsc-rpc"
        $rpc_eth   = "eth_getTransactionByHash"
        // Stealth-spawn tells — detached hidden Node child
        $spawn1    = "windowsHide"
        $spawn2    = "detached"
        // Dynamic execution of fetched payload
        $eval      = /eval\s*\(\s*[A-Za-z_$][\w$]{0,32}\s*\)/
    condition:
        (any of ($m_*) or (2 of ($rpc_*) and all of ($spawn*) and $eval)) and filesize < 2MB
}

rule FamousChollima_Packagist_TailwindJS_IOC
{
    meta:
        description = "Static IOC sweep — Packagist coord, commit, TRON/Aptos wallets, XOR keys, payload hashes"
        author      = "synthetic-detections"
        date        = "2026-06-01"
        severity    = "high"
        family      = "BeaverTail/DEV#POPPER"
        reference   = "https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package"
        hash        = "96afdba882046385242cbed46871e41147c8055c5d9eff7460847b2c01a77dc3"
        actor       = "Famous Chollima (DPRK)"
    strings:
        $pkg    = "roberts/leads"
        $branch = "drewroberts/feature/test-case"
        $commit = "6c5c3c7655ce76399af11126b7e9a9058eb2e45d" nocase
        $tron1  = "TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP"
        $tron2  = "TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG"
        $apt1   = "0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e" nocase
        $apt2   = "0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3" nocase
        $xor1   = "2[gWfGj;<:-93Z^C"
        $xor2   = "m6:tTh^D)cBz?NM]"
        $h_file = "96afdba882046385242cbed46871e41147c8055c5d9eff7460847b2c01a77dc3" nocase
        $h_arch = "522b28a2f78771715497ba53729d4ab9a50e982322c391379f3bddf7c8cb363f" nocase
    condition:
        any of them and filesize < 50MB
}

rule FamousChollima_Packagist_TailwindJS_Specimen
{
    meta:
        description = "Exact-hash pin on the malicious tailwind.js shipped in roberts/leads dev-drewroberts/feature/test-case"
        author      = "synthetic-detections"
        date        = "2026-06-01"
        severity    = "critical"
        family      = "BeaverTail/DEV#POPPER"
        reference   = "https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package"
        hash        = "96afdba882046385242cbed46871e41147c8055c5d9eff7460847b2c01a77dc3"
        actor       = "Famous Chollima (DPRK)"
    strings:
        $tailwind = "tailwind" nocase
    condition:
        $tailwind
        and filesize > 4KB
        and filesize < 2MB
        and hash.sha256(0, filesize) == "96afdba882046385242cbed46871e41147c8055c5d9eff7460847b2c01a77dc3"
}
