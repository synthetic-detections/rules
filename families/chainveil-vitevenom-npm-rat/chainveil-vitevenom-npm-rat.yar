/*
   ViteVenom / ChainVeil — npm supply-chain RAT with blockchain C2
   (Checkmarx, disclosed 2026-07-17; actor "SuccessKey")
   --------------------------------------------------------------
   Seven malicious npm packages (published 2026-06-29 → 07-03) squatting the
   Vite tooling ecosystem, expanding the ChainVeil campaign. The payload
   executes at IMPORT time (not install time, limiting endpoint detection),
   queries a four-tier blockchain C2 (Tron wallet + Aptos account pointing to
   a Binance Smart Chain transaction) to retrieve its C2 config and a
   next-stage loader, then launches a RAT (reverse shell, credential
   harvesting, file exfiltration, persistent backdoor). Retrieval falls back
   Tron → Aptos → direct HTTP. Persistence via appends to ~/.bashrc, ~/.zshrc,
   ~/.profile. Cryptocurrency wallets linked to the campaign were active from
   2026-02-27.

   Related: other npm supply-chain families in this repo —
   [[famous-chollima-packagist]], [[ironworm-npm-worm]], [[miasma-redhat-npm]].

   Rule 1 — IOC: the seven malicious package names (manifests, lockfiles,
            advisories, dependency trees).
   Rule 2 — Behavioral: JS combining a blockchain-C2 query with shell-rc
            persistence and process spawning (the distinctive ViteVenom combo).
   Rule 3 — Specimen-pin: the tight artifact combination.

   Sources:
     https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html
*/

rule ChainVeil_ViteVenom_Package_IOC {
    meta:
        description = "ViteVenom/ChainVeil — known malicious npm package names (manifest / lockfile / advisory)"
        author = "synthetic-detections"
        date = "2026-07-18"
        severity = "high"
        family = "chainveil-vitevenom-npm-rat"
        reference = "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
    strings:
        $p1 = "@uw010010/vite-tree" nocase
        $p2 = "@vite-tab/tab" nocase
        $p3 = "@vite-ln/build-ts" nocase
        $p4 = "@vite-mcp/vite-type" nocase
        $p5 = "@vite-pro/vite-ui" nocase
        $p6 = "@vitets/vite-ts" nocase
        $p7 = "@vite-ts/vite-ui" nocase
    condition:
        any of ($p*) and filesize < 5MB
}

rule ChainVeil_ViteVenom_Behavior {
    meta:
        description = "ViteVenom/ChainVeil RAT loader — blockchain-C2 retrieval + shell-rc persistence + process spawn in one JS module"
        author = "synthetic-detections"
        date = "2026-07-18"
        severity = "critical"
        family = "chainveil-vitevenom-npm-rat"
        reference = "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
    strings:
        $bc_tron = "tronweb" nocase
        $bc_tgrid = "trongrid.io" nocase
        $bc_aptos = "@aptos-labs" nocase
        $bc_aptos2 = "aptos" nocase
        $bc_bsc = "bsc-dataseed" nocase
        $rc_bash = ".bashrc"
        $rc_zsh = ".zshrc"
        $rc_prof = ".profile"
        $rc_append = "appendFileSync"
        $ex_spawn = "child_process"
        $ex_spawn2 = "spawn("
        $ex_sh = "/bin/sh"
    condition:
        any of ($bc_*) and any of ($rc_bash, $rc_zsh, $rc_prof) and $rc_append and any of ($ex_*) and filesize < 2MB
}

rule ChainVeil_ViteVenom_Specimen {
    meta:
        description = "ViteVenom/ChainVeil — tight specimen pin (blockchain C2 + multi shell-rc append + spawn)"
        author = "synthetic-detections"
        date = "2026-07-18"
        severity = "critical"
        family = "chainveil-vitevenom-npm-rat"
        reference = "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"
    strings:
        $tron = "tronweb" nocase
        $aptos = "aptos" nocase
        $bash = ".bashrc"
        $zsh = ".zshrc"
        $prof = ".profile"
        $append = "appendFileSync"
        $spawn = "spawn("
    condition:
        $tron and $aptos and $append and $spawn and 2 of ($bash, $zsh, $prof) and filesize < 2MB
}
