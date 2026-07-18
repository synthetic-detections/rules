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

rule ChainVeil_ViteVenom_Package_IOC
{
    meta:
        description = "ViteVenom/ChainVeil — known malicious npm package names (manifest / lockfile / advisory)"
        author      = "synthetic-detections"
        date        = "2026-07-18"
        severity    = "high"
        family      = "chainveil-vitevenom-npm-rat"
        reference   = "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"

    strings:
        $p1 = "@uw010010/vite-tree" ascii nocase
        $p2 = "@vite-tab/tab" ascii nocase
        $p3 = "@vite-ln/build-ts" ascii nocase
        $p4 = "@vite-mcp/vite-type" ascii nocase
        $p5 = "@vite-pro/vite-ui" ascii nocase
        $p6 = "@vitets/vite-ts" ascii nocase
        $p7 = "@vite-ts/vite-ui" ascii nocase

    condition:
        filesize < 5MB and any of ($p*)
}

rule ChainVeil_ViteVenom_Behavior
{
    meta:
        description = "ViteVenom/ChainVeil RAT loader — blockchain-C2 retrieval + shell-rc persistence + process spawn in one JS module"
        author      = "synthetic-detections"
        date        = "2026-07-18"
        severity    = "critical"
        family      = "chainveil-vitevenom-npm-rat"
        reference   = "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"

    strings:
        // blockchain C2 (Tron / Aptos / BSC)
        $bc_tron   = "tronweb" ascii nocase
        $bc_tgrid  = "trongrid.io" ascii nocase
        $bc_aptos  = "@aptos-labs" ascii nocase
        $bc_aptos2 = "aptos" ascii nocase
        $bc_bsc    = "bsc-dataseed" ascii nocase

        // shell-rc persistence
        $rc_bash   = ".bashrc" ascii
        $rc_zsh    = ".zshrc" ascii
        $rc_prof   = ".profile" ascii
        $rc_append = "appendFileSync" ascii

        // process spawn / reverse shell
        $ex_spawn  = "child_process" ascii
        $ex_spawn2 = "spawn(" ascii
        $ex_sh     = "/bin/sh" ascii

    condition:
        filesize < 2MB
        and (any of ($bc_*))
        and (any of ($rc_bash, $rc_zsh, $rc_prof) and $rc_append)
        and (any of ($ex_*))
}

rule ChainVeil_ViteVenom_Specimen
{
    meta:
        description = "ViteVenom/ChainVeil — tight specimen pin (blockchain C2 + multi shell-rc append + spawn)"
        author      = "synthetic-detections"
        date        = "2026-07-18"
        severity    = "critical"
        family      = "chainveil-vitevenom-npm-rat"
        reference   = "https://thehackernews.com/2026/07/seven-malicious-vite-npm-packages-use.html"

    strings:
        $tron    = "tronweb" ascii nocase
        $aptos   = "aptos" ascii nocase
        $bash    = ".bashrc" ascii
        $zsh     = ".zshrc" ascii
        $prof    = ".profile" ascii
        $append  = "appendFileSync" ascii
        $spawn   = "spawn(" ascii

    condition:
        filesize < 2MB
        and $tron and $aptos and $append and $spawn
        and 2 of ($bash, $zsh, $prof)
}
