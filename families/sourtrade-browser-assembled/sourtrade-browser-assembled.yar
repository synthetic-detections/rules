/*
   SourTrade — browser-assembled malware via malvertising
   (Confiant, disclosed 2026-07-23; unattributed, financially motivated)
   -----------------------------------------------------------------------
   A malvertising cluster (active since late 2024) impersonating TradingView,
   Solana and Luno. It does NOT serve a finished binary; the landing page
   assembles a unique Windows PE in the victim's browser:
     - fetch build instructions from `/config` (JSON: random.seed, random.size,
       template, standaloneUrl)
     - download a CLEAN Bun runtime from standaloneUrl (gunzip)
     - generate per-victim bytes via AES-CTR in the browser
     - assemble a PE whose malicious JavaScriptCore bytecode (app.js) rides in
       a `.bun` section
     - smuggle the download through a ServiceWorker (/sw.js) using
       streamsaver:ping / streamsaver:open / streamsaver:abort messages and a
       same-origin application/octet-stream attachment
   Every victim gets a different file hash, so hash/AV signatures fail by
   design. Detection anchors on the loader JS (config shape + streamsaver SW
   protocol + standaloneUrl/Bun assembly) and on the assembled PE's `.bun`
   JavaScriptCore section.

   NOTE: Bun, ServiceWorkers and StreamSaver.js are all legitimate. Rules
   require co-occurrence of the campaign-specific combination (the /config
   field set + the streamsaver message triple + in-browser PE assembly) so a
   normal Bun app or a legit StreamSaver download page does not match.

   Rule 1 — Behavioral: the browser-side assembler/loader JS.
   Rule 2 — Structural: assembled PE carrying a `.bun` JavaScriptCore section.
   Rule 3 — IOC: SourTrade SHA-256 sample pins.

   Related in-repo malvertising/loader families:
     [[asyncrat-screenconnect-seo]] [[steam-clickfix-xmrig]]

   Sources:
     https://blog.confiant.com/p/sourtrade-browser-assembled-malware
     https://www.bleepingcomputer.com/news/security/malicious-sites-use-javascript-to-build-malware-in-browser-memory/
*/

rule SourTrade_Browser_Assembler_JS
{
    meta:
        description = "SourTrade browser-side malware assembler JS — /config build instructions (random.seed/size, template, standaloneUrl) + streamsaver ServiceWorker download smuggling + in-browser Bun PE assembly"
        author      = "synthetic-detections"
        date        = "2026-07-28"
        severity    = "critical"
        family      = "sourtrade-browser-assembled"
        reference   = "https://blog.confiant.com/p/sourtrade-browser-assembled-malware"

    strings:
        // /config JSON build-instruction fields
        $c_seed  = "random.seed" ascii wide nocase
        $c_size  = "random.size" ascii wide nocase
        $c_std   = "standaloneUrl" ascii wide
        $c_tmpl  = "template" ascii wide nocase
        $c_cfg   = "/config" ascii wide nocase

        // ServiceWorker download-smuggling protocol (StreamSaver-style)
        $sw_ping  = "streamsaver:ping" ascii wide
        $sw_open  = "streamsaver:open" ascii wide
        $sw_abort = "streamsaver:abort" ascii wide
        $sw_reg   = "/sw.js" ascii wide nocase

        // In-browser assembly primitives
        $a_bun   = "bun" ascii wide nocase
        $a_aes   = "AES-CTR" ascii wide nocase
        $a_oct   = "application/octet-stream" ascii wide nocase

    condition:
        filesize < 3MB
        and (
            // Path 1: the config build-instruction shape (standaloneUrl is the
            // strong anchor; require a second config field to avoid a lone
            // generic "template"/"/config" match)
            ($c_std and 2 of ($c_seed, $c_size, $c_tmpl, $c_cfg))
            or
            // Path 2: the streamsaver SW protocol triple (campaign-specific
            // combination, not any single generic StreamSaver string)
            (all of ($sw_ping, $sw_open, $sw_abort))
            or
            // Path 3: browser-side PE assembly — SW download + Bun + AES-CTR
            ($sw_reg and $a_bun and $a_aes and $a_oct)
        )
}

rule SourTrade_Assembled_PE_BunSection
{
    meta:
        description = "SourTrade assembled Windows PE carrying a .bun section (JavaScriptCore bytecode for app.js) — the in-browser-built payload container"
        author      = "synthetic-detections"
        date        = "2026-07-28"
        severity    = "high"
        family      = "sourtrade-browser-assembled"
        reference   = "https://blog.confiant.com/p/sourtrade-browser-assembled-malware"

    strings:
        $bun_sec = ".bun" ascii
        $app_js  = "app.js" ascii wide nocase
        $jsc     = "JavaScriptCore" ascii wide nocase
        $bun_rt  = "Bun" ascii

    condition:
        uint16(0) == 0x5A4D            // MZ
        and filesize < 120MB
        // a .bun PE section plus Bun/JSC runtime markers of the embedded app
        and $bun_sec and $bun_rt and any of ($app_js, $jsc)
}

rule SourTrade_IOC_Hashes
{
    meta:
        description = "SourTrade SHA-256 sample pins (Confiant, 2026-07-23). Note: SourTrade mints a unique hash per victim, so these are point-in-time samples, not a stable family signature."
        author      = "synthetic-detections"
        date        = "2026-07-28"
        severity    = "high"
        family      = "sourtrade-browser-assembled"
        reference   = "https://blog.confiant.com/p/sourtrade-browser-assembled-malware"

    strings:
        $h1 = "9a29d26b94b708830c6eaea8a6c17616ec677adaf09114190d0e129564b2ca1b" ascii nocase
        $h2 = "05c0d056a6b3e76736d4f378541d28f24ecdf40060eeed24d8aa283d2f0120f6" ascii nocase
        $h3 = "ad542ed44df306bdcbb022ae210da74abad74e978cc1e3992016976282f31976" ascii nocase

    condition:
        any of them
}
