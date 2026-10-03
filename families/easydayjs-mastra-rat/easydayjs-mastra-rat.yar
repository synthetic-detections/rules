/*
   easy-day-js / Mastra npm scope takeover RAT (disclosed 2026-06-17)
   ------------------------------------------------------------------
   A hijacked contributor account ("ehindero") republished 144 packages
   under the @mastra npm scope in 88 minutes, injecting a single
   malicious dependency: easy-day-js (a dayjs typosquat). The
   postinstall hook in setup.cjs is obfuscated with a custom-alphabet
   Base64 scheme backed by a 40-element string array rotated 34
   positions before an arithmetic checksum (0x4c11d) passes.

   Kill chain: postinstall → setup.cjs disables TLS verification
   (NODE_TLS_REJECT_UNAUTHORIZED=0) → fetches stage-2 from
   23.254.164.92:8000/update/49890878 → spawns detached cross-platform
   RAT beaconing to 23.254.164.123:443/49890878 every 10 min →
   persists as NvmProtocal (Win), com.nvm.protocal.plist (macOS),
   nvmconf.service (Linux). RAT inventories 166 crypto wallet browser
   extensions, harvests browser history, steals LLM API keys and cloud
   credentials, and supports arbitrary module execution.

   Tradecraft overlaps with Sapphire Sleet (BlueNoroff) Axios npm
   compromise (Hostwinds hosting, postinstall dropper, crypto-stealer
   payload). Attribution unconfirmed.

   Rule 1 — Behavioral: dropper postinstall pattern + obfuscation
            markers in setup.cjs / package.json context.
   Rule 2 — Persistence: cross-platform RAT persistence artifacts
            (protocal.cjs, NvmProtocal, com.nvm.protocal, nvmconf).
   Rule 3 — IOC: C2 infrastructure, campaign IDs, account indicators,
            affected package coordinates.

   Sources:
     https://research.jfrog.com/post/easy-day-js/
     https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/
     https://phoenix.security/easy-day-js-mastra-npm-supply-chain-typosquat-rat-2026/
     https://orca.security/resources/blog/mastra-npm-supply-chain-attack/
     https://www.aikido.dev/blog/over-140-popular-mastra-npm-packages-hit-by-supply-chain-attack
     https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js
*/

rule EasyDayJS_Dropper_Behavior
{
    meta:
        description = "easy-day-js postinstall dropper — obfuscated setup.cjs with TLS disable, detached spawn, self-delete pattern"
        author      = "synthetic-detections"
        date        = "2026-06-18"
        severity    = "critical"
        family      = "easydayjs-mastra-rat"
        reference   = "https://research.jfrog.com/post/easy-day-js/"
    strings:
        // postinstall hook invoking setup.cjs (package.json context)
        $hook_setup  = "\"postinstall\""
        $setup_cjs   = "setup.cjs"
        // TLS verification disable — the dropper's first action
        $tls_disable = "NODE_TLS_REJECT_UNAUTHORIZED"
        // Self-deletion after payload delivery
        $self_rm     = "rmSync"
        // XOR-0x80 encoded "easy-day-js" byte sequence (dropper marker
        // written to .pkg_logs to avoid plaintext name on disk)
        $xor_marker  = { E5 E1 F3 F9 AD E4 E1 F9 AD EA F3 }
        // Obfuscation tell: 40-element array + rotation — the
        // arithmetic checksum constant from the deobfuscation loop
        $checksum    = "0x4c11d"
        // Dropper temp markers
        $pkg_hist    = ".pkg_history"
        $pkg_logs    = ".pkg_logs"
    condition:
        // Path 1: the setup.cjs dropper itself — obfuscated JS
        // with TLS disable + self-delete + XOR marker or checksum
        // Path 2: package.json with the postinstall hook shape
        // pointing at setup.cjs alongside temp marker strings
        (
            ($tls_disable and $self_rm and ($xor_marker or $checksum or $pkg_logs)) or
            ($hook_setup and $setup_cjs and ($pkg_hist or $pkg_logs))
        ) and
        filesize < 100KB
}

rule EasyDayJS_RAT_Persistence
{
    meta:
        description = "easy-day-js cross-platform RAT persistence — protocal.cjs payload with NvmProtocal/com.nvm.protocal/nvmconf artifacts"
        author      = "synthetic-detections"
        date        = "2026-06-18"
        severity    = "critical"
        family      = "easydayjs-mastra-rat"
        reference   = "https://phoenix.security/easy-day-js-mastra-npm-supply-chain-typosquat-rat-2026/"
    strings:
        // Persistence payload filename (deliberate misspelling)
        $protocal_cjs  = "protocal.cjs"
        // Windows persistence: Run key name
        $nvmprotocal   = "NvmProtocal"
        // macOS persistence: LaunchAgent label
        $launchagent   = "com.nvm.protocal"
        // Linux persistence: systemd unit name
        $systemd_unit  = "nvmconf.service"
        // Drop directories disguised as Node tooling
        $drop_win      = "NodePackages"
        $drop_mac      = "Library/NodePackages"
        $drop_linux    = ".config/systemd/nvmconf"
        // Spoofed User-Agent for C2 beacon (IE8 on XP — anachronistic)
        $ua_beacon     = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)" nocase
        // RAT command execution runner names
        $runner_nspawn = "NSpawn"
        $runner_sspawn = "SSpawn"
        // Campaign endpoint path embedded in beacon URL
        $campaign_id   = "/49890878"
        // wolfSSL test cert CN (expired 2018, used for C2 TLS)
        $wolfssl_cn    = "www.wolfssl.com"
    condition:
        // Path 1: the protocal.cjs RAT payload — persistence
        // names + beacon artifacts
        // Path 2: persistence artifacts on disk (LaunchAgent plist,
        // systemd unit, or registry reference) — catch installed
        // persistence even if protocal.cjs is renamed
        // Path 3: beacon traffic indicators in any file
        (
            ($protocal_cjs and any of ($nvmprotocal, $launchagent, $systemd_unit)) or
            (2 of ($nvmprotocal, $launchagent, $systemd_unit, $drop_win, $drop_mac, $drop_linux) and ($ua_beacon or $campaign_id or $runner_nspawn)) or
            ($ua_beacon and $campaign_id and ($wolfssl_cn or $runner_nspawn or $runner_sspawn))
        ) and
        filesize < 5MB
}

rule EasyDayJS_IOC
{
    meta:
        description = "Static IOC sweep — C2 infrastructure, campaign ID, hijacked account, affected @mastra package coordinates"
        author      = "synthetic-detections"
        date        = "2026-06-18"
        severity    = "high"
        family      = "easydayjs-mastra-rat"
        reference   = "https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/"
    strings:
        // C2 IP addresses (Hostwinds 23.254.164.0/24)
        $c2_dropper   = "23.254.164.92"
        $c2_rat       = "23.254.164.123"
        // Hostwinds hostnames from reverse DNS
        $host1        = "hwsrv-1327786"
        $host2        = "hwsrv-1327785"
        $hostdns      = "hostwindsdns.com"
        // Campaign endpoint
        $campaign     = "49890878"
        // Payload fetch URL path
        $update_path  = "/update/49890878"
        // Malicious package name
        $easy_day_js  = "easy-day-js"
        // Hijacked npm account
        $acct_hijack  = "ehindero"
        // Attacker publisher account
        $acct_publish = "sergey2016"
        // Attacker email
        $email_atk    = "sergey2016@tutamail.com"
        // Key affected package coordinates (subset of 144)
        $pkg_core     = "@mastra/core"
        $pkg_memory   = "@mastra/memory"
        $pkg_server   = "@mastra/server"
        $pkg_mcp      = "@mastra/mcp"
        $pkg_deployer = "@mastra/deployer"
        $pkg_rag      = "@mastra/rag"
        $pkg_schema   = "@mastra/schema-compat"
        $pkg_mastra   = "create-mastra"
    condition:
        // Any C2 indicator
        // Attack infrastructure context
        // The attacker email is specific enough to stand alone. The
        // bare usernames (ehindero, sergey2016) are common-shaped and
        // appear in unrelated contributor lists / git logs, so they only
        // count alongside a campaign anchor (typosquat name, C2, payload
        // path, or an affected @mastra package).
        // Malicious dependency name + any package coordinate
        // Payload URL path (specific enough to stand alone)
        (
            any of ($c2_dropper, $c2_rat, $host1, $host2) or
            ($hostdns and $campaign) or
            $email_atk or
            (any of ($acct_hijack, $acct_publish) and ($easy_day_js or $update_path or any of ($c2_dropper, $c2_rat) or any of ($pkg_core, $pkg_memory, $pkg_server, $pkg_mcp, $pkg_deployer, $pkg_rag, $pkg_schema, $pkg_mastra))) or
            ($easy_day_js and any of ($pkg_core, $pkg_memory, $pkg_server, $pkg_mcp, $pkg_deployer, $pkg_rag, $pkg_schema, $pkg_mastra)) or
            $update_path
        ) and
        filesize < 50MB
}
