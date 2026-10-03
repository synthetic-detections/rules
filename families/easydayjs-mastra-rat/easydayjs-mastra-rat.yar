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

rule EasyDayJS_Dropper_Behavior {
  meta:
    description = "easy-day-js postinstall dropper — obfuscated setup.cjs with TLS disable, detached spawn, self-delete pattern"
    author = "synthetic-detections"
    date = "2026-06-18"
    severity = "critical"
    family = "easydayjs-mastra-rat"
    reference = "https://research.jfrog.com/post/easy-day-js/"
  strings:
    $hook_setup = "\"postinstall\""
    $setup_cjs = "setup.cjs"
    $tls_disable = "NODE_TLS_REJECT_UNAUTHORIZED"
    $self_rm = "rmSync"
    $xor_marker = { E5 E1 F3 F9 AD E4 E1 F9 AD EA F3 }
    $checksum = "0x4c11d"
    $pkg_hist = ".pkg_history"
    $pkg_logs = ".pkg_logs"
  condition:
    ($tls_disable and $self_rm and ($xor_marker or $checksum or $pkg_logs) or $hook_setup and $setup_cjs and ($pkg_hist or $pkg_logs)) and filesize < 100KB
}

rule EasyDayJS_RAT_Persistence {
  meta:
    description = "easy-day-js cross-platform RAT persistence — protocal.cjs payload with NvmProtocal/com.nvm.protocal/nvmconf artifacts"
    author = "synthetic-detections"
    date = "2026-06-18"
    severity = "critical"
    family = "easydayjs-mastra-rat"
    reference = "https://phoenix.security/easy-day-js-mastra-npm-supply-chain-typosquat-rat-2026/"
  strings:
    $protocal_cjs = "protocal.cjs"
    $nvmprotocal = "NvmProtocal"
    $launchagent = "com.nvm.protocal"
    $systemd_unit = "nvmconf.service"
    $drop_win = "NodePackages"
    $drop_mac = "Library/NodePackages"
    $drop_linux = ".config/systemd/nvmconf"
    $ua_beacon = "mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)" nocase
    $runner_nspawn = "NSpawn"
    $runner_sspawn = "SSpawn"
    $campaign_id = "/49890878"
    $wolfssl_cn = "www.wolfssl.com"
  condition:
    ($protocal_cjs and any of ($nvmprotocal, $launchagent, $systemd_unit) or 2 of ($nvmprotocal, $launchagent, $systemd_unit, $drop_win, $drop_mac, $drop_linux) and ($ua_beacon or $campaign_id or $runner_nspawn) or $ua_beacon and $campaign_id and ($wolfssl_cn or $runner_nspawn or $runner_sspawn)) and filesize < 5MB
}

rule EasyDayJS_IOC {
  meta:
    description = "Static IOC sweep — C2 infrastructure, campaign ID, hijacked account, affected @mastra package coordinates"
    author = "synthetic-detections"
    date = "2026-06-18"
    severity = "high"
    family = "easydayjs-mastra-rat"
    reference = "https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/"
  strings:
    $c2_dropper = "23.254.164.92"
    $c2_rat = "23.254.164.123"
    $host1 = "hwsrv-1327786"
    $host2 = "hwsrv-1327785"
    $hostdns = "hostwindsdns.com"
    $campaign = "49890878"
    $update_path = "/update/49890878"
    $easy_day_js = "easy-day-js"
    $acct_hijack = "ehindero"
    $acct_publish = "sergey2016"
    $email_atk = "sergey2016@tutamail.com"
    $pkg_core = "@mastra/core"
    $pkg_memory = "@mastra/memory"
    $pkg_server = "@mastra/server"
    $pkg_mcp = "@mastra/mcp"
    $pkg_deployer = "@mastra/deployer"
    $pkg_rag = "@mastra/rag"
    $pkg_schema = "@mastra/schema-compat"
    $pkg_mastra = "create-mastra"
  condition:
    (any of ($c2_dropper, $c2_rat, $host1, $host2) or $hostdns and $campaign or $email_atk or any of ($acct_hijack, $acct_publish) and ($easy_day_js or $update_path or any of ($c2_dropper, $c2_rat) or any of ($pkg_core, $pkg_memory, $pkg_server, $pkg_mcp, $pkg_deployer, $pkg_rag, $pkg_schema, $pkg_mastra)) or $easy_day_js and any of ($pkg_core, $pkg_memory, $pkg_server, $pkg_mcp, $pkg_deployer, $pkg_rag, $pkg_schema, $pkg_mastra) or $update_path) and filesize < 50MB
}
