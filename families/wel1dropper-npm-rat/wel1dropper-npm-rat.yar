/*
   WEL1DROPPER — Russian AI-slopsquatting npm cross-platform RAT dropper
   ---------------------------------------------------------------------
   Disclosed 2026-08 (OpenSourceMalware / Paul McCarty; Sonatype tracks it
   as "Flooding Dropper"; Palo Alto Unit 42 reporting). 800 -> 1,000+ npm
   packages with AI-hallucinated ("slopsquatted") random names.

   Novelty: NO preinstall/postinstall lifecycle hook. The README instructs
   a plain require(), and that single import fires the chain via a bundled
   _helpers.js / lib/telemetry.js downloader. The loader fingerprints OS +
   CPU arch and pulls a native payload from one of three rotating Cloudflare
   Workers hosts (oob-worker.cf103-070 / cf102-baf / cf99-9b3 .workers.dev);
   if HTTPS fails it falls back to DNS-TXT staging from wel1[.]ru — a first
   TXT record returns a chunk count (1..2000), each chunk fetched and
   reassembled into the payload.

   Per-platform payload hosts: sdk.dl.wel1[.]ru (Linux x64), ext.dl.wel1[.]ru
   (Linux ARM64), pkg.dl.wel1[.]ru (macOS), net.dl.wel1[.]ru (Windows).
   File paths /pkg/update_win.exe (Windows), /pkg/beacon_mac.bin (macOS).
   macOS stage: anti-analysis checks (lldb/frida/dtrace, VMware) then a
   disguised LaunchAgent com.apple.windowserver.helper.plist for persistence.
   Linux final stage reportedly a Sliver implant. XOR-obfuscated decoy strings
   reference Russian banks (tcsbank[.]ru, cloudpayments[.]ru).

   Attribution: Russian actor, moderate confidence (.ru C2 + bank decoys).
   Linked to the earlier "Moika" dependency-confusion campaign (250+ pkgs,
   Apr 2026).

   Rule 1 — WEL1DROPPER_Loader_Behavior (critical): the JS downloader —
            OS/arch fingerprint + Cloudflare-Workers oob-worker host + the
            DNS-TXT/wel1.ru staging fallback, co-occurring.
   Rule 2 — WEL1DROPPER_IOC (high): hard network/persistence indicators with
            a >=2 co-occurrence guard to stay clean on IOC docs.
   Rule 3 — WEL1DROPPER_MacOS_Persistence (critical): the disguised
            LaunchAgent + anti-analysis specimen pin.

   Sibling families (npm supply-chain playbook):
     [[miasma-redhat-npm]] · [[ironworm-npm-worm]] · [[easydayjs-mastra-rat]]

   Sources:
     https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html
     https://gbhackers.com/russian-hackers-use-ai-slopsquatting/
     https://research.checkpoint.com/2026/10th-august-threat-intelligence-report/
*/

rule WEL1DROPPER_Loader_Behavior
{
    meta:
        description = "WEL1DROPPER npm loader — hookless require()-triggered downloader: OS/arch fingerprint + Cloudflare Workers oob-worker host + DNS-TXT/wel1.ru staging fallback"
        author      = "synthetic-detections"
        date        = "2026-08-11"
        severity    = "critical"
        family      = "wel1dropper-npm-rat"
        reference   = "https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html"
    strings:
        // OS + CPU-arch fingerprint via node process introspection
        $fp_platform = "process.platform"
        $fp_arch     = "process.arch"
        // Cloudflare Workers staging host — the campaign's distinctive prefix
        $cf_worker   = "oob-worker.cf"
        $cf_dev      = ".workers.dev"
        // DNS-TXT fallback staging (resolveTxt over a wel1 subdomain, chunked)
        $dns_txt     = "resolveTxt"
        $wel1        = "wel1.ru"
        $dl_sub      = ".dl.wel1.ru"
        // require()-triggered entry helper file names
        $helper_a    = "_helpers.js"
        $helper_b    = "lib/telemetry.js"
    condition:
        // JS text, and the fingerprint + (a CF-Workers OR a wel1 DNS-TXT staging path)
        2 of ($fp_*) and
        (
            all of ($cf_worker, $cf_dev) or
            $dns_txt and ($wel1 or $dl_sub)
        ) and
        any of ($helper_*) and
        filesize < 500KB
}

rule WEL1DROPPER_IOC
{
    meta:
        description = "WEL1DROPPER hard IOCs — wel1.ru staging subdomains, Cloudflare Workers hosts, disguised LaunchAgent, payload paths (>=2 co-occurring to avoid IOC-doc FPs)"
        author      = "synthetic-detections"
        date        = "2026-08-11"
        severity    = "high"
        family      = "wel1dropper-npm-rat"
        reference   = "https://gbhackers.com/russian-hackers-use-ai-slopsquatting/"
    strings:
        $h1 = "sdk.dl.wel1.ru"
        $h2 = "ext.dl.wel1.ru"
        $h3 = "pkg.dl.wel1.ru"
        $h4 = "net.dl.wel1.ru"
        $w1 = "oob-worker.cf103-070.workers.dev"
        $w2 = "oob-worker.cf102-baf.workers.dev"
        $w3 = "oob-worker.cf99-9b3.workers.dev"
        $p1 = "/pkg/update_win.exe"
        $p2 = "/pkg/beacon_mac.bin"
        $la = "com.apple.windowserver.helper.plist"
        // XOR-decoded Russian-bank decoy health-check strings
        $d1 = "tcsbank.ru"
        $d2 = "cloudpayments.ru"
    condition:
        2 of them and
        filesize < 500KB
}

rule WEL1DROPPER_MacOS_Persistence
{
    meta:
        description = "WEL1DROPPER macOS stage — disguised WindowServer LaunchAgent persistence combined with lldb/frida/dtrace + VMware anti-analysis"
        author      = "synthetic-detections"
        date        = "2026-08-11"
        severity    = "critical"
        family      = "wel1dropper-npm-rat"
        reference   = "https://thehackernews.com/2026/08/nearly-800-malicious-npm-packages.html"
    strings:
        $plist     = "com.apple.windowserver.helper.plist"
        $la_dir    = "LaunchAgents"
        $dbg1      = "lldb"
        $dbg2      = "frida"
        $dbg3      = "dtrace"
        $vm        = "VMware"
        $macbeacon = "beacon_mac.bin"
    condition:
        $plist and
        (
            2 of ($dbg1, $dbg2, $dbg3) or
            $vm and any of ($dbg1, $dbg2, $dbg3) or
            $la_dir and $macbeacon
        ) and
        filesize < 500KB
}
