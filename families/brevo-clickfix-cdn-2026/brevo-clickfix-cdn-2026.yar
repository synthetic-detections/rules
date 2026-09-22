/*
   BREVO CDN-EDGE SUPPLY-CHAIN — ClickFix + WordPress backdoor injection
   ---------------------------------------------------------------------
   Disclosed 2026-09 (Sansec; BleepingComputer; SecurityWeek). Attackers
   stole a long-lived, full-permission Cloudflare API key that Brevo
   (formerly Sendinblue) had hardcoded in application source, then created
   a malicious Cloudflare Worker that rewrote content at the CDN edge for
   ~5.5h on 2026-09-14 (16:05-20:13 UTC). Affected brevo.com, sendinblue.com,
   onboarding/account subdomains and sibforms.com; Sansec estimates 100,000+
   downstream sites embedding the Brevo widget served the payload for ~4h.

   Behaviour: visitors saw a fake Cloudflare "verification" page then a
   ClickFix lure telling them to paste and run a Windows command. On
   WordPress pages embedding an affected widget, the injected script also
   checked for a logged-in administrator and, if found, uploaded+activated
   a malicious plugin (wm.zip) via the wp-admin plugin-upload endpoints.
   Staging infra: look-alike CDN under sendibt1.com (cdn2/cdn4/cdn9/cdn10/
   cdn11), NXDOMAIN after 2026-09-15. C2 uses /f.js plus /api/v1/<hex>
   fingerprint / proof-of-work / clipboard-command / beacon endpoints.

   Attribution: unattributed; TTPs (stolen cloud key, CDN-edge Worker
   injection, ClickFix, WordPress/e-commerce focus) match the web-skimmer /
   ClickFix distribution ecosystem Sansec tracks.

   Rule 1 — BREVO_ClickFix_Injected_Loader (critical): the injected
            createElement-script loader pointing at a sendibt1.com CDN /f.js.
   Rule 2 — BREVO_IOC (high): hard IOCs — sendibt1 hosts, /api/v1/<hex> C2
            endpoints, wm.zip plugin path (>=2 co-occurring).
   Rule 3 — BREVO_WP_Admin_Plugin_Drop (critical): the admin-detection +
            wp-admin plugin-upload/activate chain with wm.zip — specimen pin.

   Companion Suricata rules: brevo-clickfix-cdn-2026.rules (DNS/TLS-SNI to
   sendibt1.com + the /f.js and /api/v1/ C2 HTTP paths).

   Sibling families (web-skimmer / ClickFix / supply-chain):
     [[bdthemes-biggopti-supply-chain]] · [[wallpaper-chrome-adfraud]]

   Sources:
     https://sansec.io/research/brevo-supply-chain-attack
     https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/
     https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/
*/

rule BREVO_ClickFix_Injected_Loader
{
    meta:
        description = "Brevo supply-chain injected loader — dynamic createElement script pointing at a sendibt1.com CDN /f.js payload"
        author      = "synthetic-detections"
        date        = "2026-09-22"
        severity    = "critical"
        family      = "brevo-clickfix-cdn-2026"
        reference   = "https://sansec.io/research/brevo-supply-chain-attack"

    strings:
        $ce   = "document.createElement(\"script\")" ascii
        $ce2  = "document.createElement('script')" ascii
        $host = "sendibt1.com" ascii nocase
        $fjs  = "/f.js" ascii
        $app  = "appendChild" ascii
        $async = ".async" ascii

    condition:
        filesize < 300KB and
        $host and $fjs and
        1 of ($ce, $ce2) and
        1 of ($app, $async)
}

rule BREVO_IOC
{
    meta:
        description = "Brevo supply-chain hard IOCs — sendibt1.com staging CDNs, /api/v1/<hex> C2 endpoints, wm.zip WordPress plugin path (>=2 co-occurring to avoid IOC-doc FPs)"
        author      = "synthetic-detections"
        date        = "2026-09-22"
        severity    = "high"
        family      = "brevo-clickfix-cdn-2026"
        reference   = "https://www.bleepingcomputer.com/news/security/brevo-supply-chain-attack-injected-clickfix-scripts-on-customer-sites/"

    strings:
        $h1 = "cdn2.sendibt1.com" ascii nocase
        $h2 = "cdn4.sendibt1.com" ascii nocase
        $h3 = "cdn9.sendibt1.com" ascii nocase
        $h4 = "cdn10.sendibt1.com" ascii nocase
        $h5 = "cdn11.sendibt1.com" ascii nocase
        // distinctive C2 API endpoints (hex-named)
        $a1 = "/api/v1/0044d4a" ascii
        $a2 = "/api/v1/e08a3c4" ascii
        $a3 = "/api/v1/8e4c615" ascii
        $a4 = "/api/v1/f659473" ascii
        $a5 = "/api/v1/4aff112?tk=" ascii
        $a6 = "/api/v1/b832c14?e=" ascii
        $a7 = "/api/v1/4ead0ff?tk=" ascii
        // WordPress backdoor plugin drop
        $wp = "/p/wm.zip" ascii

    condition:
        filesize < 300KB and 2 of them
}

rule BREVO_WP_Admin_Plugin_Drop
{
    meta:
        description = "Brevo injection WordPress stage — admin-session check plus wp-admin plugin upload/activate chain dropping wm.zip"
        author      = "synthetic-detections"
        date        = "2026-09-22"
        severity    = "critical"
        family      = "brevo-clickfix-cdn-2026"
        reference   = "https://www.securityweek.com/brevo-supply-chain-attack-injects-malware-into-100000-websites/"

    strings:
        $up  = "/wp-admin/update.php?action=upload-plugin" ascii
        $act = "action=activate" ascii
        $zip = "wm.zip" ascii
        $admin1 = "wp-admin" ascii
        $admin2 = "is_admin" ascii nocase
        $admin3 = "adminbar" ascii nocase

    condition:
        filesize < 300KB and
        $up and $zip and
        1 of ($act, $admin1, $admin2, $admin3)
}
