/*
   Wallpaper Chrome Ad-Fraud — 152 malicious "live wallpaper" extensions
   ---------------------------------------------------------------------
   Disclosed 2026-06-14 by Socket Threat Research. A coordinated family
   of 152 Chrome Web Store extensions across 38 publisher accounts and
   three brand fronts (tabplugins.com, yowgames.com, chromewallpaper.com
   → owhit.com), all built from a single codebase. ~105,000 installs.

   On install the extension opens a tab with forged Google organic
   attribution (utm_source=google&utm_medium=organic), inflating ad
   revenue. On uninstall it fires a cloaked redirect through a crafted
   google.com/url?sa=t URL to the operator domain. The service worker
   (js/bg.js) wipes all IndexedDB databases on every start as an
   anti-forensic measure, logging "Deleted IndexedDB database:" to the
   console. Telemetry (IP, ISP, clicks, referrer) is harvested and
   shared with ad networks despite store listings claiming no collection.

   All 141+ retrievable service workers share the same IndexedDB wipe,
   install-navigation, and setUninstallURL patterns.

   Rule 1 — service worker behavioural: IndexedDB wipe loop + Google
            organic attribution spoofing + setUninstallURL SERP cloaking.
   Rule 2 — manifest.json structural: MV3 + service_worker + newtab
            override co-occurring with an operator domain.
   Rule 3 — IOC sweep: operator domains, Hostinger origin IPs, ad-fraud
            header-bidding domain, the forensic console string.

   Infrastructure: Hostinger-hosted at 147.79.120.202 and 92.112.198.22.
   Header-bidding via avads.live (Advergic).

   Sources:
     https://cybersecuritynews.com/chrome-extensions-hide-ad-tracking/
     https://gbhackers.com/malicious-152-chrome-extensions-google-search/
*/

rule WallpaperAdfraud_ServiceWorkerBehavior
{
    meta:
        description = "Service worker JS matching the 152-extension wallpaper ad-fraud family — IndexedDB wipe-all loop, forged Google organic install attribution, and setUninstallURL SERP cloaking"
        author      = "synthetic-detections"
        date        = "2026-06-15"
        severity    = "high"
        family      = "wallpaper-chrome-adfraud"
        reference   = "https://cybersecuritynews.com/chrome-extensions-hide-ad-tracking/"

    strings:
        // Anti-forensic IndexedDB wipe — enumerate then delete every DB
        $idb_enum    = "indexedDB.databases()" ascii
        $idb_delete  = "deleteDatabase" ascii
        $idb_log     = "Deleted IndexedDB database:" ascii

        // Install handler opens tab with forged Google organic attribution
        $oninstalled = "onInstalled" ascii
        $utm_forge   = "utm_source=google&utm_medium=organic" ascii

        // Uninstall URL cloaked as a Google SERP click
        $uninstall   = "setUninstallURL" ascii
        $serp_cloak  = /google\.com\/url\?sa=t[^"]{0,120}(ved=|usg=)/ ascii

        // Operator backend domains embedded in the JS
        $dom_tab     = "tabplugins.com" ascii nocase
        $dom_yow     = "yowgames.com" ascii nocase
        $dom_cw      = "chromewallpaper.com" ascii nocase
        $dom_owhit   = "owhit.com" ascii nocase

    condition:
        filesize < 1MB
        and (
            // Core behavioural triad: IDB wipe + organic spoof + SERP cloak
            ($idb_enum and $idb_delete and $utm_forge and $uninstall)
            or
            // IDB wipe log string + any operator domain — high confidence
            ($idb_log and any of ($dom_*))
            or
            // Google SERP cloaking in setUninstallURL targeting an operator domain
            ($uninstall and $serp_cloak and any of ($dom_*))
            or
            // Forged organic attribution + install handler + operator domain
            ($oninstalled and $utm_forge and any of ($dom_*))
        )
}

rule WallpaperAdfraud_ExtensionManifest
{
    meta:
        description = "Chrome extension manifest.json matching the wallpaper ad-fraud family — MV3 with service_worker and newtab override pointing to an operator domain"
        author      = "synthetic-detections"
        date        = "2026-06-15"
        severity    = "medium"
        family      = "wallpaper-chrome-adfraud"
        reference   = "https://gbhackers.com/malicious-152-chrome-extensions-google-search/"

    strings:
        // MV3 manifest structure
        $mv3         = /\"manifest_version\"\s*:\s*3/ ascii
        $sw          = "\"service_worker\"" ascii
        $newtab      = "\"newtab\"" ascii
        $bg_js       = "js/bg.js" ascii

        // Operator domains in the manifest (permissions, externally_connectable, etc.)
        $dom_tab     = "tabplugins.com" ascii nocase
        $dom_yow     = "yowgames.com" ascii nocase
        $dom_cw      = "chromewallpaper.com" ascii nocase
        $dom_owhit   = "owhit.com" ascii nocase

    condition:
        filesize < 64KB
        and $mv3
        and $newtab
        and ($sw or $bg_js)
        and any of ($dom_*)
}

rule WallpaperAdfraud_IOC
{
    meta:
        description = "Static IOC sweep — operator domains, Hostinger origin IPs, Advergic header-bidding domain, and forensic log string for the 152-extension wallpaper ad-fraud campaign"
        author      = "synthetic-detections"
        date        = "2026-06-15"
        severity    = "medium"
        family      = "wallpaper-chrome-adfraud"
        reference   = "https://cybersecuritynews.com/chrome-extensions-hide-ad-tracking/"

    strings:
        // Operator domains
        $dom_tab     = "tabplugins.com" ascii nocase
        $dom_yow     = "yowgames.com" ascii nocase
        $dom_cw      = "chromewallpaper.com" ascii nocase
        $dom_owhit   = "owhit.com" ascii nocase

        // Advergic header-bidding domain used for monetisation
        $dom_avads   = "avads.live" ascii nocase

        // Hostinger origin server IPs
        $ip1         = "147.79.120.202" ascii
        $ip2         = "92.112.198.22" ascii

        // Forensic fingerprint left by the service worker
        $idb_log     = "Deleted IndexedDB database:" ascii

        // Forged Google SERP attribution pattern
        $serp_spoof  = /google\.com\/url\?sa=t&source=web/ ascii

    condition:
        filesize < 50MB and (
            // Two or more operator domains — IOC dump or writeup
            2 of ($dom_tab, $dom_yow, $dom_cw, $dom_owhit)
            // Or any operator domain co-occurring with the ad-fraud infra
            or (any of ($dom_tab, $dom_yow, $dom_cw, $dom_owhit) and ($dom_avads or any of ($ip*)))
            // Or the forensic log string — unique to this family
            or $idb_log
            // Or an origin IP with ad-fraud domain
            or (any of ($ip*) and $dom_avads)
            // Or SERP spoofing pattern with any operator domain
            or ($serp_spoof and any of ($dom_tab, $dom_yow, $dom_cw, $dom_owhit))
        )
}
