/*
   BdThemes "Biggopti" WordPress supply-chain compromise (poisoned banner API)
   --------------------------------------------------------------------------
   Reported 2026-08-08 by the Wordfence Threat Intelligence Team. Seven BdThemes
   Elementor add-on plugins (Element Pack, Live Copy Paste, Pixel Gallery, Prime
   Slider, Smart Admin Assistant, Ultimate Post Kit, Ultimate Store Kit) share a
   promotional-banner component "Biggopti" that fetches flat JSON from a static
   DigitalOcean Spaces bucket ("Sigmative API"). A client-side XSS (the
   display_id field is concatenated into an HTML id attribute without escaping,
   introduced 2026-03-01 in Prime Slider 4.1.9) was weaponised when an actor with
   WRITE ACCESS to the bucket replaced the legitimate JSON with a payload that
   breaks out of the id attribute via an onanimationstart handler, executing in
   every logged-in admin's browser on each wp-admin page load.

   Kill chain: poisoned display_id -> eval(String.fromCharCode(...)) ->
   fetch api.sigmative[.]io/prod/store/api/biggopti/x.js -> new Function(text)().
   Primary payload w2.js: C2-checks ia-cdn[.]com/fz/c, creates a rogue admin via
   the WP REST API using the live X-WP-Nonce, drops webshell emer-run.php inside
   a fake plugin ZIP (slug wp-smart-thumbnails or similar), then installs two
   MU-plugin backdoors (a magic-login backdoor reachable via ?_wplogin=<token>,
   and a stealth module that hooks DB queries to hide the rogue accounts).
   Alternate payload x.js: deterministic creds from the site hostname —
   user "bd_<6-char base36 hash>", pass "Bd@26!<hash>x".

   No plugin update or on-disk file change is required to be victimised: the
   malicious code lives in a remote JSON response and in-memory admin JS, so
   file-integrity scanners see nothing. These rules therefore target (1) the
   poisoned banner-JSON payload shape, (2) the dropped PHP webshell/backdoor
   artifacts on disk, and (3) hard host/network + credential-scheme IOCs.

   Rule shape:
     (1) Biggopti_Poisoned_Banner_Payload  — behavioural, the JSON/JS injection
         shape (onanimationstart breakout + fromCharCode stager + Sigmative host)
     (2) Biggopti_Dropped_Webshell_Backdoor — the on-disk PHP artifacts
         (emer-run webshell, ?_wplogin magic-login, deterministic bd_ creds),
         gated so a lone generic token cannot fire
     (3) Biggopti_IOCs — hard IOCs (C2 host, staging host, md5 pins), high conf

   Guards: the bare strings "display_id", "onanimationstart", "MU-plugin",
   "?_wplogin" or a lone slug are legitimate/benign on their own and are never
   allowed to match in isolation — every rule requires co-occurrence.

   Siblings (supply-chain / npm+ecosystem poisoning / webshell):
     [[chaindrop-npm-worm]], [[gitlost-github-agent-injection]]

   Sources:
     https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/

   Known samples (md5, MU-plugin/webshell PHP):
     1024732009983dd5e54b4cf5593f04d4  emer-run.php (webshell)
     7719cd98a35ffad2771f26d1ceab7d27  class-wp-token-validate.php (magic-login)
     9aadc3e5c5242b273bd17c5bdc358845  class-wp-query-*.php (stealth module)
     e450ae5bc4bfc0d960dded06a76bb8e9  wp-cache-optimizer.php ("Health Check")
*/

rule Biggopti_Poisoned_Banner_Payload
{
    meta:
        description = "BdThemes/Biggopti poisoned banner-JSON: onanimationstart id-attribute breakout + fromCharCode stager fetching the Sigmative payload"
        author      = "synthetic-detections"
        date        = "2026-08-09"
        severity    = "critical"
        family      = "bdthemes-biggopti-supply-chain"
        reference   = "https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/"

    strings:
        // (1) the XSS breakout vector used in the poisoned display_id
        $brk1 = "onanimationstart=" ascii wide nocase
        $brk2 = "animation:wrapperSlideInTop" ascii wide nocase

        // (2) the fromCharCode/eval stager that reassembles the fetch()
        $stg1 = "eval(String.fromCharCode(" ascii wide nocase
        $stg2 = "new Function(t)()" ascii wide nocase
        $stg3 = ".then(r=>r.text())" ascii wide nocase

        // (3) Biggopti/Sigmative context tying it to this family
        $ctx1 = "biggopti" ascii wide nocase
        $ctx2 = "sigmative" ascii wide nocase
        $ctx3 = "display_id" ascii wide nocase
        $ctx4 = "/prod/store/api/biggopti/" ascii wide nocase

    condition:
        // breakout OR stager, AND a family-context anchor
        ((any of ($brk*)) or (any of ($stg*))) and (any of ($ctx*))
        and filesize < 512KB
}

rule Biggopti_Dropped_Webshell_Backdoor
{
    meta:
        description = "BdThemes/Biggopti on-disk PHP artifacts: emer-run webshell, ?_wplogin magic-login MU-plugin, or deterministic bd_ credential scheme"
        author      = "synthetic-detections"
        date        = "2026-08-09"
        severity    = "critical"
        family      = "bdthemes-biggopti-supply-chain"
        reference   = "https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/"

    strings:
        $php = "<?php"

        // dropped-artifact filenames / disguised slugs
        $a1 = "emer-run.php" ascii wide nocase
        $a2 = "wp-smart-thumbnails" ascii wide nocase
        $a3 = "wp-cache-optimizer.php" ascii wide nocase
        $a4 = "class-wp-token-validate.php" ascii wide nocase

        // magic-login backdoor entry (targets longest-registered admin)
        $b1 = "_wplogin" ascii wide nocase

        // deterministic credential scheme from the site hostname (x.js -> PHP)
        $c1 = "Bd@26!" ascii wide
        $c2 = /\bbd_[0-9a-z]{1,6}\b/ ascii wide

        // rogue-admin / MU-plugin persistence action
        $d1 = "wp-content/mu-plugins" ascii wide nocase
        $d2 = "wp_insert_user" ascii wide nocase
        $d3 = "X-WP-Nonce" ascii wide nocase

    condition:
        $php and (
            any of ($a*)                       // named dropped artifact
            or ($b1 and any of ($d*))          // magic-login + persistence/admin
            or (($c1 or $c2) and any of ($d*)) // deterministic creds + action
        )
        and filesize < 256KB
}

rule Biggopti_IOCs
{
    meta:
        description = "BdThemes/Biggopti hard IOCs — C2 ia-cdn.com/fz/c, Sigmative staging host, and dropped-artifact md5 pins"
        author      = "synthetic-detections"
        date        = "2026-08-09"
        severity    = "high"
        family      = "bdthemes-biggopti-supply-chain"
        reference   = "https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/"

    strings:
        $c2   = "ia-cdn.com/fz/c" ascii wide nocase
        $host = "api.sigmative.io" ascii wide nocase
        $path = "sigmative.io/prod/store/api/biggopti/x.js" ascii wide nocase

        // md5 pins (recorded for hash-sweep parity; string form for text IOC feeds)
        $h1 = "1024732009983dd5e54b4cf5593f04d4" ascii wide nocase
        $h2 = "7719cd98a35ffad2771f26d1ceab7d27" ascii wide nocase
        $h3 = "9aadc3e5c5242b273bd17c5bdc358845" ascii wide nocase
        $h4 = "e450ae5bc4bfc0d960dded06a76bb8e9" ascii wide nocase

    condition:
        any of them and filesize < 2MB
}
