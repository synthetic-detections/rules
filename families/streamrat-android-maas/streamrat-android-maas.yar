/*
   StreamRat Android MaaS banker (disclosed 2026-09-02, ThreatFabric)
   -------------------------------------------------------------------
   Android banking trojan / infostealer sold as Malware-as-a-Service (panel
   has user / supervisor / admin roles). Distributed through Meta and TikTok
   advertisements ("Steamtv Esp.", 2026-06-11 -> 2026-07-03, ~570,000 Meta
   users reached) impersonating a free TV-streaming service for Spanish
   speakers; victims overwhelmingly in Spain.

   Delivery is a multi-stage HTML/JavaScript dropper (index.html ->
   set_launcher.html / vpn_required.html / r1edmi.html) that lands an APK
   (app.apk, later update_<timestamp>.apk). Observed packages:
   io.base.one887 ("StrεαmTV Pro") and io.meat.hint ("Sistema de vídeo").

   Capabilities: Accessibility-service abuse for remote control; two screen
   modes — VNC through MediaProjection and HVNC through the Accessibility
   node tree (Adler-32 checksums de-duplicate frames / UI trees); overlay
   injections stored per target package as <package>.html under an
   "injections" directory; a non-functional VPN used to cut the victim's
   internet on demand. C2 is a WebSocket RPC: registration carries the custom
   headers X-Device-Id / X-Device-Model / X-Api-Level; commands are a 2-byte
   opcode + 4-byte id (+payload). Infrastructure overlaps a GitHub repository
   previously used to distribute the Mirax trojan.

   YARA scans DEX/resource string tables; in standard APKs classes.dex is
   stored uncompressed so YARA matches raw APK bytes. Repacked buyer builds
   may hide Rule 1 strings — Rules 2 and 3 carry coverage for the
   distributed form and for IOC feeds.

   Anchors (strongest -> weakest):
     - Package names, C2 IPs and the two published APK SHA-256 hashes
       (verbatim, ThreatFabric) — Rules 2 and 3.
     - The custom WebSocket registration header triplet, the dropper page
       set, and the injections/MediaProjection/Accessibility cluster —
       Rule 1. Reported artifacts (medium confidence); every path requires
       multi-subsystem co-occurrence.

   Rule 1 — Behavioural (critical): WebSocket header triplet, dropper page
            set, overlay-injection + screen-capture cluster, gated.
   Rule 2 — IOC (high): package names, C2 IPs, app labels / ad lure paired.
   Rule 3 — Specimen (critical): the two published APK SHA-256 hashes as text.

   Sibling families: [[redwing-android-maas]] (Android MaaS banker, WebSocket
   C2), [[rokarolla-android-banker]]. No shared infrastructure reported.

   Sources:
     https://www.threatfabric.com/blogs/from-meta-ads-to-full-device-takeover-uncovering-streamrat
     https://thehackernews.com/2026/09/meta-ads-push-streamrat-android-trojan.html
     https://www.malwarebytes.com/blog/news/2026/09/streamrat-android-malware-spreads-through-meta-and-tiktok-ads
*/

rule StreamRat_Behavior
{
    meta:
        description = "StreamRat Android MaaS — custom WebSocket registration headers, HTML dropper page set, overlay-injection + screen-capture cluster"
        author      = "synthetic-detections"
        date        = "2026-09-05"
        severity    = "critical"
        family      = "streamrat-android-maas"
        reference   = "https://www.threatfabric.com/blogs/from-meta-ads-to-full-device-takeover-uncovering-streamrat"

    strings:
        // WebSocket registration header triplet (all three together is the
        // distinctive signature; X-Device-Id alone is common in benign SDKs)
        $h_id     = "X-Device-Id" ascii
        $h_model  = "X-Device-Model" ascii
        $h_api    = "X-Api-Level" ascii
        $ws_up    = "Upgrade: websocket" ascii nocase
        $ws_sch   = "wss://" ascii

        // Multi-stage HTML dropper pages
        $pg_launch = "set_launcher.html" ascii
        $pg_vpn    = "vpn_required.html" ascii
        $pg_r1     = "r1edmi.html" ascii
        $pg_apk    = "app.apk" ascii
        $pg_upd    = "update_" ascii

        // Overlay injections + screen capture / control subsystems
        $inj_dir   = "injections" ascii fullword
        $mp_api    = "android.media.projection.MediaProjection" ascii
        $acc_svc   = "android.accessibilityservice.AccessibilityService" ascii
        $acc_shot  = "takeScreenshot" ascii
        $vpn_svc   = "android.net.VpnService" ascii

    condition:
        filesize < 100MB
        and (
            // Path 1: the header triplet + WebSocket transport
            (all of ($h_*) and any of ($ws_*))
            or
            // Path 2: dropper page set (2 of the 3 bespoke pages + payload name)
            (2 of ($pg_launch, $pg_vpn, $pg_r1) and any of ($pg_apk, $pg_upd))
            or
            // Path 3: overlay injections + both screen-capture routes + kill-switch VPN
            ($inj_dir and $mp_api and ($acc_svc or $acc_shot) and $vpn_svc
             and any of ($h_*))
            or
            // Path 4: cross-subsystem — header triplet + injections/capture context
            (all of ($h_*) and $inj_dir and ($mp_api or $acc_shot))
        )
}

rule StreamRat_IOC
{
    meta:
        description = "StreamRat static IOC sweep — dropper package names, C2 IPs, app labels and ad lure paired"
        author      = "synthetic-detections"
        date        = "2026-09-05"
        severity    = "high"
        family      = "streamrat-android-maas"
        reference   = "https://www.threatfabric.com/blogs/from-meta-ads-to-full-device-takeover-uncovering-streamrat"

    strings:
        // Package names (distinctive)
        $pkg1 = "io.base.one887" ascii fullword
        $pkg2 = "io.meat.hint" ascii fullword

        // C2 servers
        $ip1  = "45.147.28.59" ascii fullword
        $ip2  = "193.32.2.245" ascii fullword

        // App labels / ad lure — only credited when paired
        $lbl1 = "Sistema de v\xc3\xaddeo" ascii
        $lbl2 = "Str\xce\xb5\xce\xb1mTV" ascii
        $lure = "Steamtv Esp" ascii nocase

    condition:
        filesize < 100MB
        and (
            any of ($pkg*)
            or any of ($ip*)
            or 2 of ($lbl*, $lure)
        )
}

rule StreamRat_Specimen_Pin
{
    meta:
        description = "Hash pin for the two published StreamRat APK samples (SHA-256, matched as text)"
        author      = "synthetic-detections"
        date        = "2026-09-05"
        severity    = "critical"
        family      = "streamrat-android-maas"
        reference   = "https://www.threatfabric.com/blogs/from-meta-ads-to-full-device-takeover-uncovering-streamrat"

    strings:
        $sha1 = "e0714788b4e2518b0d9d4cbf18c7217bb97718e01689d77338f1cc4a230fcb6c" ascii nocase
        $sha2 = "ba83cc3c9535690191018edf73ca5c6001609df9919462796aa2e551f142e4d3" ascii nocase

    condition:
        any of them
}
