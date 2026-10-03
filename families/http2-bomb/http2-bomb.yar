/*
   HTTP/2 Bomb — Quang Luong / Codex team (disclosed 2026-06-03)
   --------------------------------------------------------------
   Remote DoS chaining two long-known HTTP/2 weaknesses:
     1. HPACK "Indexed Reference Bomb" — seed the dynamic table with one
        large header, then emit thousands of 1-byte indexed references to
        amplify the decoded header block on the server side.
     2. Flow-control stall — advertise a 0-byte receive window so the
        server can never finish sending, then drip 1-byte WINDOW_UPDATE
        frames to keep resetting the send timeout.
     3. RFC 9113 §8.2.3 Cookie-crumb splitting bypasses naive per-field
        header-count limits in nginx / Apache / IIS / Envoy / Pingora.

   Apache fix: CVE-2026-49975 (mod_http2 v2.0.41).
   nginx fix: 1.29.8 with `max_headers` directive defaulting to 1000.
   IIS / Cloudflare Pingora: no patch at disclosure.

   YARA scope: this is a wire-level DoS; on-disk detection focuses on PoC
   source code, weaponised derivatives, and any local clones of the
   reference exploit repository. The rules do NOT see HTTP/2 traffic —
   pair with WAF / proxy signatures for actual exploitation detection.

   Rule 1 — behavioural: PoC source-code shape — HPACK indexed-reference
            loop + zero window + WINDOW_UPDATE drip + HTTP/2 framing.
   Rule 2 — IOC sweep: Codex / califio repo path, MADBugs identifier,
            technique names, author handles.

   Sources:
     https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb
     https://seclists.org/oss-sec/2026/q2/790
     https://thehackernews.com/2026/06/new-http2-bomb-vulnerability-allows.html
     https://www.securityweek.com/http-2-bomb-exploit-knocks-web-servers-offline-in-seconds/
*/

rule HTTP2_Bomb_PoC_SourceCode {
    meta:
        description = "PoC / derivative exploit source for the HTTP/2 Bomb DoS: HPACK indexed-reference amplification + zero-window flow-control stall"
        author = "synthetic-detections"
        date = "2026-06-04"
        severity = "critical"
        family = "http2-bomb"
        reference = "https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb"
    strings:
        $hpack_word = "HPACK"
        $h2_setting = "SETTINGS_INITIAL_WINDOW_SIZE"
        $h2_dynamic = /dynamic[ _]?table/
        $h2_indexed = /indexed[ _]?(reference|header)/
        $h2_send_preface = "PRI * HTTP/2.0"
        $zero_window = /(initial[_-]?window[_-]?size|recv[_-]?window)\s*[=:]\s*0\b/
        $drip = /WINDOW_UPDATE[^;\n]{0,120}(1|0x01|\\x01)\b/
        $crumb_phrase = /cookie[^,;\n]{0,40}(crumb|crumbs|split|fragment)/
        $technique = /indexed[ _-]?reference[ _-]?bomb/
        $lib_h2py = "h2.connection"
        $lib_hyper = "hyper.client"
        $lib_h2c = "http2.NewClientConn"
        $lib_nghttp2 = "nghttp2_session"
    condition:
        ($technique and any of ($lib_h2py, $lib_hyper, $lib_h2c, $lib_nghttp2) or any of ($lib_h2py, $lib_hyper, $lib_h2c, $lib_nghttp2, $h2_send_preface, $h2_setting) and $zero_window and $drip and ($h2_dynamic or $h2_indexed or $hpack_word or $crumb_phrase)) and filesize < 5MB
}

rule HTTP2_Bomb_PoC_IOC {
    meta:
        description = "Static IOCs for the HTTP/2 Bomb disclosure — Codex / califio publication path, MADBugs identifier, named authors, CVE token"
        author = "synthetic-detections"
        date = "2026-06-04"
        severity = "high"
        family = "http2-bomb"
        reference = "https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb"
    strings:
        $repo_path = "califio/publications/tree/main/MADBugs/http2-bomb" nocase
        $repo_short = "MADBugs/http2-bomb" nocase
        $madbugs = "MADBugs"
        $codex_blog = "blog.calif.io" nocase
        $cve_apache = "CVE-2026-49975" nocase
    condition:
        (any of ($repo_path, $repo_short, $madbugs, $codex_blog) or $cve_apache and any of ($repo_path, $repo_short, $madbugs, $codex_blog)) and filesize < 50MB
}
