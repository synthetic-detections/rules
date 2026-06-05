/*
   Windows Search URI handler NTLMv2 hash leak — Huntress disclosure (2026-06-03)
   ------------------------------------------------------------------------------
   A `search:` (or `search-ms:`) URI carrying a `crumb=location:` parameter
   pointing to an attacker-controlled SMB UNC path induces Windows Search to
   reach out over SMB, leaking the user's Net-NTLMv2 hash. Same primitive
   family as CVE-2023-35636 (Outlook) and CVE-2026-33829 (Snipping Tool);
   Microsoft has declined to fix this variant and assigned no CVE.

   Delivery vehicles are HTML links, Markdown links, .url / .website / .lnk
   shortcut files, and command-line invocations (`start "" "search:..."`).
   Resolved by HKCR via DelegateExecute CLSID {90b9bce2-b6db-4fd3-8451-35917ea1081b}.

   Rule 1 — behavioural: search: URI + crumb=location: + UNC pointer co-occurrence.
            Vehicle-agnostic.
   Rule 2 — HTML/document lure: <a href="search:...crumb=location:\\..."> structural.
   Rule 3 — registry/config anchor: DelegateExecute CLSID alongside the URI handler.

   Sources:
     https://www.huntress.com/blog/unpatched-ntlm-leak-windows-search-uri-handler
     https://thehackernews.com/2026/06/unpatched-windows-search-uri.html
*/

rule WindowsSearch_URI_NTLM_Leak_Lure
{
    meta:
        description = "Windows search: / search-ms: URI carrying crumb=location: pointing to an SMB UNC — NTLMv2 hash leak primitive (Huntress 2026-06-03)"
        author      = "synthetic-detections"
        date        = "2026-06-04"
        severity    = "critical"
        family      = "windows-search-uri-ntlm-leak"
        reference   = "https://www.huntress.com/blog/unpatched-ntlm-leak-windows-search-uri-handler"

    strings:
        // URI scheme
        $sch_search   = "search:" ascii nocase
        $sch_searchms = "search-ms:" ascii nocase

        // The bypass primitive — crumb=location: keys the SMB out-call destination
        $crumb_loc    = /crumb\s*=\s*location:/ ascii nocase

        // UNC pointer to attacker host, escaped or raw. Bounded length prevents
        // catastrophic backtracking; the search: URI pattern keeps the prefix close.
        $unc_raw      = /\\\\[A-Za-z0-9._-]{1,253}\\[A-Za-z0-9._$-]{1,80}/ ascii
        $unc_escaped  = /\\\\\\\\[A-Za-z0-9._-]{1,253}\\\\[A-Za-z0-9._$-]{1,80}/ ascii

    condition:
        filesize < 1MB
        and any of ($sch_search, $sch_searchms)
        and $crumb_loc
        and any of ($unc_raw, $unc_escaped)
}

rule WindowsSearch_URI_NTLM_Leak_HtmlAnchor
{
    meta:
        description = "HTML / HTA / Markdown-rendered anchor that delivers the Windows Search URI NTLM-leak lure in a single click"
        author      = "synthetic-detections"
        date        = "2026-06-04"
        severity    = "critical"
        family      = "windows-search-uri-ntlm-leak"
        reference   = "https://www.huntress.com/blog/unpatched-ntlm-leak-windows-search-uri-handler"

    strings:
        // <a href="search:...crumb=location:\\host\share"> or HTA-style equivalents
        $anchor_a    = /<a\b[^>]{0,400}href\s*=\s*["']search(-ms)?:[^"'>]{1,800}crumb\s*=\s*location:[^"'>]{1,400}/ ascii nocase

        // Markdown-style [text](search:...crumb=location:\\...)
        $anchor_md   = /\]\s*\(\s*search(-ms)?:[^)]{1,800}crumb\s*=\s*location:[^)]{1,400}\)/ ascii nocase

        // Command-line invocation as seen in the Huntress writeup
        $startcmd    = /start\s+""\s+"search(-ms)?:[^"]{1,800}crumb\s*=\s*location:[^"]{1,400}"/ ascii nocase

    condition:
        filesize < 1MB and any of them
}

rule WindowsSearch_URI_NTLM_Leak_RegistryAnchor
{
    meta:
        description = "Registry / config file referencing the search: URI DelegateExecute CLSID alongside the leak primitive — useful for hardening surveys and forensic snapshots"
        author      = "synthetic-detections"
        date        = "2026-06-04"
        severity    = "high"
        family      = "windows-search-uri-ntlm-leak"
        reference   = "https://www.huntress.com/blog/unpatched-ntlm-leak-windows-search-uri-handler"

    strings:
        $clsid_dele  = "90b9bce2-b6db-4fd3-8451-35917ea1081b" ascii nocase
        $delegate    = "DelegateExecute" ascii nocase
        $sch_search  = "search:" ascii nocase
        $sch_searchms = "search-ms:" ascii nocase

    condition:
        filesize < 5MB
        and $clsid_dele
        and ($delegate or $sch_search or $sch_searchms)
}
