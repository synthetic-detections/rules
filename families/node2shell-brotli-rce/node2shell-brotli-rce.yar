/*
   Node2Shell — CVE-2026-111497 Brotli decoder OOB write
   -----------------------------------------------------
   Out-of-bounds write in Google's Brotli C decoder (1.0.3–1.2.0),
   bundled in Node.js, Bun, Envoy, Istio, and Python brotli. A crafted
   Brotli stream declares one block type per category (NBLTYPES=1) then
   contains data the decoder misinterprets as a block-switch command.
   The 2018 fast-path returns an error code indistinguishable from
   "need more input," so the caller feeds more data, writing past the
   internal buffer boundary.

   Attack vectors:
     - Inbound: POST with Content-Encoding: br to Express 5 / body-parser
       2.x / Koa / Fastify (decodes Brotli request bodies by default)
     - Outbound: HTTP response with Content-Encoding: br consumed by
       Node.js fetch(), axios, got, SuperAgent, Next.js SSR

   Imperva demonstrated RCE ("Node2Shell") on Node.js 24.22.0 arm64.
   No public PoC released; the 86-byte test stream is withheld.
   Synthetic specimens here reconstruct the structural anomaly from the
   RFC 7932 format spec and the vulnerability description.

   Fixed: Brotli 1.0.10/1.1.1/1.2.1, Node.js 22.23.4/24.22.1/26.12.1,
   Bun 1.4.4. Fix commit: upstream 0ed4268a (distinct error return for
   invalid block switch, new BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH).

   Rule shape:
     (1) Node2Shell_HTTP_Request_Delivery  — behavioural/high: HTTP POST
         with Content-Encoding: br + small body (attack delivery via
         Express/body-parser)
     (2) Node2Shell_HTTP_Response_Delivery — behavioural/medium: HTTP 200
         with Content-Encoding: br + small body (attack delivery via
         fetch/axios)

   Detection strategy: Brotli decompression exploits leave no files on
   disk — detection is network-layer. These rules match captured HTTP
   traffic (PCAPs, proxy logs, WAF dumps) for the exploit delivery
   pattern. The Content-Encoding: br in a POST request body is unusual
   enough to be a high-signal indicator, while in responses it's common
   (compressed APIs), so the response rule adds a size guard.

   Sources:
     https://thehackernews.com/2026/10/researchers-demonstrate-node2shell-rce.html
     https://www.sysdig.com/blog/node2shell-cve-2026-111497-detecting-the-node-js-brotli-rce
     https://www.miggo.io/post/node2shell-cve-2026-111497-nodejs-vulnerability
*/

rule Node2Shell_HTTP_Request_Delivery : exploit network
{
    meta:
        description = "Node2Shell CVE-2026-111497 delivery via HTTP request — POST with Content-Encoding: br body; Brotli-compressed request bodies are rare in legitimate traffic and the primary inbound attack vector for Express 5 / body-parser 2.x"
        author      = "synthetic-detections"
        date        = "2026-10-27"
        severity    = "high"
        family      = "node2shell-brotli-rce"
        reference   = "https://thehackernews.com/2026/10/researchers-demonstrate-node2shell-rce.html"
    strings:
        $method   = "POST "
        $ce_br    = "Content-Encoding: br" nocase
        $ct_json  = "Content-Type: application/json" nocase
        $ct_form  = "Content-Type: application/x-www-form-urlencoded" nocase
        $ct_multi = "Content-Type: multipart/form-data" nocase
        $http     = "HTTP/1."
        $crlf2    = "\r\n\r\n"
    condition:
        $method at 0
        and $ce_br
        and $http
        and $crlf2
        and any of ($ct_json, $ct_form, $ct_multi)
        and filesize < 4KB
}

rule Node2Shell_HTTP_Response_Delivery : exploit network
{
    meta:
        description = "Node2Shell CVE-2026-111497 delivery via HTTP response — tiny Brotli-compressed response body (under 256 bytes payload) that could exploit Node.js fetch(); legitimate Brotli responses this small are uncommon because the compression overhead exceeds the savings"
        author      = "synthetic-detections"
        date        = "2026-10-27"
        severity    = "medium"
        family      = "node2shell-brotli-rce"
        reference   = "https://www.miggo.io/post/node2shell-cve-2026-111497-nodejs-vulnerability"
    strings:
        $status = "HTTP/1.1 200"
        $ce_br  = "Content-Encoding: br" nocase
        $cl_1   = /Content-Length: [1-9]\d?\r\n/
        $cl_2   = /Content-Length: 1\d{2}\r\n/
        $cl_3   = /Content-Length: 2[0-4]\d\r\n/
        $cl_4   = /Content-Length: 25[0-6]\r\n/
        $crlf2  = "\r\n\r\n"
    condition:
        $status and $ce_br and $crlf2 and any of ($cl_1, $cl_2, $cl_3, $cl_4) and filesize < 2KB
}
