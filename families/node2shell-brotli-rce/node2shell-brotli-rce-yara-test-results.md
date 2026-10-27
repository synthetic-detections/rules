# Node2Shell / Brotli CVE-2026-111497 — YARA test results

Rule file: `node2shell-brotli-rce.yar` (2 rules)
Family: `node2shell-brotli-rce`
Sources: Imperva "Node2Shell" write-up, Sysdig detection blog, Miggo analysis.

## Rules
1. `Node2Shell_HTTP_Request_Delivery` (high) — HTTP POST with
   `Content-Encoding: br` + API content type; Brotli-compressed request
   bodies are rare in legitimate traffic and the primary inbound attack
   vector for Express 5 / body-parser 2.x / Koa / Fastify.
2. `Node2Shell_HTTP_Response_Delivery` (medium) — HTTP 200 with
   `Content-Encoding: br` + small Content-Length (< 256 bytes); tiny
   Brotli responses are uncommon because compression overhead exceeds
   savings at that size.

Not covered (by design): the actual Brotli stream structure (single
block type + block switch) is a bit-level anomaly that YARA string
matching cannot express. The Imperva PoC (86 bytes) is withheld, and
no public PoC exists. Detection targets the HTTP delivery envelope,
not the stream internals. Runtime detection (Falco, WAF, Miggo) is
better suited for the decompression-path trigger.

## Specimens (synthetic)

Constructed from RFC 7932 format spec + vulnerability description:

- `malformed-brotli-stream.bin` — 57-byte Brotli stream declaring
  NBLTYPES=1 for all categories + 0xFF fill data (structural anomaly
  pattern). Fails brotli.decompress() as expected.
- `node2shell-request.bin` — Synthetic HTTP POST with Content-Encoding:
  br carrying the malformed stream (Express 5 attack vector).
- `node2shell-response.bin` — Synthetic HTTP 200 with Content-Encoding:
  br carrying the malformed stream (fetch() attack vector).
- `valid-brotli-reference.bin` (benign) — 19-byte legitimate Brotli
  stream compressing `{"status":"ok"}`.

## In-repo smoke test

Environment: YARA 4.5.2, Linux x86_64, 2026-10-27.

`yara -r node2shell-brotli-rce.yar specimens/` → 2 hits:

| Specimen | Rule matched |
|---|---|
| `node2shell-request.bin` | `Node2Shell_HTTP_Request_Delivery` |
| `node2shell-response.bin` | `Node2Shell_HTTP_Response_Delivery` |

`malformed-brotli-stream.bin` does NOT match either rule (expected —
rules target the HTTP envelope, not bare Brotli streams).

`yara -r node2shell-brotli-rce.yar benign/` → **0 hits (clean)**.

## Corpus FP test

PENDING — jobs 48-49 submitted to yaragate, awaiting results.
