#!/usr/bin/env python3
"""
Synthetic HTTP/1.1 PCAPs for the StyleSmuggler Magento/Adobe Commerce smoke test.

StyleSmuggler (Sansec, 2026-09-05): an unauthenticated RCE 0-day whose network
exploit stage abuses two POST endpoints. The malicious payload travels in the
HTTP *request body*, not the URI:

  * GraphQL `styles[...]` PHP injection -> POST /graphql, body carries the
    `styles[...]` mutation argument that reaches a PHP `eval`   -> sid 9500131
  * PayPal transparent-response webshell -> POST /paypal/transparent/response/,
    body carries `eval(base64_decode(...))`                     -> sid 9500132

Regression note: sid 9500131 previously left `styles[`/`eval` in the `http.uri`
sticky buffer, so it could never fire on a real GraphQL POST (the URI is just
`/graphql`; the payload is in the body). attack-graphql-styles-injection.pcap
reproduces that real request shape — it must alert now and would stay silent
against the old URI-scoped rule.

Attack PCAPs (should alert):
  attack-graphql-styles-injection.pcap : POST /graphql, styles[...]+eval in body -> sid 9500131
  attack-paypal-response-webshell.pcap : POST /paypal/transparent/response/,
                                         eval(base64_decode(...)) in body        -> sid 9500132

Benign PCAPs (should stay clean):
  benign-graphql-query.pcap : normal Magento GraphQL POST, no styles[]/eval
  benign-graphql-uri-noise.pcap : POST /graphql?styles[0]=eval — the payload
                                  tokens live in the URI query string, the body
                                  is a clean query. This is exactly what the old
                                  URI-scoped rule (wrongly) keyed off, so it would
                                  FALSE-POSITIVE on the old rule; the fixed
                                  body-scoped rule must stay silent.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _lib.h2c_http_helper import build_pcap


def http_post(host: str, path: str, body: bytes,
              content_type: str = "application/json") -> bytes:
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    return headers + body


def http_200_ok() -> bytes:
    body = b'{"data":{}}'
    headers = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("latin-1")
    return headers + body


# GraphQL mutation whose `styles[...]` argument smuggles a PHP eval gadget into
# the server-side render. Payload shape is illustrative; the rule keys on the
# `styles[` + `eval` co-occurrence in the request body.
GRAPHQL_STYLES_INJECTION = (
    b'{"query":"mutation{setStyles(styles[0]:\\"a\\";'
    b'eval($_POST[c]);//):ok}"}'
)

# PayPal transparent-response webshell drop: eval(base64_decode(...)).
PAYPAL_WEBSHELL_BODY = (
    b'RESULT=0&RESPMSG=Approved&'
    b'PNREF=<?php eval(base64_decode($_REQUEST["s"]));?>'
)

# Benign Magento GraphQL storefront query — no styles[]/eval.
BENIGN_GRAPHQL_BODY = (
    b'{"query":"query{products(filter:{sku:{eq:\\"WT08\\"}}){items{name price}}}"}'
)


def main() -> None:
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
    os.makedirs(here, exist_ok=True)
    host = "shop.example.com"

    # --- attacks ---
    build_pcap(
        f"{here}/attack-graphql-styles-injection.pcap",
        [http_post(host, "/graphql", GRAPHQL_STYLES_INJECTION)],
        [http_200_ok()],
    )
    build_pcap(
        f"{here}/attack-paypal-response-webshell.pcap",
        [http_post(host, "/paypal/transparent/response/", PAYPAL_WEBSHELL_BODY,
                   content_type="application/x-www-form-urlencoded")],
        [http_200_ok()],
    )

    # --- benign ---
    build_pcap(
        f"{here}/benign-graphql-query.pcap",
        [http_post(host, "/graphql", BENIGN_GRAPHQL_BODY)],
        [http_200_ok()],
    )
    # URI-only decoy: the payload tokens live in the query string, not the body.
    # The old URI-scoped rule would (wrongly) have keyed off this; the fixed
    # body-scoped rule must stay silent.
    build_pcap(
        f"{here}/benign-graphql-uri-noise.pcap",
        [http_post(host, "/graphql?styles[0]=eval", BENIGN_GRAPHQL_BODY)],
        [http_200_ok()],
    )

    print("wrote 2 attack + 2 benign pcaps")


if __name__ == "__main__":
    main()
