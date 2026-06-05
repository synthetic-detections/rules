#!/usr/bin/env python3
"""
Benign baseline: a normal h2.connection HTTP/2 client.
Uses the same library and HPACK-aware code path as a PoC would, but does
not advertise a zero receive window, does not drip flow-control updates,
and does not exercise the amplification primitives. Structurally similar
to the malicious sample — stresses the co-occurrence guard.
"""

import h2.connection
import h2.config

def fetch(host, path):
    config = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    conn.send_headers(stream_id=1, headers=[
        (":method", "GET"),
        (":path", path),
        (":scheme", "https"),
        (":authority", host),
        ("accept", "text/html"),
    ], end_stream=True)
    return conn.data_to_send()
