#!/usr/bin/env python3
"""Synthetic HTTP/1.1 PCAPs for ai-agent-gov-probe Suricata rules."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _lib.h2c_http_helper import build_pcap

PCAPS = os.path.join(os.path.dirname(__file__), "pcaps")
os.makedirs(PCAPS, exist_ok=True)

HOST = "collection-search.example.gov"

def http_get(path):
    return (
        f"GET {path} HTTP/1.1\r\nHost: {HOST}\r\n"
        f"User-Agent: python-httpx/0.27\r\nConnection: close\r\n\r\n"
    ).encode("latin-1")

def http_post(path, body):
    return (
        f"POST {path} HTTP/1.1\r\nHost: {HOST}\r\n"
        f"User-Agent: python-httpx/0.27\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
    ).encode("latin-1")

def http_200():
    b = b'{"results":[]}'
    return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(b) + b

# --- attack PCAPs (must alert) ---

# sid 9000901: INT32 boundary probe
build_pcap(os.path.join(PCAPS, "attack-int32-boundary.pcap"),
           [http_get("/collection-search?page=2147483648&q=divorce+records")],
           [http_200()])

# sid 9000902: debug + output enumeration
build_pcap(os.path.join(PCAPS, "attack-debug-output-enum.pcap"),
           [http_get("/api/search?q=test&debug=1&output=json")],
           [http_200()])

# sid 9000903: debug + raw enumeration
build_pcap(os.path.join(PCAPS, "attack-debug-raw-enum.pcap"),
           [http_get("/collection-search?id=5&debug=1&raw=true")],
           [http_200()])

# sid 9000904: guerrillamail in POST body
build_pcap(os.path.join(PCAPS, "attack-disposable-email.pcap"),
           [http_post("/api/register",
                      "email=sheet850ec368%40guerrillamailblock.com&org=OpenAI+Research&captcha=Ttuwosv")],
           [http_200()])

# sid 9000905: oai agent task tag
build_pcap(os.path.join(PCAPS, "attack-oai-agent-tag.pcap"),
           [http_get("/api/data?State_Id=1&tag=oai_dsqa250_counselor")],
           [http_200()])

# --- benign PCAPs (must NOT alert) ---

build_pcap(os.path.join(PCAPS, "benign-normal-search.pcap"),
           [http_get("/collection-search?page=3&q=divorce+records+1905")],
           [http_200()])

build_pcap(os.path.join(PCAPS, "benign-debug-only.pcap"),
           [http_get("/api/search?q=test&debug=1")],
           [http_200()])

build_pcap(os.path.join(PCAPS, "benign-normal-registration.pcap"),
           [http_post("/api/register", "email=user%40example.com&org=Acme+Corp")],
           [http_200()])

build_pcap(os.path.join(PCAPS, "benign-oauth-param.pcap"),
           [http_get("/api/data?oauth_token=abc123&scope=read")],
           [http_200()])

print(f"Generated {len(os.listdir(PCAPS))} PCAPs in {PCAPS}/")
