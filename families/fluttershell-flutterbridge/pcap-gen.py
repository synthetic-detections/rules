#!/usr/bin/env python3
"""
Synthetic PCAPs for FlutterShell wire-rule smoke testing.
  benign-news-browse.pcap   -> HTTP GET to a benign news site
  attack-fluttershell-config.pcap -> HTTP GET to /getConfig on a FlutterShell C2
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _lib.h2c_http_helper import build_pcap


def http_get(host: str, path: str, ua: str = "Mozilla/5.0") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1")


def http_200(body: bytes = b"{}", ctype: str = "application/json") -> bytes:
    return (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("latin-1") + body


def main() -> None:
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
    os.makedirs(here, exist_ok=True)

    benign = http_get("news.example.com", "/article/123",
                      ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) "
                         "AppleWebKit/605.1.15 Safari/605.1.15")
    build_pcap(f"{here}/benign-news-browse.pcap", [benign],
               [http_200(b"<html>news</html>", "text/html")])

    attack = http_get("atsheisdomestic.org", "/getConfig",
                      ua="Mozilla/5.0 FlutterShell WebView")
    build_pcap(f"{here}/attack-fluttershell-config.pcap", [attack],
               [http_200(b'{"tasks":[{"cmd":"exec_sync"}]}')])
    print("wrote benign-news-browse.pcap and attack-fluttershell-config.pcap")


if __name__ == "__main__":
    main()
