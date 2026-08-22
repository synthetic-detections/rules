#!/usr/bin/env python3
"""
Synthetic PCAPs for the defcon-docsend-phish Suricata smoke test.

benign-docsend-browse.pcap   : real-browser GET to the legitimate docsend.com
                               viewer plus a GET /api/launcher/start on an
                               unrelated host — neither should alert.
attack-macos-getscpt.pcap    : GET /api/v1/getscpt/admin to 192.253.248.181
                               (backdoor config fetch) — sids 9000901, 9000909.
attack-macos-exfil.pcap      : POST /log to 86.54.25.213 — sids 9000902, 9000909.
attack-win-launcher.pcap     : POST /api/launcher/start on docsend.web12api.com
                               — sid 9000903.
attack-win-getfile.pcap      : GET /get_file?file=2Ec6QYynajHw on eu03hub.com
                               — sid 9000904.
attack-win-ledger.pcap       : GET /api/commands/BOTID on eu07connect.com
                               — sid 9000905.
attack-win-netsupport.pcap   : NetSupport CMD=POLL to msedgewebview1.pro on
                               87.120.104.88:443 (cleartext) — sids 9000906,
                               9000909.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _lib.h2c_http_helper import build_pcap  # noqa: E402

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")


def http_get(host: str, path: str, ua: str = BROWSER_UA) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1")


def http_post(host: str, path: str, body: bytes,
              ctype: str = "application/x-www-form-urlencoded",
              ua: str = BROWSER_UA) -> bytes:
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1") + body


def http_200(body: bytes = b"OK", ctype: str = "text/plain") -> bytes:
    return (
        f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("latin-1") + body


def main() -> None:
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
    os.makedirs(here, exist_ok=True)

    # Benign: legitimate DocSend viewer + an unrelated /api/launcher/start.
    build_pcap(f"{here}/benign-docsend-browse.pcap",
               [http_get("docsend.com", "/view/evdfym2aj5tend76"),
                http_post("launcher.example-games.com", "/api/launcher/start",
                          b'{"version":"1.2.3"}', "application/json")],
               [http_200(b"<html>DocSend</html>", "text/html"),
                http_200(b'{"ok":true}', "application/json")],
               server_ip="10.99.0.20")

    # macOS backdoor config fetch.
    build_pcap(f"{here}/attack-macos-getscpt.pcap",
               [http_get("192.253.248.181", "/api/v1/getscpt/admin", "curl/8.4.0")],
               [http_200(b"<?xml version=\"1.0\"?><plist/>", "application/xml")],
               server_ip="192.253.248.181")

    # macOS AMOS exfil.
    build_pcap(f"{here}/attack-macos-exfil.pcap",
               [http_post("86.54.25.213", "/log", b"user=admin&data=ZmFrZQ==",
                          ua="curl/8.4.0")],
               [http_200()],
               server_ip="86.54.25.213")

    # Windows Electron loader host profile.
    build_pcap(f"{here}/attack-win-launcher.pcap",
               [http_post("docsend.web12api.com", "/api/launcher/start",
                          b'{"hostname":"LAB","user":"victim","av":"Defender"}',
                          "application/json")],
               [http_200(b'{"stage2":"..."}', "application/json")],
               server_ip="10.99.0.30")

    # Windows stage-2 archive fetch.
    build_pcap(f"{here}/attack-win-getfile.pcap",
               [http_get("eu03hub.com", "/get_file?file=2Ec6QYynajHw")],
               [http_200(b"PK\x03\x04fake", "application/zip")],
               server_ip="10.99.0.31")

    # Ledger implant tasking.
    build_pcap(f"{here}/attack-win-ledger.pcap",
               [http_get("eu07connect.com", "/api/commands/0a1b2c3d")],
               [http_200(b'{"cmd":"noop"}', "application/json")],
               server_ip="10.99.0.32")

    # NetSupport gateway poll, cleartext on 443.
    build_pcap(f"{here}/attack-win-netsupport.pcap",
               [http_post("msedgewebview1.pro", "/fakeurl.htm",
                          b"CMD=POLL\r\nINFO=1\r\nACK=1\r\n",
                          ua="NetSupport Manager/1.3")],
               [http_200(b"CMD=ACK")],
               server_ip="87.120.104.88", server_port=443)

    print("wrote 1 benign + 6 attack pcaps")


if __name__ == "__main__":
    main()
