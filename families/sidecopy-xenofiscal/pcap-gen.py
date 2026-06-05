#!/usr/bin/env python3
"""
Synthetic PCAPs for the SideCopy / Operation XENOFISCAL smoke test.

benign-edu-browse.pcap     : normal HTTPS-shaped GET to a benign .edu site
                             (text/html, real-browser User-Agent).
attack-mshta-hta.pcap      : GET /institute/cloudiya/zuidrt.hta from
                             abimj.edu.af with mshta-style User-Agent.
attack-xenorat-c2.pcap     : opaque TCP packet to 185.235.137.106 — the
                             reported XenoRAT C2.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _lib.h2c_http_helper import build_pcap


def http_get(host: str, path: str, ua: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("latin-1")


def http_200(body: bytes = b"OK", ctype: str = "application/octet-stream") -> bytes:
    headers = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode("latin-1")
    return headers + body


def main() -> None:
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")

    # Benign — a real-browser User-Agent fetching an .edu page.
    benign = http_get(
        "students.example.edu",
        "/news/spring-schedule.html",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    )
    build_pcap(f"{here}/benign-edu-browse.pcap", [benign],
               [http_200(b"<html>schedule</html>", "text/html")])

    # Attack — mshta-style User-Agent fetching the HTA from abimj.edu.af.
    attack = http_get(
        "abimj.edu.af",
        "/institute/cloudiya/zuidrt.hta",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; "
        "Trident/8.0; rv:11.0) like Gecko",
    )
    build_pcap(f"{here}/attack-mshta-hta.pcap", [attack],
               [http_200(b"<html><script>...</script></html>",
                         "application/hta")])

    # XenoRAT C2 — opaque TCP push to 185.235.137.106. No HTTP layer.
    build_pcap(
        f"{here}/attack-xenorat-c2.pcap",
        [b"\x10\x20\x30\x40beacon-ping-fake"],
        server_ip="185.235.137.106",
        server_port=4433,
    )

    print("wrote benign-edu-browse.pcap, attack-mshta-hta.pcap, attack-xenorat-c2.pcap")


if __name__ == "__main__":
    main()
