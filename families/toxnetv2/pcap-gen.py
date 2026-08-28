#!/usr/bin/env python3
"""
Synthetic PCAPs for the ToxNet v2 smoke test.

attack-kaf-delivery.pcap : GET /z0l1mxjm4mdl4jjfjf7sb2vdmv/kaf.sh from the
                           payload-delivery host 45.151.139.113.
attack-c2-ip.pcap        : opaque UDP to the Tox C2 node 45.130.151.214:33445.
benign-shell-fetch.pcap  : GET /scripts/setup.sh from an unrelated host --
                           a plain '.sh' fetch without the ToxNet path token,
                           must stay silent.
"""
import os
from scapy.all import IP, UDP, Raw, wrpcap
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _lib.h2c_http_helper import build_pcap

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")


def http_get(host, path, ua="curl/8.5.0"):
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1")


def main():
    os.makedirs(HERE, exist_ok=True)

    build_pcap(
        f"{HERE}/attack-kaf-delivery.pcap",
        [http_get("45.151.139.113", "/z0l1mxjm4mdl4jjfjf7sb2vdmv/kaf.sh")],
        server_ip="45.151.139.113",
    )

    wrpcap(
        f"{HERE}/attack-c2-ip.pcap",
        [IP(src="10.99.0.10", dst="45.130.151.214")
         / UDP(sport=41000, dport=33445) / Raw(b"tox-dht-ping")],
    )

    build_pcap(
        f"{HERE}/benign-shell-fetch.pcap",
        [http_get("mirror.example.org", "/scripts/setup.sh")],
        server_ip="198.51.100.20",
    )

    print("wrote attack-kaf-delivery.pcap, attack-c2-ip.pcap, benign-shell-fetch.pcap")


if __name__ == "__main__":
    main()
