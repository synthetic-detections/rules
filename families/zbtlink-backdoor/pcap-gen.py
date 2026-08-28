#!/usr/bin/env python3
"""
Synthetic PCAPs for the SPEAKINGSTONE / DARKLANTERN (Zbtlink) smoke test.

attack-darklantern-9992.pcap    : inbound UDP/9992 carrying "revProto".
attack-speakingstone-10000.pcap : inbound UDP/10000 carrying "zbtProtocol".
attack-speakingstone-reply.pcap : implant reply from UDP src 8897 (zbtProtocol).
attack-c2-dns.pcap              : DNS A queries for ac-link.com and
                                  www.findmyipaddr.com.
attack-c2-ip.pcap               : opaque UDP to the C2 IP 47.107.224.89.
benign-udp.pcap                 : unrelated UDP/9992 payload + a benign DNS
                                  lookup (www.zbt-china.com) -- no proto tag,
                                  no C2 domain, must stay silent.
"""
import os
from scapy.all import IP, UDP, DNS, DNSQR, Raw, wrpcap

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
INT = "10.99.0.10"     # infected router (HOME_NET)
EXT = "203.0.113.7"    # attacker / C2 (EXTERNAL_NET)


def udp(src, dst, sport, dport, payload):
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)


def dnsq(qname):
    return (IP(src=INT, dst="10.99.0.53")
            / UDP(sport=40000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname)))


def main():
    os.makedirs(HERE, exist_ok=True)

    wrpcap(f"{HERE}/attack-darklantern-9992.pcap",
           [udp(EXT, INT, 33333, 9992, b"revProto\x01cmd=/etc/exec/cmd id")])

    wrpcap(f"{HERE}/attack-speakingstone-10000.pcap",
           [udp(EXT, INT, 44444, 10000, b"zbtProtocol\x02register mac")])

    wrpcap(f"{HERE}/attack-speakingstone-reply.pcap",
           [udp(INT, EXT, 8897, 44444, b"zbtProtocol\x02ack ok")])

    wrpcap(f"{HERE}/attack-c2-dns.pcap",
           [dnsq("ac-link.com"), dnsq("www.findmyipaddr.com")])

    wrpcap(f"{HERE}/attack-c2-ip.pcap",
           [udp(INT, "47.107.224.89", 40001, 9992, b"beacon")])

    # Benign: unrelated UDP to 9992 (no proto tag) + a legit vendor DNS lookup.
    wrpcap(f"{HERE}/benign-udp.pcap",
           [udp(EXT, INT, 50000, 9992, b"\x00\x11\x22random-udp-noise"),
            dnsq("www.zbt-china.com")])

    print("wrote attack-darklantern-9992.pcap, attack-speakingstone-10000.pcap, "
          "attack-speakingstone-reply.pcap, attack-c2-dns.pcap, attack-c2-ip.pcap, "
          "benign-udp.pcap")


if __name__ == "__main__":
    main()
