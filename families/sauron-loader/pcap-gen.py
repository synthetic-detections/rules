#!/usr/bin/env python3
# Regenerate the smoke-test pcaps for the Sauron Loader Suricata rules.
# attack-*  -> must alert (>=1);  benign-* -> must be clean (0).
import os
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
os.makedirs(OUT, exist_ok=True)
HOME = "10.0.0.5"          # in Suricata's default HOME_NET
CF   = "104.21.48.1"       # Cloudflare edge (documentation stand-in)

def tcp_flow(dst, dport, payload=b"", sport=49700):
    """3-way handshake then optional PSH-ACK with payload (HOME -> dst)."""
    pkts = [
        IP(src=HOME, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=1000),
        IP(src=dst, dst=HOME)/TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=1001),
        IP(src=HOME, dst=dst)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=5001),
    ]
    if payload:
        pkts.append(IP(src=HOME, dst=dst)/TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=5001)/Raw(load=payload))
    return pkts

def dns_query(name, server="8.8.8.8", sport=51000):
    return [IP(src=HOME, dst=server)/UDP(sport=sport, dport=53)/DNS(id=sport & 0xffff, rd=1, qd=DNSQR(qname=name))]

def client_hello(hostname):
    hn = hostname.encode()
    server_name = b"\x00" + len(hn).to_bytes(2, "big") + hn
    sni_list = len(server_name).to_bytes(2, "big") + server_name
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    ext_block = len(sni_ext).to_bytes(2, "big") + sni_ext
    body = b"\x03\x03" + b"\x00"*32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + ext_block
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs

C2 = ["api.namsb-show.com", "api.quinlantours.com", "api.virtual-magic.com",
      "api.lahaina-shores.com", "api.mythicinsights.com"]

# ---- attack: one DNS lookup per C2 host, TLS SNI to two of them ----
dns = []
for i, h in enumerate(C2):
    dns += dns_query(h, sport=51000 + i)
wrpcap(f"{OUT}/attack-dns-c2.pcap", dns)
wrpcap(f"{OUT}/attack-tls-sni-namsb.pcap",  tcp_flow(CF, 443, client_hello("api.namsb-show.com")))
wrpcap(f"{OUT}/attack-tls-sni-mythic.pcap", tcp_flow(CF, 443, client_hello("api.mythicinsights.com"), sport=49701))

# ---- benign: look-alike names that share the suffix but not the domain ----
wrpcap(f"{OUT}/benign-dns-lookalike.pcap",
       dns_query("api.lahainashores.com") + dns_query("myvirtual-magic.com", sport=51010))
wrpcap(f"{OUT}/benign-tls-sni-lookalike.pcap", tcp_flow(CF, 443, client_hello("www.notquinlantours.com")))
print("wrote pcaps to", OUT)
