#!/usr/bin/env python3
# Regenerate the smoke-test pcaps for the proc-macro1 dropper Suricata rules.
# attack-*  -> must alert (>=1);  benign-* -> must be clean (0).
import os
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
os.makedirs(OUT, exist_ok=True)
HOME = "10.0.0.5"          # in Suricata's default HOME_NET

def tcp_flow(dst, dport, payload=b"", sport=44300):
    """3-way handshake then optional PSH-ACK with payload (HOME -> dst)."""
    pkts = []
    pkts.append(IP(src=HOME, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=1000))
    pkts.append(IP(src=dst, dst=HOME)/TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=1001))
    pkts.append(IP(src=HOME, dst=dst)/TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=5001))
    if payload:
        pkts.append(IP(src=HOME, dst=dst)/TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=5001)/Raw(load=payload))
    return pkts

def dns_query(name, server="8.8.8.8"):
    return [IP(src=HOME, dst=server)/UDP(sport=51000, dport=53)/DNS(rd=1, qd=DNSQR(qname=name))]

def client_hello(hostname):
    hn = hostname.encode()
    server_name = b"\x00" + len(hn).to_bytes(2,"big") + hn
    sni_list = len(server_name).to_bytes(2,"big") + server_name
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2,"big") + sni_list
    ext_block = len(sni_ext).to_bytes(2,"big") + sni_ext
    body  = b"\x03\x03" + b"\x00"*32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + ext_block
    hs    = b"\x01" + len(body).to_bytes(3,"big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2,"big") + hs

# ---- attack ----
wrpcap(f"{OUT}/attack-c2-payload-host.pcap", tcp_flow("23.254.165.112", 9089))
wrpcap(f"{OUT}/attack-c2-stage2.pcap",       tcp_flow("23.254.167.216", 443))
wrpcap(f"{OUT}/attack-dns-c2.pcap",          dns_query("hwsrv-798836.hostwindsdns.com"))
wrpcap(f"{OUT}/attack-tls-sni.pcap",         tcp_flow("23.254.165.112", 443, client_hello("hwsrv-798836.hostwindsdns.com")))

# ---- benign (structurally identical, clean destinations/names) ----
wrpcap(f"{OUT}/benign-crates-dns.pcap",      dns_query("static.crates.io"))
wrpcap(f"{OUT}/benign-github-tcp.pcap",      tcp_flow("140.82.112.3", 443))
wrpcap(f"{OUT}/benign-tls-sni.pcap",         tcp_flow("140.82.112.3", 443, client_hello("static.crates.io")))
print("wrote pcaps to", OUT)
