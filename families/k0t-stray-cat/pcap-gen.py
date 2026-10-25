#!/usr/bin/env python3
"""Generate test PCAPs for k0t Stray Cat Suricata rules."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '_lib'))
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

PCAP_DIR = os.path.join(os.path.dirname(__file__), 'pcaps')
os.makedirs(PCAP_DIR, exist_ok=True)

def dns_query(qname, dst='8.8.8.8'):
    return (Ether() /
            IP(dst=dst) /
            UDP(sport=12345, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=qname)))

# Attack: DNS queries for staging domains
attack_pkts = [
    dns_query('sthyjk.com'),
    dns_query('alknene.shop'),
    dns_query('radesashar.com'),
    dns_query('agent.afahimsa.top'),
]
wrpcap(os.path.join(PCAP_DIR, 'attack-dns-staging.pcap'), attack_pkts)

# Attack: DNS queries for MeshCentral C2
mesh_pkts = [
    dns_query('mesh.buttruyen.com'),
    dns_query('meshcentral.girydsfsggvb.com'),
]
wrpcap(os.path.join(PCAP_DIR, 'attack-dns-meshcentral.pcap'), mesh_pkts)

# Attack: TCP to AdaptixC2 team server
adaptix_pkts = [
    Ether() / IP(src='10.0.0.5', dst='64.94.85.14') /
    TCP(sport=44444, dport=4321, flags='S'),
    Ether() / IP(src='64.94.85.14', dst='10.0.0.5') /
    TCP(sport=4321, dport=44444, flags='SA'),
    Ether() / IP(src='10.0.0.5', dst='64.94.85.14') /
    TCP(sport=44444, dport=4321, flags='A'),
    Ether() / IP(src='10.0.0.5', dst='64.94.85.14') /
    TCP(sport=44444, dport=4321, flags='PA') / Raw(b'beacon'),
]
wrpcap(os.path.join(PCAP_DIR, 'attack-tcp-adaptixc2.pcap'), adaptix_pkts)

# Benign: DNS queries for unrelated domains
benign_pkts = [
    dns_query('example.com'),
    dns_query('google.com'),
    dns_query('meshcentral.com'),
]
wrpcap(os.path.join(PCAP_DIR, 'benign-dns-unrelated.pcap'), benign_pkts)

print(f"Generated {len(os.listdir(PCAP_DIR))} PCAPs in {PCAP_DIR}")
