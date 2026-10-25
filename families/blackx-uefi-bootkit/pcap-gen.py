#!/usr/bin/env python3
"""Generate PCAPs for BlackX UEFI bootkit Suricata rule testing.

attack-dns-archivetj.pcap  — DNS query for archivetj.com (should alert)
attack-tls-archivetj.pcap  — TLS ClientHello with SNI archivetj.com (should alert)
benign-dns-example.pcap    — DNS query for example.com (should not alert)
benign-tls-example.pcap    — TLS ClientHello with SNI example.com (should not alert)
"""
import os
import struct

PCAP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
os.makedirs(PCAP_DIR, exist_ok=True)

PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION = (2, 4)
LINKTYPE_ETHERNET = 1


def pcap_header():
    return struct.pack("<IHHiIII", PCAP_MAGIC, *PCAP_VERSION, 0, 0, 65535, LINKTYPE_ETHERNET)


def pcap_record(data, ts_sec=1730000000, ts_usec=0):
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def eth_ipv4_udp(src_ip, dst_ip, sport, dport, payload):
    udp_len = 8 + len(payload)
    udp = struct.pack(">HHH", sport, dport, udp_len) + b"\x00\x00" + payload
    ip_total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_total, 0x1234, 0x4000,
                     64, 17, 0, bytes(map(int, src_ip.split("."))),
                     bytes(map(int, dst_ip.split("."))))
    eth = b"\x00" * 6 + b"\x00" * 6 + struct.pack(">H", 0x0800)
    return eth + ip + udp


def eth_ipv4_tcp(src_ip, dst_ip, sport, dport, payload, seq=1000, ack=2000, flags=0x18):
    tcp_hdr_len = 20
    tcp = struct.pack(">HHIIHHHH", sport, dport, seq, ack,
                      (tcp_hdr_len // 4) << 12 | flags, 65535, 0, 0) + payload
    ip_total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_total, 0x5678, 0x4000,
                     64, 6, 0, bytes(map(int, src_ip.split("."))),
                     bytes(map(int, dst_ip.split("."))))
    eth = b"\x00" * 6 + b"\x00" * 6 + struct.pack(">H", 0x0800)
    return eth + ip + tcp


def dns_query(name):
    labels = b""
    for part in name.split("."):
        labels += bytes([len(part)]) + part.encode()
    labels += b"\x00"
    qtype = struct.pack(">HH", 1, 1)  # A, IN
    header = struct.pack(">HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
    return header + labels + qtype


def tls_client_hello(sni):
    sni_bytes = sni.encode()
    sni_ext = struct.pack(">HH", 0, len(sni_bytes) + 5)
    sni_ext += struct.pack(">H", len(sni_bytes) + 3)
    sni_ext += struct.pack(">BH", 0, len(sni_bytes))
    sni_ext += sni_bytes
    extensions = sni_ext

    random_bytes = b"\x00" * 32
    session_id = b"\x00"
    cipher_suites = struct.pack(">HH", 2, 0x1301)
    compression = struct.pack(">BB", 1, 0)

    hello = b"\x03\x03" + random_bytes + session_id + cipher_suites + compression
    hello += struct.pack(">H", len(extensions)) + extensions

    handshake = struct.pack(">B", 1) + struct.pack(">I", len(hello))[1:] + hello
    record = struct.pack(">BHH", 0x16, 0x0301, len(handshake)) + handshake
    return record


def tcp_handshake_and_data(src_ip, dst_ip, sport, dport, payload):
    """Return a list of frames: SYN, SYN-ACK, ACK, DATA (PSH+ACK)."""
    syn = eth_ipv4_tcp(src_ip, dst_ip, sport, dport, b"", seq=1000, ack=0, flags=0x02)
    synack = eth_ipv4_tcp(dst_ip, src_ip, dport, sport, b"", seq=2000, ack=1001, flags=0x12)
    ack = eth_ipv4_tcp(src_ip, dst_ip, sport, dport, b"", seq=1001, ack=2001, flags=0x10)
    data = eth_ipv4_tcp(src_ip, dst_ip, sport, dport, payload, seq=1001, ack=2001, flags=0x18)
    return [syn, synack, ack, data]


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(pcap_header())
        for i, frame in enumerate(frames):
            f.write(pcap_record(frame, ts_sec=1730000000 + i))


# Attack PCAPs
dns_attack = eth_ipv4_udp("10.0.0.1", "8.8.8.8", 12345, 53, dns_query("archivetj.com"))
write_pcap(os.path.join(PCAP_DIR, "attack-dns-archivetj.pcap"), [dns_attack])

tls_attack_frames = tcp_handshake_and_data("10.0.0.1", "93.184.216.34", 49000, 443, tls_client_hello("archivetj.com"))
write_pcap(os.path.join(PCAP_DIR, "attack-tls-archivetj.pcap"), tls_attack_frames)

# Benign PCAPs
dns_benign = eth_ipv4_udp("10.0.0.1", "8.8.8.8", 12345, 53, dns_query("example.com"))
write_pcap(os.path.join(PCAP_DIR, "benign-dns-example.pcap"), [dns_benign])

tls_benign_frames = tcp_handshake_and_data("10.0.0.1", "93.184.216.34", 49000, 443, tls_client_hello("example.com"))
write_pcap(os.path.join(PCAP_DIR, "benign-tls-example.pcap"), tls_benign_frames)

print("Generated 4 PCAPs in", PCAP_DIR)
