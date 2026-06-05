"""
Shared scapy helper for synthesising TCP+HTTP/1.1 PCAPs.
Used by each family's pcap-gen.py — keeps the per-family generator small.
"""
from scapy.all import IP, TCP, Raw, wrpcap


def build_pcap(
    out_path: str,
    client_pushes: list[bytes],
    server_pushes: list[bytes] | None = None,
    client_ip: str = "10.99.0.10",
    server_ip: str = "10.99.0.20",
    client_port: int = 51234,
    server_port: int = 80,
) -> None:
    """
    Render a TCP flow:
      SYN, SYN-ACK, ACK, then alternating client/server PUSH/ACK packets.
      Server bytes (if any) follow each client push.
    """
    server_pushes = server_pushes or [b"" for _ in client_pushes]
    if len(server_pushes) < len(client_pushes):
        server_pushes = list(server_pushes) + [b""] * (len(client_pushes) - len(server_pushes))

    seq_c, seq_s = 1000, 2000
    pkts = [
        IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="S", seq=seq_c),
        IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, flags="SA",
              seq=seq_s, ack=seq_c + 1),
        IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="A",
              seq=seq_c + 1, ack=seq_s + 1),
    ]
    seq_c += 1
    seq_s += 1
    for cbuf, sbuf in zip(client_pushes, server_pushes):
        if cbuf:
            pkts.append(
                IP(src=client_ip, dst=server_ip)
                / TCP(sport=client_port, dport=server_port,
                      flags="PA", seq=seq_c, ack=seq_s) / Raw(cbuf)
            )
            seq_c += len(cbuf)
            pkts.append(
                IP(src=server_ip, dst=client_ip)
                / TCP(sport=server_port, dport=client_port,
                      flags="A", seq=seq_s, ack=seq_c)
            )
        if sbuf:
            pkts.append(
                IP(src=server_ip, dst=client_ip)
                / TCP(sport=server_port, dport=client_port,
                      flags="PA", seq=seq_s, ack=seq_c) / Raw(sbuf)
            )
            seq_s += len(sbuf)
            pkts.append(
                IP(src=client_ip, dst=server_ip)
                / TCP(sport=client_port, dport=server_port,
                      flags="A", seq=seq_c, ack=seq_s)
            )
    wrpcap(out_path, pkts)
