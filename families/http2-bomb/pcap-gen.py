#!/usr/bin/env python3
"""
Synthetic h2c PCAP generator for HTTP/2 Bomb smoke testing.

Produces two PCAPs against the same IP/port pair:
  - benign-h2c.pcap : preface + SETTINGS_INITIAL_WINDOW_SIZE=65535 + a GET.
  - bomb-h2c.pcap   : preface + SETTINGS_INITIAL_WINDOW_SIZE=0 + a GET + N
                      consecutive WINDOW_UPDATE frames carrying increment=1
                      (the stall + drip primitives of Quang Luong / Codex's
                      HTTP/2 Bomb; CVE-2026-49975 for Apache httpd).

This is plain h2c (cleartext HTTP/2); a real-world Bomb would run over
TLS-encrypted h2 and require either decryption at the proxy or signatures
on the TLS-server side. h2c is fine for smoke-testing byte-content rules.
"""
from scapy.all import IP, TCP, Raw, wrpcap

CLIENT_IP = "10.99.0.10"
SERVER_IP = "10.99.0.20"
CLIENT_PORT = 51234
SERVER_PORT = 80

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"  # 24 bytes


def settings_initial_window(window: int) -> bytes:
    """SETTINGS frame carrying a single entry: INITIAL_WINDOW_SIZE (id=4) = window."""
    payload = b"\x00\x04" + window.to_bytes(4, "big")            # id=4, value=window
    length = len(payload).to_bytes(3, "big")                     # 6
    return length + b"\x04" + b"\x00" + b"\x00\x00\x00\x00" + payload


def window_update(increment: int, stream_id: int = 0) -> bytes:
    """WINDOW_UPDATE frame: type=8, payload = 4-byte window-size-increment."""
    payload = increment.to_bytes(4, "big")
    length = len(payload).to_bytes(3, "big")                     # 4
    return length + b"\x08" + b"\x00" + stream_id.to_bytes(4, "big") + payload


def headers_get_root(stream_id: int = 1) -> bytes:
    """
    Minimal HEADERS frame for a GET / over HTTP/2.
    HPACK indexed-header entries from the static table:
      \\x82 = :method GET
      \\x84 = :path /
      \\x86 = :scheme http
    flags = END_STREAM(0x01) | END_HEADERS(0x04) = 0x05
    """
    hpack = b"\x82\x84\x86"
    length = len(hpack).to_bytes(3, "big")
    return length + b"\x01" + b"\x05" + stream_id.to_bytes(4, "big") + hpack


def build_pcap(client_pushes: list[bytes], out_path: str) -> None:
    """
    Render a TCP+IP flow:
      SYN, SYN-ACK, ACK, then one PUSH/ACK per client_pushes entry with a
      matching server ACK between each. Server side stays silent at L7 —
      the rules we're testing only care about the client→server direction.
    """
    seq_c, seq_s = 1000, 2000
    pkts = [
        IP(src=CLIENT_IP, dst=SERVER_IP)
          / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=seq_c),
        IP(src=SERVER_IP, dst=CLIENT_IP)
          / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="SA",
                seq=seq_s, ack=seq_c + 1),
        IP(src=CLIENT_IP, dst=SERVER_IP)
          / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A",
                seq=seq_c + 1, ack=seq_s + 1),
    ]
    seq_c += 1
    seq_s += 1
    for buf in client_pushes:
        pkts.append(
            IP(src=CLIENT_IP, dst=SERVER_IP)
              / TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA",
                    seq=seq_c, ack=seq_s) / Raw(buf)
        )
        seq_c += len(buf)
        pkts.append(
            IP(src=SERVER_IP, dst=CLIENT_IP)
              / TCP(sport=SERVER_PORT, dport=CLIENT_PORT, flags="A",
                    seq=seq_s, ack=seq_c)
        )
    wrpcap(out_path, pkts)


def main() -> None:
    here = "<host>/repos/another repo/families/http2-bomb/pcaps"

    # Benign: real-shape h2c GET, healthy 64 KiB receive window.
    benign_initial = PREFACE + settings_initial_window(65535) + headers_get_root(1)
    build_pcap([benign_initial], f"{here}/benign-h2c.pcap")

    # Malicious: stall (window=0) + GET + 10 separate packets each carrying
    # one WINDOW_UPDATE increment=1 frame (the drip).
    bomb_initial = PREFACE + settings_initial_window(0) + headers_get_root(1)
    drip_pushes = [window_update(1) for _ in range(10)]
    build_pcap([bomb_initial, *drip_pushes], f"{here}/bomb-h2c.pcap")

    print("wrote benign-h2c.pcap and bomb-h2c.pcap")


if __name__ == "__main__":
    main()
