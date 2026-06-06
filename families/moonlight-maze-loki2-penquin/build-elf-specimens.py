#!/usr/bin/env python3
"""
Fabricate minimal ELF64 specimens for the moonlight-maze-loki2-penquin
family. None of these files are executable; the header is structurally
valid but the program area is just embedded strings + padding so the
YARA conditions fire as intended.

Specimens covered:
  - loki2-strings.elf            -> rule MoonlightMaze_LOKI2
  - penquin-x64-strings.elf      -> rule Penquin_Turla_LinuxBackdoor
  - penquin-2014era.elf          -> rule Penquin_Turla_2014Era
  - penquin-magic-packet.elf     -> rule Penquin_Turla_MagicPacket
  - penquin-opcode.elf           -> rule Penquin_Turla_Opcode_Leonardo
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, "specimens")
os.makedirs(SPEC, exist_ok=True)


def elf64_header():
    return (
        b"\x7fELF"
        + b"\x02\x01\x01\x00"
        + b"\x00" * 8
        + b"\x02\x00"          # ET_EXEC
        + b"\x3e\x00"          # EM_X86_64
        + b"\x01\x00\x00\x00"
        + b"\x00" * 40
    )


def write_specimen(name: str, blob: bytes, target_size: int) -> None:
    path = os.path.join(SPEC, name)
    pad = b"\x00" * max(0, target_size - len(blob))
    with open(path, "wb") as f:
        f.write(blob + pad)
    print(f"wrote {path} ({len(blob) + len(pad)} bytes)")


# --- LOKI2 strings -----------------------------------------------------------
loki = elf64_header() + b"\n".join([
    b"\x00",
    b"lokid: inactive client <%d> expired from list [%d]\x00",
    b"[SUPER fatal] control should NEVER fall here\x00",
    b"lokid: Client database full\x00",
    b"loki: submiting our public key to server\x00",
    b"[fatal] Diffie-Hellman key generation failure\x00",
    b"lokid: client <%d> requested an all kill\x00",
    b"L_TAG 0xf001 packet identification marker\x00",
])
write_specimen("loki2-strings.elf", loki, 8 * 1024)

# --- Penquin_x64 (Leonardo strings) ------------------------------------------
penquin_x64 = elf64_header() + b"\n".join([
    b"\x00",
    b"/root/.hsperfdata\x00",
    b"Desc| Filename | size |state|\x00",
    b"VS filesystem: %s\x00",
    b"File already exist on remote filesystem !\x00",
    b"/tmp/.sync.pid\x00",
    b"rem_fd: ssl \x00",
    b"TREX_PID=%u\x00",
    b"/tmp/.xdfg\x00",
    b"__we_are_happy__\x00",
    b"/root/.sess\x00",
])
write_specimen("penquin-x64-strings.elf", penquin_x64, 96 * 1024)

# --- 2014-era Penquin (C2 + glibc/openssl/libpcap + sh wrapper) --------------
penquin_2014 = elf64_header() + b"\n".join([
    b"\x00",
    b"news-bbc.podzone.org\x00",
    b"80.248.65.183\x00",
    b"glibc2.3.2\x00",
    b"OpenSSL 0.9.6\x00",
    b"libpcap\x00",
    b"/bin/sh -c \x00",
])
write_specimen("penquin-2014era.elf", penquin_2014, 64 * 1024)

# --- Penquin magic-packet anchors (BPF filters + 0xbdbd0560 mask) ------------
magic = elf64_header() + b"\n".join([
    b"\x00",
    b"tcp[8:4] & 0xe007ffff = 0xe003bebe\x00",
    b"tcp[8:4] & 0xe007ffff = 0x1bebe\x00",
    b"udp[12:4] & 0xe007ffff\x00",
    b"0xbdbd0560\x00",
    b"pcap_setfilter\x00",
    b"pcap_open_live\x00",
    b"eth0\x00",
])
# Also embed the 4-byte mask in both endians so $mask_2020_le / _be fire
magic += b"\x60\x05\xBD\xBD"
magic += b"\xBD\xBD\x05\x60"
write_specimen("penquin-magic-packet.elf", magic, 48 * 1024)

# --- Penquin opcode (Leonardo) - embed 2+ of the verbatim hex sequences ------
opcode_bytes = bytes.fromhex(
    "8D4105320648FFC68881E0806900"               # $op0
    "00000000"
    "48FFC14883F94975E9"                          # $op1
    "00000000"
    "C7059B7D29001D000000C7052D7B290065746830C6052A7B290000E8"  # $op2
)
opc = elf64_header() + b"\x00" * 64 + opcode_bytes
write_specimen("penquin-opcode.elf", opc, 64 * 1024)

print("done.")
