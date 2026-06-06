#!/usr/bin/env python3
"""
Benign baseline ELF64 specimen: same header shape as the Moonlight Maze
specimens, but with strings that mimic a normal SSH/networking utility.
Stresses the YARA rule's anchor specificity — a generic ELF with no
LOKI2 / Penquin tells must not match any rule.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "normal-sshd.elf")

header = (
    b"\x7fELF\x02\x01\x01\x00"
    + b"\x00" * 8
    + b"\x02\x00"          # ET_EXEC
    + b"\x3e\x00"          # EM_X86_64
    + b"\x01\x00\x00\x00"
    + b"\x00" * 40
)

# Generic networking-daemon strings — none are LOKI2 / Penquin anchors.
strings = b"\n".join([
    b"\x00",
    b"OpenSSH_9.6p1\x00",
    b"/var/run/sshd.pid\x00",
    b"connect to host %s port %d: %s\x00",
    b"received signal %d\x00",
    b"banner timeout\x00",
    b"successful login for user %s from %s\x00",
])

blob = header + strings + b"\x00" * (64 * 1024 - len(header) - len(strings))
with open(OUT, "wb") as f:
    f.write(blob)
print("wrote", OUT, len(blob), "bytes")
