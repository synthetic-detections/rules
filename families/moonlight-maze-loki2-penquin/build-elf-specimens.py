#!/usr/bin/env python3
"""
Fabricate two minimal ELF64 specimens:
  - loki2-strings.elf   : ELF64 header + verbatim LOKI2 Phrack-51 anchor
                          strings embedded for rule MoonlightMaze_LOKI2.
  - penquin-x64-strings.elf : ELF64 header + Penquin_x64 anchor strings
                              (Leonardo 2026-04-24) for Penquin_Turla_LinuxBackdoor.
Neither file is executable; the header is structurally valid but the
program area is just embedded strings + padding so the YARA conditions
fire as intended.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))

def elf64_header():
    return (
        b"\x7fELF"          # EI_MAG
        + b"\x02"            # EI_CLASS = ELFCLASS64
        + b"\x01"            # EI_DATA = ELFDATA2LSB
        + b"\x01"            # EI_VERSION
        + b"\x00"            # EI_OSABI
        + b"\x00"            # EI_ABIVERSION
        + b"\x00" * 7        # padding
        + b"\x02\x00"        # e_type = ET_EXEC
        + b"\x3e\x00"        # e_machine = EM_X86_64
        + b"\x01\x00\x00\x00"
        + b"\x00" * 40       # zeroed entry/phoff/shoff/etc.
    )


# --- specimen 1: LOKI2 -------------------------------------------------------
loki_strings = b"\n".join([
    b"\x00",
    b"lokid: inactive client <%d> expired from list [%d]\x00",
    b"[SUPER fatal] control should NEVER fall here\x00",
    b"lokid: Client database full\x00",
    b"loki: submiting our public key to server\x00",
    b"[fatal] Diffie-Hellman key generation failure\x00",
    b"lokid: client <%d> requested an all kill\x00",
    b"L_TAG 0xf001 packet identification marker\x00",
])
loki_blob = elf64_header() + loki_strings + b"\x00" * (8192 - len(elf64_header()) - len(loki_strings))
with open(os.path.join(HERE, "loki2-strings.elf"), "wb") as f:
    f.write(loki_blob)
print("wrote loki2-strings.elf", len(loki_blob), "bytes")

# --- specimen 2: Penquin Turla ------------------------------------------------
penquin_strings = b"\n".join([
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
# Land in the 50KiB-2MiB Penquin size band (well under the 5MiB cap).
target = 96 * 1024
penquin_blob = elf64_header() + penquin_strings
penquin_blob += b"\x00" * (target - len(penquin_blob))
with open(os.path.join(HERE, "penquin-x64-strings.elf"), "wb") as f:
    f.write(penquin_blob)
print("wrote penquin-x64-strings.elf", len(penquin_blob), "bytes")
