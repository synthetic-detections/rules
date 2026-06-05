#!/usr/bin/env python3
"""
Fabricate a minimal-shape ELF64 binary in the IronWorm dropper size band
with a UPX! signature embedded. NOT executable — header bytes are
structurally valid but the program is just padding. Only the YARA rule's
condition logic is being validated.
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools-setup.elf")

# ELF64 header (64 bytes): magic, class=64, data=2 (LSB), version=1,
# osabi=0, abiversion=0, padding * 7, e_type=ET_EXEC(2), e_machine=AMD64(0x3e),
# rest = zeros (synthetic — not loadable, but YARA only inspects bytes).
header = (
    b"\x7fELF"            # EI_MAG
    + b"\x02"              # EI_CLASS = ELFCLASS64
    + b"\x01"              # EI_DATA = ELFDATA2LSB
    + b"\x01"              # EI_VERSION
    + b"\x00"              # EI_OSABI
    + b"\x00"              # EI_ABIVERSION
    + b"\x00" * 7          # EI_PAD
    + b"\x02\x00"          # e_type = ET_EXEC
    + b"\x3e\x00"          # e_machine = EM_X86_64
    + b"\x01\x00\x00\x00"  # e_version
    + b"\x00" * 40         # placeholder for entry/phoff/shoff/etc.
)

# Embed UPX! signature + the C2 endpoint string the rule also accepts.
upx_block = (
    b"UPX!"                # rule anchor 1
    + b"\x00\x00\x00\x00"
    + b"/api/agent\x00"    # rule anchor 2
)

# Pad to ~900 KiB so we land squarely in the 700-1500 KiB size band.
target_size = 900 * 1024
pad = b"\x00" * (target_size - len(header) - len(upx_block))
blob = header + upx_block + pad

with open(OUT, "wb") as fh:
    fh.write(blob)
print(f"wrote {OUT} ({len(blob)} bytes)")
