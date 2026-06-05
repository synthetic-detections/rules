#!/usr/bin/env python3
"""
Benign ELF64 baseline: same header shape as the IronWorm specimen but
*not* UPX-packed and *not* in the 700-1500 KiB size band (small CLI tool
shape, ~64 KiB). Exercises both filters in the specimen rule's condition.
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "small-tool.elf")

header = (
    b"\x7fELF"
    + b"\x02\x01\x01\x00"
    + b"\x00" * 8
    + b"\x02\x00"          # ET_EXEC
    + b"\x3e\x00"          # EM_X86_64
    + b"\x01\x00\x00\x00"
    + b"\x00" * 40
)

# 64 KiB padding — well below the 700 KiB lower bound.
pad = b"hello\x00" * (64 * 1024 // 6)
with open(OUT, "wb") as fh:
    fh.write(header + pad)
print(f"wrote {OUT} ({64 + len(pad)//1024} KiB approx)")
