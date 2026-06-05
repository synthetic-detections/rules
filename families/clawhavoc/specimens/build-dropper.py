#!/usr/bin/env python3
"""
Fabricate a synthetic Mach-O fat-binary header for the ClawHavoc dropper
specimen. The file is NOT executable — it's a structurally-valid FAT
header followed by padding with the ad-hoc code-signing identifier
embedded so the YARA rule's $sign_id anchor lights up.
"""
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dropper.macho")

# FAT_MAGIC (big-endian universal Mach-O magic) at offset 0
header = b"\xca\xfe\xba\xbe"

# Trailing fat_header fields (nfat_arch, padding) — synthetic, not loadable
header += b"\x00\x00\x00\x02"  # 2 architectures (synthetic; we don't ship arch entries)

# Ad-hoc code-signing identifier observed in real ClawHavoc samples
sign_id = b"\x00jhzhhfomng\x00"

# One of the observed distribution binary names
name = b"x5ki60w1ih838sp7"

# Pad to ~80 KiB to look like a real (small) Mach-O dropper, well under
# the 10 MiB cap and over the xattr-band lower bound used in the rule.
target = 80 * 1024
blob = header + sign_id + name
blob += b"\x00" * (target - len(blob))

with open(OUT, "wb") as fh:
    fh.write(blob)
print(f"wrote {OUT} ({len(blob)} bytes)")
