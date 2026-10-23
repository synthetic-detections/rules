#!/usr/bin/env python3 -I
"""Generate synthetic specimens and benign files for Stadia RAT YARA rules."""
import os, struct

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, "specimens")
BEN = os.path.join(HERE, "benign")

def write(path, data):
    with open(path, "wb") as f:
        f.write(data)

def make_pe32_stub(body_extra=b"", num_imports=1):
    """Minimal PE32 stub with configurable import count."""
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)  # e_lfanew

    pe_sig = b"PE\x00\x00"

    coff = bytearray(20)
    struct.pack_into("<H", coff, 0, 0x14C)   # Machine: i386
    struct.pack_into("<H", coff, 2, 1)        # NumberOfSections
    struct.pack_into("<H", coff, 16, 0xE0)    # SizeOfOptionalHeader

    opt = bytearray(0xE0)
    struct.pack_into("<H", opt, 0, 0x10B)     # PE32 magic
    struct.pack_into("<I", opt, 56, 0x1000)   # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)    # SizeOfHeaders
    struct.pack_into("<I", opt, 92, 16)       # NumberOfRvaAndSizes

    # Import directory RVA (fake, points into body)
    struct.pack_into("<I", opt, 104, 0x200)   # import RVA
    struct.pack_into("<I", opt, 108, 40 * num_imports)

    sec = bytearray(40)
    sec[0:8] = b".text\x00\x00\x00"
    body_size = 0x1000 + len(body_extra)
    struct.pack_into("<I", sec, 8, body_size)   # VirtualSize
    struct.pack_into("<I", sec, 12, 0x1000)     # VirtualAddress
    struct.pack_into("<I", sec, 16, body_size)  # SizeOfRawData
    struct.pack_into("<I", sec, 20, 0x200)      # PointerToRawData

    headers = bytes(dos) + pe_sig + bytes(coff) + bytes(opt) + bytes(sec)
    padding = b"\x00" * (0x200 - len(headers))

    body = b"\x00" * 0x100 + body_extra + b"\x00" * (0x1000 - len(body_extra) - 0x100)
    return headers + padding + body

# --- Specimen 1: Strings rule (build marker + HVNC + RC4 key + protocol + locales) ---
strings_body = b"STADIA_BETA\x00StadiaVnc%d\x00"
strings_body += b"eepkTOgSwdNCgrhITR\x00"
strings_body += b"set_online\x00host_token\x00"
strings_body += struct.pack("<I", 0x0419)
strings_body += struct.pack("<I", 0x0422)
strings_body += struct.pack("<I", 0x0423)
strings_body += struct.pack("<I", 0x043F)
strings_body += struct.pack("<I", 0x0443)
strings_body += b"Remote Desktop\x00Remote CMD\x00"
strings_body += b"File Explorer\x00Process Manager\x00"
# Pad to ~560KB to match real sample size band
strings_body += b"\x00" * (560000 - len(strings_body))
pe_specimen1 = make_pe32_stub(strings_body, num_imports=1)
write(os.path.join(SPEC, "specimen-strings.exe"), pe_specimen1)

# --- Specimen 2: IOC rule ---
ioc_body = b"\x00" * 64
ioc_body += b"93.152.213.215\x00"
ioc_body += b"91.92.43.45\x00"
ioc_body += b"193.148.56.97\x00"
ioc_body += b"stadiadev.cc\x00"
ioc_body += b"plymouth\x00"
ioc_body += b"Add-MpPreference -ExclusionPath\x00"
ioc_body += b"\x00" * (2048 - len(ioc_body))
write(os.path.join(SPEC, "specimen-iocs.bin"), ioc_body)

# --- Specimen 3: Structural rule (PE32 + single import + stadia string + task XML) ---
struct_body = b"STADIA_BETA\x00StadiaVnc%d\x00"
struct_body += b"eepkTOgSwdNCgrhITR\x00"
struct_body += b"<Interval>PT15M</Interval>\x00"
struct_body += b"<Duration>P3650D</Duration>\x00"
struct_body += b"<Hidden>true</Hidden>\x00"
struct_body += b"\x00" * (560000 - len(struct_body))
pe_specimen3 = make_pe32_stub(struct_body, num_imports=1)
write(os.path.join(SPEC, "specimen-structural.exe"), pe_specimen3)

# --- Benign 1: PE32 with multiple imports (not single-KERNEL32) ---
benign_body = b"RuntimeBroker.exe\x00set_online\x00"
benign_body += b"\x00" * (4096 - len(benign_body))
pe_benign1 = make_pe32_stub(benign_body, num_imports=3)
write(os.path.join(BEN, "benign-multi-import.exe"), pe_benign1)

# --- Benign 2: random data ---
import random
random.seed(99)
write(os.path.join(BEN, "benign-random.bin"), bytes(random.getrandbits(8) for _ in range(4096)))

print("Generated 3 specimens + 2 benign files")
