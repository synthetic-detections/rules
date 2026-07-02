#!/usr/bin/env python3
"""Hard-negative: a benign native app whose embedded strings coincidentally
contain substrings of GentleKiller kill-list/IOC atoms. Exercises the
substring-inflation hazard (avp<-avpui, Traps<-bootstraps, egui<-beguile,
MB2<-SMB2). A precise rule must NOT fire on this."""
import struct
blob = bytearray()
blob += b'MZ' + b'\x90' * 6            # DOS header start
blob += struct.pack('<I', 0)
# realistic benign strings: a Rust GUI app talking SMB, with generic prose
words = [
    b"This crate uses the egui immediate-mode GUI and beguiling animations.",
    b"Negotiating SMB2 and SMB2_002 dialects over the wire.",
    b"Bootstraps the runtime; straps and buckles module init.",
    b"avpui-like theming is unrelated to any antivirus product.",
    b"DeviceIoControl is a standard Win32 API used for device access.",
    b"components: egui_extras, egui_plot, beguile-macros, bootstraps-rs",
    b"protocol handlers: SMB2, RDP, and generic transport straps.",
]
# pad to well over 20KB with benign filler
body = b"\n".join(words) + b"\n"
body += b"// benign padding: " + b"lorem ipsum dolor sit amet " * 1200
blob += body
with open("benign/benign_rustapp_smb.bin", "wb") as f:
    f.write(bytes(blob))
print("wrote", len(blob), "bytes")
