#!/usr/bin/env python3 -I
"""Generate synthetic specimens and benign files for MythicRatatoskr YARA rules."""
import os, struct

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, "specimens")
BEN = os.path.join(HERE, "benign")

def write(path, data):
    with open(path, "wb") as f:
        f.write(data)

# --- Specimen 1: Agent rule (function names + PSK) ---
agent_body = b"\x00" * 256
agent_body += b"CheckInAgent\x00saveConfig\x00agent_run\x00init_agent\x00"
agent_body += b"getTasks\x00doTask\x00connectForSocks\x00runService\x00"
agent_body += b"US3pM9KFxrZBSgc1pGl2wO4Kir1XjZP5Z9kBXBMYd2s=\x00"
agent_body += b"d71f1722-cf0b-4e27-9f8e-c95ec9b24a23\x00"
agent_body += b"chtime\x00expose\x00nodeinfo\x00churl\x00"
agent_body += b"Accepting stream\x00Passing off to socks5\x00"
agent_body += b"200::\x00"
agent_body += b"\x00" * (4096 - len(agent_body))
write(os.path.join(SPEC, "specimen-agent.bin"), agent_body)

# --- Specimen 2: IOC rule ---
ioc_body = b"\x00" * 128
ioc_body += b"201:b479:2771:8df4:b5eb:d007:63b0\x00"
ioc_body += b"\\Windows\\Temp\\.updatecache\x00"
ioc_body += b"\\system32\\.updatecache\x00"
ioc_body += b"/Temp/.crond\x00"
ioc_body += b"/tmp/.test_config\x00"
ioc_body += b"krbtman.exe\x00windowsdefendersvc.exe\x00"
ioc_body += b"OneDriveLiveUpdater.exe\x00"
ioc_body += b"uztickets.com\x00egyptanimals.com\x00"
ioc_body += b"pdfopentask\x00"
ioc_body += b"\x00" * (2048 - len(ioc_body))
write(os.path.join(SPEC, "specimen-iocs.bin"), ioc_body)

# --- Specimen 3: SOCKS5 rule ---
socks_body = b"\x00" * 128
socks_body += b"bindProxy\x00"
socks_body += b"127.0.0.1:33690\x00"
socks_body += b"Accepting stream\x00"
socks_body += b"Passing off to socks5\x00"
socks_body += b"200::\x00"
socks_body += b"runService\x00"
socks_body += b"connectForSocks\x00"
socks_body += b"\x00" * (4096 - len(socks_body))
write(os.path.join(SPEC, "specimen-socks5.bin"), socks_body)

# --- Benign 1: Go binary with some common function names but no Mythic/Yggdrasil ---
benign1 = b"\x00" * 256
benign1 += b"runService\x00saveConfig\x00"  # generic Go names
benign1 += b"main.main\x00runtime.goexit\x00"
benign1 += b"\x00" * (4096 - len(benign1))
write(os.path.join(BEN, "benign-go-service.bin"), benign1)

# --- Benign 2: random data ---
import random
random.seed(42)
write(os.path.join(BEN, "benign-random.bin"), bytes(random.getrandbits(8) for _ in range(4096)))

print("Generated 3 specimens + 2 benign files")
