#!/usr/bin/env python3
"""Synthetic HTTP PCAPs for the ArangoDB exploitation chain."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _lib.h2c_http_helper import build_pcap

def req(method, path, body="", host="db.example.com", ctype="application/json"):
    h=f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.5\r\n"
    if body:
        h+=f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
    h+=f"Connection: close\r\n\r\n{body}"
    return h.encode("latin-1")
def ok(b=b'{"error":false}'):
    return b"HTTP/1.1 200 OK\r\nServer: ArangoDB\r\nContent-Length: %d\r\n\r\n"%len(b)+b

here=os.path.join(os.path.dirname(os.path.abspath(__file__)),"pcaps")
# Stage 1 attack: %5fapi bypass to delete users -> sid 2026091901
build_pcap(f"{here}/attack-stage1-authbypass.pcap",
           [req("PUT","/%5fapi/simple/remove-by-example",'{"collection":"_users","example":{}}')],[ok()])
# Stage 2 attack: system task with isSystem:true -> sid 2026091902
build_pcap(f"{here}/attack-stage2-systemtask.pcap",
           [req("POST","/_api/tasks",'{"name":"x","command":"(function(){})();","isSystem":true}')],[ok()])
# Benign 1: normal _api call, no encoding -> clean
build_pcap(f"{here}/benign-normal-api.pcap",
           [req("GET","/_api/version")],[ok()])
# Benign 2: legit task creation WITHOUT isSystem -> clean
build_pcap(f"{here}/benign-task-nosystem.pcap",
           [req("POST","/_api/tasks",'{"name":"nightly","command":"(function(){})();","period":60}')],[ok()])
print("wrote 4 pcaps")
if __name__=="__main__": pass
