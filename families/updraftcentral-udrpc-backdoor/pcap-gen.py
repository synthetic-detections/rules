#!/usr/bin/env python3
"""
Synthetic HTTP/1.1 PCAPs for UpdraftCentral UDRPC backdoor smoke tests.

attack-udrpc-format1.pcap   : CVE-2026-10795 format=1 legacy RPC exploit
attack-udrpc-stolenkey.pcap : Stolen connection-key command delivery
attack-udrpc-upload.pcap    : plugin.upload_plugin command via UDRPC
attack-webshell-offseq.pcap : OffSeq webshell access with admin888 gate
benign-wp-ajax.pcap         : Normal WordPress admin-ajax.php heartbeat
benign-updraft-backup.pcap  : Legitimate UpdraftPlus backup request
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _lib.h2c_http_helper import build_pcap


def http_post(host: str, path: str, body: str, ua: str = "Mozilla/5.0") -> bytes:
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    ).encode("latin-1")


def http_200_ok() -> bytes:
    body = b"<html><body>OK</body></html>"
    headers = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: text/html\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode("latin-1")
    return headers + body


def main() -> None:
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
    os.makedirs(here, exist_ok=True)
    ok = http_200_ok()

    # --- Attack PCAPs ---

    # CVE-2026-10795: format=1 legacy RPC exploit
    build_pcap(f"{here}/attack-udrpc-format1.pcap", [http_post(
        "victim.example.com",
        "/wp-admin/admin-ajax.php",
        "action=updraft_central_ajaxcallback&format=1"
        "&key_name=site123.central.updraftplus.com"
        "&udrpc_message=eyJjb21tYW5kIjoicGx1Z2luLmxvYWRfcGx1Z2lucyJ9",
        ua="WordPress/6.4; class-udrpc.php",
    )], [ok])

    # Stolen connection-key command delivery (October breach)
    build_pcap(f"{here}/attack-udrpc-stolenkey.pcap", [http_post(
        "victim.example.com",
        "/wp-admin/admin-ajax.php",
        "action=updraft_central_ajaxcallback"
        "&key_name=customer42.central.updraftplus.com"
        "&udrpc_message=eyJjb21tYW5kIjoicGx1Z2luLnVwbG9hZF9wbHVnaW4ifQ",
    )], [ok])

    # plugin.upload_plugin command (malicious plugin push)
    build_pcap(f"{here}/attack-udrpc-upload.pcap", [http_post(
        "victim.example.com",
        "/wp-admin/admin-ajax.php",
        "action=updraft_central_ajaxcallback"
        "&key_name=target99.central.updraftplus.com"
        "&udrpc_message=plugin.upload_plugin"
        "&plugin_data=UEsDBBQAAAAIAA",
    )], [ok])

    # OffSeq webshell access (admin888 gate)
    build_pcap(f"{here}/attack-webshell-offseq.pcap", [http_post(
        "victim.example.com",
        "/wp-content/plugins/wp_cleanup/wp_cleanup.php",
        "postpass2=1&password=admin888&cmd=id",
    )], [ok])

    # --- Benign PCAPs ---

    # Normal WordPress admin-ajax heartbeat
    build_pcap(f"{here}/benign-wp-ajax.pcap", [http_post(
        "example.com",
        "/wp-admin/admin-ajax.php",
        "action=heartbeat&_nonce=abc123&data%5Bwp-refresh-post-lock%5D%5Bpost_id%5D=42",
    )], [ok])

    # Legitimate UpdraftPlus backup request (no udrpc_message)
    build_pcap(f"{here}/benign-updraft-backup.pcap", [http_post(
        "example.com",
        "/wp-admin/admin-ajax.php",
        "action=updraft_backup_now&backupnow_nonce=x9f3a&onlythisfileentity=db",
    )], [ok])

    print("wrote 4 attack + 2 benign PCAPs")


if __name__ == "__main__":
    main()
