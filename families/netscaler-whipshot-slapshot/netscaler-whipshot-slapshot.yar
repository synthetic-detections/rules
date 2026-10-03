/*
   NetScaler WHIPSHOT / SLAPSHOT — post-exploitation implants on Citrix
   NetScaler ADC/Gateway after CVE-2026-88771 / CVE-2026-88772 (2026-09).
   -------------------------------------------------------------------------
   Two unauthenticated NetScaler RCE zero-days (CVE-2026-88771 unauth RCE all
   ADC/Gateway; CVE-2026-88772 memory-overflow/auth-bypass over DTLS UDP:443)
   went to mass exploitation on 2026-09-29 after a public root-cause + PoC.
   Google/Mandiant track the implants as WHIPSHOT (PHP web shell driven by
   HTTP_X_UX request headers, chunked Base64 transport) and SLAPSHOT (Python
   SOCKS tunneler; IPC to WHIPSHOT via /tmp/.uxdport + /tmp/.uxdlock). Actors
   abuse httpd.conf to register .deb/.sig/.ico as PHP handlers and run
   `chmod u+s /bin/sh`. GreyNoise observed a web shell staged at
   /var/netscaler/logon/LogonPoint/custom/.ctxs.receiver aliased receiver.min.css.

   Siblings: [[interlock]] (unrelated appliance-edge campaign)

   Sources:
     https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation
     https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances
     https://www.helpnetsecurity.com/2026/09/29/netscaler-zero-day-exploitation-escalates-into-mass-attacks-cve-2026-88771/
*/

import "hash"

rule NetScaler_WHIPSHOT_SLAPSHOT_Behavior {
  meta:
    description = "WHIPSHOT/SLAPSHOT NetScaler implants — shared IPC + web-shell/tunneler behaviour (HTTP_X_UX header dispatch, /tmp/.uxdport IPC, SLAPSHOT command verbs)"
    author = "synthetic-detections"
    date = "2026-09-30"
    severity = "critical"
    family = "netscaler-whipshot-slapshot"
    reference = "https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances"
  strings:
    $w_hdr1 = "HTTP_X_UX"
    $w_hdr2 = "HTTP_X_UX_"
    $w_sock = "fsockopen"
    $s_env = "UXD_IDLE_EXIT"
    $ipc1 = "/tmp/.uxdport"
    $ipc2 = "/tmp/.uxdlock"
    $v_open = "\"open\""
    $v_conn = "\"conn\""
    $v_push = "\"push\""
    $v_pull = "\"pull\""
    $v_exch = "\"exch\""
    $v_ping = "\"ping\""
  condition:
    (($w_hdr1 or $w_hdr2) and any of ($ipc1, $ipc2) and $w_sock or $s_env and any of ($ipc1, $ipc2) and 3 of ($v_*)) and filesize < 80KB
}

rule NetScaler_WebShell_httpd_Handler_Abuse {
  meta:
    description = "NetScaler post-exploit persistence — httpd.conf abuse registering .deb/.sig/.ico as PHP handlers + web-shell staging paths"
    author = "synthetic-detections"
    date = "2026-09-30"
    severity = "high"
    family = "netscaler-whipshot-slapshot"
    reference = "https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation"
  strings:
    $h_php = "application/x-httpd-php"
    $h_deb = "AddHandler application/x-httpd-php .deb"
    $h_sig = "AddHandler application/x-httpd-php .sig"
    $h_alias = "AliasMatch"
    $p_ns = "/var/netscaler/gui/vpn/scripts/linux/"
    $p_ctxs = ".ctxs.receiver"
    $p_recv = /receiver\.min\.[0-9a-f]*\.?css/
    $p_ico = /\.ico\$ \/var\/netscaler\/gui\/vpn\/scripts\/linux\/\$1\.sig/
    $suid = "chmod u+s /bin/sh"
  condition:
    (($h_deb or $h_sig) and ($h_alias or $h_php) or $h_php and any of ($p_ns, $p_ctxs, $p_ico) or $p_ctxs and $p_recv or $suid) and filesize < 64KB
}

rule NetScaler_WHIPSHOT_WebShell_SpecimenPin {
  meta:
    description = "NetScaler WHIPSHOT web shell — pinned SHA-256 of the GreyNoise-observed .ctxs.receiver/receiver.min.css sample"
    author = "synthetic-detections"
    date = "2026-09-30"
    severity = "critical"
    family = "netscaler-whipshot-slapshot"
    reference = "https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation"
    sha256 = "6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7"
  condition:
    hash.sha256(0, filesize) == "6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7"
}
