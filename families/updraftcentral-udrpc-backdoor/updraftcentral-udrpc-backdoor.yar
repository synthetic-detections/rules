/*
   UpdraftCentral UDRPC backdoor campaign, 2026-10-17
   ---------------------------------------------------
   TeamUpdraft's teamupdraft.com was breached over October 17-18, 2026.
   Attackers exfiltrated UpdraftCentral connection keys from the customer
   database and used them to send signed UDRPC commands (plugin.upload_plugin)
   to connected WordPress sites, installing malicious plugins that provide
   webshell or auth-cookie backdoor access.

   Two distinct payloads were observed:
   - Variant A (OffSeq, CVE-2026-10795 wave): compact webshell with
     "postpass2" reachability marker, "admin888" password gate, XOR-encoded
     file upload ("myXorSecret"), and system() command execution. Plugin
     paths follow wp_<7 lowercase>/wp_<7 lowercase>.php.
   - Variant B (October key-compromise wave): auth-cookie backdoor that
     calls wp_set_auth_cookie() after hash_equals() validates a query-string
     token, and hides its created account via pre_user_query / pre_count_users
     hooks. Can authenticate as the first existing administrator without
     creating a new account.

   Rule 1 — Behavioural: operational shape of either webshell variant.
   Rule 2 — IOC: campaign-specific metadata, plugin descriptions, user-agent
            strings, and UDRPC command artifacts.
   Rule 3 — Specimen pin: SHA-256 hashes for all known samples plus a
            size-band heuristic for the small OffSeq webshell.

   Sources:
     https://www.wordfence.com/blog/2026/10/updraftcentral-connection-key-compromise/
     https://offseq.com/en/research/the-backdoor-inside-the-backup-request/
     https://teamupdraft.com/blog/security-incident-october-2026/
     https://github.com/izxci/CVE-2026-10795
*/

import "hash"

rule UpdraftCentral_UDRPC_Webshell : backdoor webshell wordpress
{
    meta:
        description = "UpdraftCentral UDRPC backdoor — behavioural detection of both webshell variants (OffSeq compact webshell and October auth-cookie backdoor)"
        author      = "synthetic-detections"
        date        = "2026-10-20"
        severity    = "critical"
        family      = "updraftcentral-udrpc-backdoor"
        reference   = "https://www.wordfence.com/blog/2026/10/updraftcentral-connection-key-compromise/"
    strings:
        // Variant A — OffSeq compact webshell
        $va_marker    = "postpass2"
        $va_passwd    = "admin888"
        $va_xor       = "myXorSecret"
        $va_exec      = "system(" nocase
        $va_upload    = "b64data"
        // Variant B — auth-cookie backdoor
        $vb_setcook   = "wp_set_auth_cookie" nocase
        $vb_hasheq    = "hash_equals" nocase
        $vb_hideuser  = "pre_user_query" nocase
        $vb_hidecount = "pre_count_users" nocase
    condition:
        // Variant A: reachability marker + password gate + at least one
        // of the operational strings (XOR key, exec, or upload param)
        // Variant B: auth-cookie set after hash validation, with user-
        // hiding hooks (both query and count hooks required together)
        (
            ($va_marker and $va_passwd and any of ($va_xor, $va_exec, $va_upload)) or
            ($vb_setcook and $vb_hasheq and $vb_hideuser and $vb_hidecount)
        )
        and filesize < 100KB
}

rule UpdraftCentral_UDRPC_IOC : backdoor ioc wordpress
{
    meta:
        description = "UpdraftCentral UDRPC campaign IOCs — plugin metadata, user-agent, description strings, UDRPC command artifacts"
        author      = "synthetic-detections"
        date        = "2026-10-20"
        severity    = "high"
        family      = "updraftcentral-udrpc-backdoor"
        reference   = "https://www.wordfence.com/blog/2026/10/updraftcentral-connection-key-compromise/"
    strings:
        // Globally unique campaign indicator — fires standalone
        $desc       = "Small maintenance toolkit: keeps option storage tidy." nocase
        // Corroborating tokens — require cluster
        $ua_udrpc   = "WordPress/6.4; class-udrpc.php"
        $ajax_cb    = "updraft_central_ajaxcallback"
        $cmd_upload = "plugin.upload_plugin"
        $cmd_enum   = "plugin.load_plugins"
        $user_disp  = "Site Tools"
        $user_1     = "data-ops43"
        $user_2     = "media-staff96"
        $user_3     = "site_editor784"
        $user_4     = "site.crew51"
        $user_5     = "web_desk9"
    condition:
        (
            $desc or
            ($ua_udrpc and ($ajax_cb or $cmd_upload or $cmd_enum)) or
            ($ajax_cb and $cmd_upload) or
            ($user_disp and any of ($user_1, $user_2, $user_3, $user_4, $user_5)) or
            2 of ($user_1, $user_2, $user_3, $user_4, $user_5)
        )
        and filesize < 10MB
}

rule UpdraftCentral_UDRPC_Specimen : backdoor specimen wordpress
{
    meta:
        description = "UpdraftCentral UDRPC specimen pin — SHA-256 hashes for known malicious plugins plus size-band heuristic for the compact OffSeq webshell"
        author      = "synthetic-detections"
        date        = "2026-10-20"
        severity    = "critical"
        family      = "updraftcentral-udrpc-backdoor"
        reference   = "https://offseq.com/en/research/the-backdoor-inside-the-backup-request/"
    strings:
        $marker = "postpass2"
        $exec   = "system(" nocase
    condition:
        // Exact SHA-256 pins — zero FP
        // October campaign (Wordfence PSA)
        // CVE-2026-10795 campaign (OffSeq)
        // Heuristic fallback for the ~3,686-byte OffSeq webshell family:
        // reachability marker + command execution in a small PHP file
        hash.sha256(0, filesize) == "54ca7b2da87852a5d1fd7bde644027f84557db4d45fbb25cb2d135a3497d8d5c" or hash.sha256(0, filesize) == "2cdf3f2a3f10f0e12f00f2267907d44796107ab4aececdac520bba13e012b47a" or hash.sha256(0, filesize) == "1821a58e2a851acd1a608a77ce2f77817a0b7b6ef344b9889c8f8728e62969ec" or hash.sha256(0, filesize) == "43dc88fd18501be3dbd6d7f1755e77386d081dd41cef82bc514d39991ae69c49" or hash.sha256(0, filesize) == "0290c2baa363eac72ef2b6891bef1c9c8b4774d5b95d14f4871bde6094fdacde" or hash.sha256(0, filesize) == "99a7fb44d1502938a40b3f663f4e5771b5cf741bcbaec58d7dda0b5066b5a0a5" or hash.sha256(0, filesize) == "ac87d574d74c854d1be68274a7915cfa5a3a6750ca3e89cec2ea02301d66cabe" or hash.sha256(0, filesize) == "8e8d88878379f0a6c640c99f48b0edf064761a6b79bb14aba553996aa143a59f" or hash.sha256(0, filesize) == "3b321d1d5568f32b0049682e935a4f6807096985e4aa857ec65cdde5fcf243a4" or ($marker and $exec and filesize >= 0xbb8 and filesize <= 0x1388)
}
