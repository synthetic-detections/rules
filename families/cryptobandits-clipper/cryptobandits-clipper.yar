/*
   CryptoBandits cryptocurrency clipper/stealer + USB worm
   (disclosed 2026-06-17, Microsoft Threat Intelligence)
   -------------------------------------------------------
   Windows-based cryptocurrency clipper active since February 2026.
   Two components: a worm for USB propagation via .lnk shortcut
   replacement, and a clipper/stealer that monitors clipboard at
   ~500ms intervals for BIP39 seed phrases, private keys, and
   wallet addresses (Bitcoin legacy/P2SH/Bech32/Taproot, Tron,
   Monero). Replaces copied wallet addresses with attacker-controlled
   substitutes, preserving prefix characters to avoid visual detection.

   Architecture: obfuscated JavaScript payloads executed via
   wscript.exe/cscript.exe with ActiveXObject-driven execution.
   Initial installer is PyInstaller+PyArmor packaged. Persistence
   via two scheduled tasks (XML-wrapped JS). C2 over Tor hidden
   services through renamed Tor binary (ugate.exe) on localhost:9050.
   EVAL command provides full RCE backdoor capability.

   C2 protocol uses action codes: GUID (beacon), SEED (exfil seed
   phrase), PKEY (exfil private key), REPL (address replacement
   notification), GOOD (legacy). Responses: GUID (ack), EVAL (RCE).

   Anti-analysis: detects Task Manager via WMI Win32_Process query,
   exits if found. Defender AV exclusions set for staging folders.

   Microsoft detection: Trojan:Win32/CryptoBandits.A/.B,
   Trojan:JS/CryptoBandits.A/.B

   Rule 1 — Behavioral: C2 protocol markers, clipboard monitoring
            patterns, Tor proxy configuration, anti-analysis checks.
   Rule 2 — Structural: JavaScript payload structure — staging paths,
            scheduled task patterns, worm propagation markers.
   Rule 3 — IOC: Tor .onion C2 domains, file hashes, C2 endpoints.

   Sources:
     https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/
     https://thehackernews.com/2026/06/microsoft-details-windows-clipper.html
*/

rule CryptoBandits_Clipper_Behavior
{
    meta:
        description = "CryptoBandits clipper — C2 protocol action codes, clipboard crypto monitoring, Tor SOCKS5 proxy, anti-analysis via WMI"
        author      = "synthetic-detections"
        date        = "2026-06-19"
        severity    = "critical"
        family      = "cryptobandits-clipper"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"

    strings:
        // C2 protocol action codes — sent in POST bodies
        $proto_guid  = "GUID" ascii
        $proto_seed  = "SEED" ascii
        $proto_pkey  = "PKEY" ascii
        $proto_repl  = "REPL" ascii
        $proto_good  = "GOOD" ascii
        $proto_eval  = "EVAL" ascii
        $proto_geip  = "GEIP" ascii

        // C2 endpoint paths
        $c2_route    = "/route.php" ascii
        $c2_recvf    = "/recvf.php" ascii
        $c2_stub     = "/stub.php" ascii

        // Tor SOCKS5 proxy configuration
        $tor_socks1  = "socks5-hostname" ascii
        $tor_socks2  = "localhost:9050" ascii
        $tor_socks3  = "127.0.0.1:9050" ascii

        // Renamed Tor binary
        $tor_rename  = "ugate.exe" ascii nocase

        // Anti-analysis — Task Manager detection via WMI
        $anti_wmi    = "Win32_Process" ascii
        $anti_taskmg = "taskmgr" ascii nocase

        // Clipboard monitoring for crypto artifacts
        $clip_bc1q   = "bc1q" ascii
        $clip_bc1p   = "bc1p" ascii
        $clip_seed   = "seed" ascii nocase

        // Crypto wallet format markers in address validation
        $wallet_bip  = "BIP39" ascii
        $wallet_wif  = "WIF" ascii

        // C2 payload output file
        $payload_out = "cfile" ascii

    condition:
        filesize < 5MB
        and (
            // Path 1: C2 protocol — 4+ action codes + any endpoint. The codes
            // are short generic tokens (GUID/GOOD/EVAL/SEED), so require 4 of
            // them alongside a C2 endpoint path to avoid matching API docs.
            (4 of ($proto_*) and any of ($c2_*))
            or
            // Path 2: Tor proxy + C2 endpoint
            (any of ($tor_socks1, $tor_socks2, $tor_socks3) and any of ($c2_*))
            or
            // Path 3: renamed Tor binary + C2 action codes
            ($tor_rename and 2 of ($proto_*))
            or
            // Path 4: clipboard crypto monitoring + Tor + exfil codes
            (any of ($clip_*) and any of ($tor_socks*) and any of ($proto_seed, $proto_pkey, $proto_repl))
            or
            // Path 5: anti-analysis + C2 protocol
            ($anti_wmi and $anti_taskmg and 2 of ($proto_*))
            or
            // Path 6: C2 endpoint trifecta (route + recvf + stub)
            ($c2_route and $c2_recvf and $c2_stub)
            or
            // Path 7: wallet-format markers + exfil codes + a C2/Tor anchor.
            // BIP39/WIF/SEED/PKEY are normal crypto-wallet vocabulary (this
            // path matched a legitimate BIP39 library), so require a malicious
            // anchor — a C2 endpoint, Tor SOCKS proxy, or the renamed Tor binary.
            (
                ($wallet_bip or $wallet_wif)
                and any of ($proto_seed, $proto_pkey)
                and (any of ($c2_*) or any of ($tor_socks1, $tor_socks2, $tor_socks3) or $tor_rename)
            )
            or
            // Path 8: payload output file + C2 endpoints
            ($payload_out and any of ($c2_*))
        )
}

rule CryptoBandits_Worm_Structure
{
    meta:
        description = "CryptoBandits worm/stealer — JavaScript payload structure, staging paths, scheduled task patterns, USB propagation"
        author      = "synthetic-detections"
        date        = "2026-06-19"
        severity    = "critical"
        family      = "cryptobandits-clipper"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"

    strings:
        // Staging directory pattern
        $stage_path  = "\\Users\\Public\\Documents\\" ascii nocase
        $stage_js    = ".js" ascii

        // Script execution via Windows Script Host
        $wsh_wscript = "wscript" ascii nocase
        $wsh_cscript = "cscript" ascii nocase
        $wsh_activex = "ActiveXObject" ascii

        // Scheduled task creation pattern
        $schtask_create = "schtasks" ascii nocase
        $schtask_xml    = "/xml" ascii nocase
        $schtask_tn     = "/tn" ascii nocase

        // USB worm — .lnk shortcut manipulation
        $lnk_ext     = ".lnk" ascii
        $lnk_wshell  = "WScript.Shell" ascii
        $lnk_shortcut = "CreateShortcut" ascii

        // curl with SOCKS proxy for C2
        $curl_socks  = "curl" ascii nocase
        $curl_onion  = ".onion" ascii

        // Screenshot exfiltration
        $screen_cap  = "screenshot" ascii nocase

        // Clipboard access patterns (JS/ActiveX)
        $clip_get    = "GetText" ascii
        $clip_set    = "SetText" ascii

        // Defense evasion — AV exclusion
        $av_exclude  = "ExclusionPath" ascii

    condition:
        filesize < 5MB
        and (
            // Path 1: JS payload in Public\Documents staging + WSH
            ($stage_path and $stage_js and any of ($wsh_*))
            or
            // Path 2: scheduled task + XML + JS in staging path
            ($schtask_create and $schtask_xml and $stage_path)
            or
            // Path 3: USB worm — .lnk creation + WSH + staging path
            ($lnk_wshell and $lnk_shortcut and $stage_path)
            or
            // Path 4: curl to .onion via SOCKS + WSH
            ($curl_socks and $curl_onion and any of ($wsh_*))
            or
            // Path 5: clipboard get/set + screenshot + AV exclusion
            ($clip_get and $clip_set and ($screen_cap or $av_exclude))
            or
            // Path 6: ActiveXObject + scheduled task + staging path
            ($wsh_activex and $schtask_create and $stage_path)
            or
            // Path 7: .lnk creation + curl .onion — worm + C2
            ($lnk_shortcut and $lnk_ext and $curl_onion)
            or
            // Path 8: scheduled task /tn + /xml + staging path
            ($schtask_tn and $schtask_xml and $stage_path)
        )
}

rule CryptoBandits_IOC
{
    meta:
        description = "Static IOC sweep — Tor .onion C2 domains, C2 endpoints, file hashes"
        author      = "synthetic-detections"
        date        = "2026-06-19"
        severity    = "high"
        family      = "cryptobandits-clipper"
        reference   = "https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/"

    strings:
        // Tor hidden service C2 domains
        $onion01 = "cgky6bn6ux5wvlybtmm3z255igt52ljml2ngnc5qp3cnw5jlglamisad.onion" ascii nocase
        $onion02 = "gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad.onion" ascii nocase
        $onion03 = "he5vnov645txpcv57el2theky2elesn24ebvgwfoewlpftksxp4fnxad.onion" ascii nocase
        $onion04 = "lyhizqy2js2eh6ufngkbzntouiikdek5zsdj3qwa22b4z6knpqorgiad.onion" ascii nocase
        $onion05 = "j3bv7g27oramhbxxuv6gl3dcyfmf44qnvju3offdyrap7hurfprq74qd.onion" ascii nocase
        $onion06 = "shinypogk4jjniry5qi7247tznop6mxdrdte2k6pdu5cyo43vdzmrwid.onion" ascii nocase
        $onion07 = "7goms4byw26kkbaanz5a5u5234gusot7rp5imzc3ozh66wwcvmcudjid.onion" ascii nocase
        $onion08 = "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion" ascii nocase
        $onion09 = "wt26llpl5k6gok3vnaxmucwgzv2wk3l7nuibbh25clghrtus3p5ctsid.onion" ascii nocase
        $onion10 = "ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion" ascii nocase

        // Worm component hashes (SHA-256)
        $hash01 = "7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c" ascii nocase
        $hash02 = "a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630" ascii nocase
        $hash03 = "23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43" ascii nocase
        $hash04 = "cf9fc891ea5ca5ecd8113ef3e69f6f52ff538b6cccbdaa9559106fc72bc6da30" ascii nocase
        $hash05 = "100407796028bf3649752d9d2a67a0e4394d752eb8de86daa42920e814f3fae8" ascii nocase
        $hash06 = "d14b80cbd1a19d4ad0473a0661297f8fdf598e81ff6c4ab24e212dcad2e54b3f" ascii nocase
        $hash07 = "9d90f54ae36c6c5435d5b8bed40faf54cc91f6db28574a6310b5ffaeb0362e96" ascii nocase
        $hash08 = "67fc5cf395e28294bbb91ed0e954fdf2e80ebd9119022a115a42c286dc8bacf5" ascii nocase

        // Clipper/stealer component hashes
        $hash09 = "0020d23b0f9c5e6851a7f737af73fd143175ee47054931166369edd93338538a" ascii nocase
        $hash10 = "35a6bc44b176a050fd6824904b7604f0f45b0fdfa26bf9500b9e05973b387cfd" ascii nocase
        $hash11 = "c824630154ac4fdfce94ded01f037c305eab51e9bef3f493c60ff3184a640502" ascii nocase
        $hash12 = "d43bf94f0cb0ab97c88113b7e07d1a4024d1610617b5ad05882b1dbab89e15ba" ascii nocase
        $hash13 = "b2777b73a4c33ac6a409d475057843be6b5d32262ef28a1f1ff5bb52e3834c5f" ascii nocase
        $hash14 = "7787a9a7d8ae393aa32f257d083903c4dc9b97a1e5b0458c4cd480d4f3cb5b05" ascii nocase
        $hash15 = "f3b54984caca95fd496bcfe5d7db1611b08d2f5b7d250b43b430e5d76393f9e0" ascii nocase
        $hash16 = "20db98af3037b197c8a846dbf17b87fc6f049c3e0d9a188f9b9a74d3916dd5e1" ascii nocase

        // Renamed Tor binary
        $tor_bin = "ugate.exe" ascii nocase

    condition:
        filesize < 50MB
        and (
            // Any .onion C2 domain
            any of ($onion*)
            or
            // Any known file hash
            any of ($hash*)
            or
            // Renamed Tor binary name (fragile but specific in context)
            ($tor_bin and any of ($onion*))
        )
}
