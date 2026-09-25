/*
   sauron-loader — Sauron Loader, MaaS loader sold on underground forums
   (DCSO CyTec, disclosed 2026-09-24)
   ---------------------------------------------------------------------
   Malware-as-a-service loader advertised by the forum alias "S4ur0n" to
   Russian-speaking customers (terms exclude CIS and public-sector victims).
   Delivery is an MSI (Msiexec, T1218.007) that drops three files into
   C:\ProgramData\keyroll\ :
     rnpkeys.exe  — legitimate RNP (OpenPGP) key tool, the side-load host
     rnp.dll      — the malicious 64-bit loader DLL, side-loaded by rnpkeys.exe
     tdwp.dll     — decrypter / scheduler component
   Persistence is a scheduled task named "keyroll". The loader carries the
   string "Sauron" and an embedded configuration located by a position-
   independent "stub selector" (call $+5 / pop rax / cmp rcx,0 / cmp rcx,1 /
   lea rax,[rax+disp] / ret). The blob is a 16-byte Salsa20 key + 8-byte
   nonce + size + ciphertext; the plaintext starts with magic 0xBAADF00D,
   a flags byte (0x80 = CIS keyboard check, 0x40 = gov-domain check), 1..16
   header DWORDs ending in a major/minor/build version, then length-prefixed
   DER RSA keys (private 1192 bytes, public 294 bytes), UTF-16 group/build
   IDs and an array of UTF-16 C2 URLs. C2 is HTTPS POST, Salsa20-encrypted,
   RSA-signed TLV messages (register / get task / task result / get payload)
   to paths /<api|webhook|metrics|public|internal>/v<1-9>/<set|get><Resource>
   with decoy query parameters (request_id, timestamp, api_key, user_id,
   session_token, client_version, platform, redirect_url, device_type,
   encryption_key). User-Agent is built from a format string with the host's
   NT version: an Edge 143 string on Windows 10+ and an IE11/Trident string
   on Windows 8. Payload handlers: EXE, DLL, driver, shellcode, MSI, ZIP,
   CMD, PowerShell, VBS, JavaScript. Bot ID = MD5(COMPUTERNAME + USERNAME +
   volume serial).

   C2: api.namsb-show.com, api.quinlantours.com, api.virtual-magic.com,
   api.lahaina-shores.com, api.mythicinsights.com (all registered
   2026-06/07, Cloudflare NS).

   Related Windows loader / side-load families in this repo:
   [[golden-chickens-tag195]] (MaaS loader ecosystem),
   [[asyncrat-screenconnect-seo]] (signed-host DLL side-loading),
   [[bluemoon-exploit-kit]] (MSI staging + side-loaded DLL).

   Rule 1 — Behavioural: stub-selector code shape in a 64-bit DLL, OR a
            decrypted config (0xBAADF00D header + DER RSA private key at the
            header offset + RSA-2048 SPKI), OR the UA format-string pair with
            the decoy C2 query vocabulary, OR an MSI laying down the keyroll
            triad. No single generic token fires it.
   Rule 2 — IOC: C2 domains, keyroll drop path, component names, forum
            alias, config IDs, imphashes — co-occurrence guarded so a single
            C2 string on its own does not fire.
   Rule 3 — Specimen pin: SHA-256 of the published DLL / MSI samples. The
            legitimate rnpkeys.exe side-load host is deliberately NOT pinned.

   Sources:
     https://medium.com/@DCSO_CyTec/sauron-loader-a-new-loader-lurking-in-underground-forums-e91fa70db537
     https://malware.news/t/sauron-loader-a-new-loader-lurking-in-underground-forums/125861
     https://github.com/DCSO/Blog_CyTec/tree/main/2026_09__sauron_loader
*/

import "pe"
import "hash"

rule SauronLoader_Behavioral
{
    meta:
        description = "Sauron Loader — config stub-selector in a 64-bit DLL, decrypted 0xBAADF00D config with embedded RSA keys, Edge143/Trident UA format pair + decoy C2 query set, or keyroll MSI triad"
        author      = "synthetic-detections"
        date        = "2026-09-25"
        severity    = "critical"
        family      = "sauron-loader"
        reference   = "https://github.com/DCSO/Blog_CyTec/tree/main/2026_09__sauron_loader"

    strings:
        // DCSO stub selector, generalised: branch targets, the small lea
        // displacement and the disp32 to the config blob are wildcarded so
        // rebuilt samples with a different layout still match.
        // call $+5 ; pop rax ; cmp rcx,0 ; je ; cmp rcx,1 ; je ;
        // lea rax,[rax+imm8] ; ret ; lea rax,[rax+disp32] ; ret
        $sel = { E8 00 00 00 00 58 48 83 F9 00 74 ?? 48 83 F9 01 74 ?? 48 8D 40 ?? C3 48 8D 80 ?? ?? ?? ?? C3 }

        // decrypted config: magic 0xBAADF00D (LE), flags byte, 1..16 header
        // DWORDs + 4-byte LE key length, then a DER RSA private key (version 0)
        $cfg_hdr  = { 0D F0 AD BA ( 00 | 40 | 80 | C0 ) [4-64] ?? ?? 00 00 30 82 ?? ?? 02 01 00 }
        // RSA-2048 SubjectPublicKeyInfo (294 bytes) that follows the private key
        $cfg_spki = { 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 }

        // User-Agent format strings (NT version filled in at runtime)
        $ua_edg = "Mozilla/5.0 (Windows NT %d.%d; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.3650.96" ascii wide
        $ua_tri = "Mozilla/5.0 (Windows NT %d.%d; Trident/7.0; rv:11.0) like Gecko" ascii wide

        // decoy C2 query-parameter vocabulary
        $q01 = "request_id" ascii wide
        $q02 = "api_key" ascii wide
        $q03 = "user_id" ascii wide
        $q04 = "session_token" ascii wide
        $q05 = "client_version" ascii wide
        $q06 = "redirect_url" ascii wide
        $q07 = "device_type" ascii wide
        $q08 = "encryption_key" ascii wide

        // MSI payload triad + install directory / task name
        $m_keyroll = "keyroll" ascii wide nocase fullword
        $m_rnpkeys = "rnpkeys.exe" ascii wide nocase
        $m_rnp     = "rnp.dll" ascii wide nocase fullword
        $m_tdwp    = "tdwp.dll" ascii wide nocase

    condition:
        filesize < 50MB
        and (
            // unpacked loader DLL: stub selector in a PE32+ DLL
            (uint16(0) == 0x5A4D and pe.is_64bit() and pe.is_dll() and $sel)
            // decrypted config in memory / dump: header then SPKI right after the private key
            or ($cfg_hdr and $cfg_spki in (@cfg_hdr[1] .. @cfg_hdr[1] + 4200))
            // PE carrying both UA format strings plus the decoy query set
            or (uint16(0) == 0x5A4D and $ua_edg and $ua_tri and 4 of ($q*))
            // MSI (OLE compound file) laying down the keyroll triad
            or (uint32(0) == 0xE011CFD0 and $m_keyroll and $m_rnpkeys and $m_rnp and $m_tdwp)
        )
}

rule SauronLoader_IOC
{
    meta:
        description = "Sauron Loader — C2 domains, keyroll drop path, tdwp.dll component, forum alias, config IDs and imphashes (co-occurrence guarded)"
        author      = "synthetic-detections"
        date        = "2026-09-25"
        severity    = "high"
        family      = "sauron-loader"
        reference   = "https://github.com/DCSO/Blog_CyTec/tree/main/2026_09__sauron_loader"

    strings:
        // C2 (registrable domains; the loader uses the api. host of each)
        $d1 = "namsb-show.com" ascii wide nocase
        $d2 = "quinlantours.com" ascii wide nocase
        $d3 = "virtual-magic.com" ascii wide nocase
        $d4 = "lahaina-shores.com" ascii wide nocase
        $d5 = "mythicinsights.com" ascii wide nocase

        // co-occurrence anchors
        $a_keyroll = "ProgramData\\keyroll" ascii wide nocase
        $a_tdwp    = "tdwp.dll" ascii wide nocase
        $a_ua      = "Edg/143.0.3650.96" ascii wide
        $a_alias   = "S4ur0n" ascii wide
        $a_grp     = "test_bot_group_uid" ascii wide
        $a_bld     = "test_build_tag_uid" ascii wide
        $a_sauron  = "Sauron" ascii wide fullword

    condition:
        filesize < 50MB
        and (
            // two distinct C2 domains together
            2 of ($d*)
            // one C2 domain guarded by a family anchor ("Sauron" only counts inside a PE)
            or (1 of ($d*) and (any of ($a_keyroll, $a_tdwp, $a_ua, $a_alias, $a_grp, $a_bld)
                                or (uint16(0) == 0x5A4D and $a_sauron)))
            // drop path + decrypter component name
            or ($a_keyroll and $a_tdwp)
            // published imphashes, guarded by a family string in a 64-bit DLL
            or (uint16(0) == 0x5A4D and pe.is_64bit() and pe.is_dll()
                and (pe.imphash() == "cc4a762bd1b2eb3b54dfa46a33d5a50f"
                     or pe.imphash() == "85b55a5c926f8ef8f4f5f7ca2070c775"
                     or pe.imphash() == "fd90e5c28f1b4156ae7a40859b11e11c"
                     or pe.imphash() == "f9e79734109d56f4dd73964feeaeffc0")
                and ($a_sauron or $a_ua or any of ($d*)))
        )
}

rule SauronLoader_Specimen
{
    meta:
        description = "Sauron Loader — SHA-256 pin of the published loader DLLs, tdwp.dll and the dropper MSI"
        author      = "synthetic-detections"
        date        = "2026-09-25"
        severity    = "critical"
        family      = "sauron-loader"
        reference   = "https://github.com/DCSO/Blog_CyTec/tree/main/2026_09__sauron_loader"

    condition:
        filesize < 1MB
        and (
            hash.sha256(0, filesize) == "53b5b3186304c9fed669c56adc8f1b9add2a806b044ef01e828746f149caef61"
            or hash.sha256(0, filesize) == "5f82a170193f43eda9e32137b858058a64af32874cb93591b32d7bbd6aef6c33"   // DLL, 256368 B
            or hash.sha256(0, filesize) == "68da2a2b52499119767bc341c1c263bcd859edc264f46d12c41a4454e6b2a606"   // DLL, 245616 B
            or hash.sha256(0, filesize) == "6bea92c0ab711d62a6b43997ba28ebe771627c25924d51642bfe8d0a848d5a59"   // DLL, 256368 B
            or hash.sha256(0, filesize) == "92542749d6ca37b6ffca2dff4029a76b470625e8f1e1c62fde07d83976aeb1c9"   // DLL, 286208 B
            or hash.sha256(0, filesize) == "5606afdc5191d42f38d3c4f1692eda0a629c88810e29bfe78528733284ad1bf8"   // rnp.dll, 307496 B
            or hash.sha256(0, filesize) == "6551293e996d19755ba497f50b30a18c178f0d6e2a73b29ae742b8171e2985b7"   // tdwp.dll, 172840 B
            or hash.sha256(0, filesize) == "ee727d639eaa4ee2e0d7cafbe496e14aaac8df0955d9fb599f2c11dfa1d0f8f2"   // test.msi, 593920 B
        )
}
