/*
   Prinz Eugen ransomware (first observed April 2026, ThreatDown deep-dive 2026-06-20)
   ------------------------------------------------------------------------------------
   New Go-based ransomware operation — not a RaaS, currently closed to affiliates.
   Named after a WWII German heavy cruiser. At least 5 victims including
   Standard Bank Group (1.2 TB exfiltrated, 1 BTC ransom refused).

   Distinctive traits: prioritizes recently modified files for encryption
   (maximizes business impact), leaves NO ransom note on disk, tears down
   infrastructure rapidly post-operation.

   Kill chain: stolen RDP → RMM abuse (RemotePC / IDrive) → PowerShell
   stager from 212.80.7[.]74 (/serverscan.ps1, /stager/mini, /stager/ps1)
   → servertool.exe (Go binary, custom package "scorched-earth-ausfc") →
   ChaCha20-Poly1305 encryption (Argon2id→SHA-256→HKDF-SHA256 KDF, per-file
   random IV, 1MB chunks) → encrypted files get .prinzeugen extension with
   CHV1 magic header → self-delete via ping-delay cmd → backdoor account
   "net user admin germania /add".

   Actor indicators: handles ROOTBOY / avtokz / GERMANIA; TOX and
   mail2tor/cock.li contact; BTC wallet bc1q2ztpcvqdaptej6uu2ywt9mrlatx6envu34rf0v.

   Rule 1 — Behavioral: Go encryptor binary with scorched-earth-ausfc
            package and encryption function names.
   Rule 2 — Structural: encrypted file with CHV1 magic header and
            .prinzeugen extension reference in proximity.
   Rule 3 — IOC: C2 infrastructure, actor contact, stager paths,
            self-delete pattern, backdoor account command.

   Sources:
     https://www.threatdown.com/blog/prinz-eugen-ransomware-a-deep-dive-into-a-new-go-based-encryptor/
     https://www.bleepingcomputer.com/news/security/new-prinz-eugen-ransomware-prioritizes-recent-files-for-encryption/
     https://gbhackers.com/prinz-eugen-ransomware/
     https://cyberpress.org/prinz-eugen-ransomware-attack/
*/

import "pe"

rule PrinzEugen_Encryptor_Behavior
{
    meta:
        description = "Prinz Eugen Go-based encryptor — scorched-earth-ausfc package with ChaCha20 encryption routines"
        author      = "synthetic-detections"
        date        = "2026-06-22"
        severity    = "critical"
        family      = "prinz-eugen-ransomware"
        hash        = "686213cc11d36af764de824801bced9366dfca3823fe0d51b752f74149bcf1f4"
        reference   = "https://www.threatdown.com/blog/prinz-eugen-ransomware-a-deep-dive-into-a-new-go-based-encryptor/"

    strings:
        // Go package path — unique to this family
        $pkg_name = "scorched-earth-ausfc" ascii

        // Core encryption function names (Go symbol table)
        $func_encrypt = "EncryptFileToKey" ascii
        $func_verify  = "VerifyEncryptedWithKey" ascii

        // Encrypted file extension written to disk
        $ext = ".prinzeugen" ascii

        // Magic header written to encrypted files
        $magic = "CHV1" ascii

        // Self-delete pattern: ping loopback then del
        $self_del = "ping 127.0.0.1 -n 2" ascii

        // Backdoor local account creation
        $backdoor = "admin germania" ascii

        // Temporary encryption working file suffix
        $tmp_ext = ".prinzeugen.tmp" ascii

    condition:
        filesize > 100KB and filesize < 30MB
        and (
            // Path 1: the encryptor binary — package name is
            // the strongest single anchor; pair with any function
            // or operational artifact
            (
                $pkg_name
                and any of ($func_encrypt, $func_verify, $ext, $magic)
            )
            or
            // Path 2: without full symbol table (stripped binary) —
            // file extension + magic header + any operational tell
            (
                $ext and $magic
                and any of ($self_del, $backdoor, $tmp_ext, $pkg_name)
            )
        )
}

rule PrinzEugen_Encrypted_File
{
    meta:
        description = "File encrypted by Prinz Eugen ransomware — CHV1 magic header with ChaCha20-Poly1305 ciphertext"
        author      = "synthetic-detections"
        date        = "2026-06-22"
        severity    = "critical"
        family      = "prinz-eugen-ransomware"
        reference   = "https://www.threatdown.com/blog/prinz-eugen-ransomware-a-deep-dive-into-a-new-go-based-encryptor/"

    strings:
        // CHV1 magic at file start — the encryptor's version marker
        $magic = "CHV1"

    condition:
        // CHV1 at offset 0 + minimum ciphertext size (header + IV +
        // at least one ChaCha20-Poly1305 block + auth tag)
        $magic at 0
        and filesize > 128
        and filesize < 500MB
}

rule PrinzEugen_IOC
{
    meta:
        description = "Static IOC sweep — Prinz Eugen C2 infrastructure, actor contacts, stager URLs, operational commands"
        author      = "synthetic-detections"
        date        = "2026-06-22"
        severity    = "high"
        family      = "prinz-eugen-ransomware"
        hash        = "686213cc11d36af764de824801bced9366dfca3823fe0d51b752f74149bcf1f4"
        reference   = "https://www.bleepingcomputer.com/news/security/new-prinz-eugen-ransomware-prioritizes-recent-files-for-encryption/"

    strings:
        // C2 panel / stager host (AS215439, Play2go International, Frankfurt)
        $c2_ip = "212.80.7.74" ascii

        // Operator domains
        $dom_bank    = "stndrdbnk.cc" ascii
        $dom_captcha = "g-captchafestung.sbs" ascii
        $dom_dyndns  = "festung-e.duckdns.org" ascii

        // PowerShell stager URL paths
        $stager_ps1  = "/serverscan.ps1" ascii
        $stager_mini = "/stager/mini" ascii
        $stager_main = "/stager/ps1" ascii

        // Actor contact — TOX ID (unique 76-char hex)
        $tox = "496187425B2944D73FBB17CAF3F9FD569B9ED3A08A497A8314CB4F27A51E65081ACEE1E22F21" ascii nocase

        // Actor email addresses
        $email_tor  = "prinzeugen@mail2tor.co" ascii
        $email_cock = "standardbankcc@cock.li" ascii

        // Bitcoin wallet
        $btc = "bc1q2ztpcvqdaptej6uu2ywt9mrlatx6envu34rf0v" ascii

        // Onion leak sites
        $onion_active = "prinzfkbjiazbrur4mjje6mntjc4vydx3iatkkzycufoylqcoo4y7pqd" ascii
        $onion_down   = "6cudc5cqa2bjpwdhcwm2lj6dbqejjjqzeo6ipwvmbazr6cgu7vfk3dad" ascii

        // Self-delete command pattern (full form)
        $self_del = "cmd.exe /C ping 127.0.0.1 -n 2" ascii

        // Backdoor account creation
        $backdoor_cmd = "net user admin germania /add" ascii

        // Actor handles (in threat reports / leak site context)
        $handle_root = "ROOTBOY" ascii
        $handle_germ = "GERMANIA" ascii

    condition:
        filesize < 50MB
        and (
            // Any C2 infrastructure indicator
            any of ($c2_ip, $dom_bank, $dom_captcha, $dom_dyndns)
            or
            // Stager URL paths (specific enough with the path structure)
            any of ($stager_ps1, $stager_mini, $stager_main)
            or
            // Actor contact channels
            any of ($tox, $email_tor, $email_cock, $btc)
            or
            // Onion infrastructure
            any of ($onion_active, $onion_down)
            or
            // Operational commands (together — individually too generic)
            ($self_del and $backdoor_cmd)
            or
            // Actor handles + any other IOC (handles alone too generic)
            (any of ($handle_root, $handle_germ) and any of ($c2_ip, $dom_bank, $dom_captcha, $dom_dyndns, $email_tor, $email_cock, $btc))
        )
}
