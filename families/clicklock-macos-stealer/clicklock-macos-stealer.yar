/*
   ClickLock — macOS infostealer with coercion kill-loop
   (Group-IB, disclosed 2026-07-16)
   -----------------------------------------------------
   macOS stealer delivered via the ClickFix technique (a command pasted
   into Terminal behind a fake "Cloudflare CAPTCHA" / "verify you are not a
   bot" page). An osascript fake system dialog harvests the login password;
   if the victim cancels, two LaunchAgents persist and, at next login, the
   malware terminates Finder, Dock, Spotlight, Terminal, Activity Monitor,
   Console, System Settings and browsers every ~210 ms (200 ms in the
   Keychain module) for up to 83 hours to coerce the victim into typing
   their password. Steals from 8 browsers, 31 crypto-wallet extensions, 7
   password managers, 8 desktop wallets, 6 chains, the macOS Keychain
   (`security find-generic-password -wa "Chrome"`), shell history and FTP
   credentials, and stages a GSocket backdoor disguised as `iCloudsync`.
   Exfil via api.telegram.org. ~100 victims / 33 countries since ~May 2026.

   Related: ClickFix delivery overlaps other macOS stealer campaigns
   (AMOS et al.) — see [[famous-chollima-packagist]] for a different
   ClickFix-adjacent loader family in this repo.

   Rule 1 — Behavioral: orchestrator/module shell + AppleScript patterns
            (kill-loop, ClickFix banners, Keychain theft, staging dir).
   Rule 2 — IOC: C2 domains, LaunchAgent labels, sample SHA1 hashes.
   Rule 3 — Specimen-pin: the tight, distinctive artifact combination.

   Sources:
     https://www.group-ib.com/blog/clicklock-stealer-macos-malware/
     https://thehackernews.com/2026/07/new-clicklock-macos-stealer-kills-apps.html
*/

rule ClickLock_macOS_Stealer_Behavior {
    meta:
        description = "ClickLock macOS stealer — orchestrator/module shell + osascript behavior (ClickFix banner, kill-loop coercion, Keychain theft)"
        author = "synthetic-detections"
        date = "2026-07-17"
        severity = "critical"
        family = "clicklock-macos-stealer"
        reference = "https://www.group-ib.com/blog/clicklock-stealer-macos-malware/"
    strings:
        $ban_bot = "Verifying you are not a bot" nocase
        $ban_cf = "CLOUDFLARE CAPTCHA ACCESS CONTROL" nocase
        $ban_signals = "Collecting browser signals" nocase
        $kl_killall = "killall"
        $kl_finder = "Finder"
        $kl_actmon = "Activity Monitor"
        $kl_sleep210 = "0.210"
        $kl_sleep200 = "0.200"
        $kc_chrome = "find-generic-password -wa \"Chrome\""
        $st_cacheb = ".cacheb"
        $st_chromekey = "-chrome-key.txt"
        $st_icloud = "Application Support/iCloudsync"
        $st_finderlog = "finder_output.txt"
        $osa = "osascript"
    condition:
        (any of ($ban_*) and ($kl_killall and $kl_finder and any of ($kl_sleep200, $kl_sleep210) or $kc_chrome or $st_cacheb or $st_icloud) or $kl_killall and $kl_finder and $kl_actmon and any of ($kl_sleep200, $kl_sleep210) or $kc_chrome and $st_cacheb and $osa or ($st_chromekey or $st_finderlog) and $st_cacheb and $osa) and filesize < 512KB
}

rule ClickLock_macOS_Stealer_IOC {
    meta:
        description = "ClickLock macOS stealer — network IOCs, LaunchAgent labels, and sample SHA1 hashes"
        author = "synthetic-detections"
        date = "2026-07-17"
        severity = "high"
        family = "clicklock-macos-stealer"
        reference = "https://thehackernews.com/2026/07/new-clicklock-macos-stealer-kills-apps.html"
    strings:
        $d_pana = "panalobet.ph" nocase
        $d_graf = "store.grafsynergy.com" nocase
        $d_cotton = "cottonbox.co.il" nocase
        $d_gsnc = "gsnc.eu:67" nocase
        $la_auth = "com.authirity"
        $la_chrom = "com.chromer"
        $h1 = "d9617710d4ed8e9b87f6fee0b7014c4101effba0" nocase
        $h2 = "b67aa4f598c0ea625a7409ea7884e10a7bc9c3ff" nocase
        $h3 = "8dda05168ea8610a2449419a47517bc32823d6ec" nocase
        $h4 = "0a1fb016bd10bac5455175c79aa4511e5ff1a330" nocase
        $h5 = "2fc970e25570532f9cbe33b7ebfe1f0383a7341a" nocase
    condition:
        (any of ($h*) or any of ($d_*) and any of ($la_*) or 2 of ($d_*) or $la_auth and $la_chrom) and filesize < 50MB
}

rule ClickLock_macOS_Stealer_Specimen {
    meta:
        description = "ClickLock macOS stealer — tight specimen pin (distinctive artifact combination)"
        author = "synthetic-detections"
        date = "2026-07-17"
        severity = "critical"
        family = "clicklock-macos-stealer"
        reference = "https://www.group-ib.com/blog/clicklock-stealer-macos-malware/"
    strings:
        $la_auth = "com.authirity"
        $la_chrom = "com.chromer"
        $st_cacheb = ".cacheb"
        $kc_chrome = "find-generic-password -wa \"Chrome\""
        $ban_cf = "CLOUDFLARE CAPTCHA ACCESS CONTROL" nocase
    condition:
        ($la_auth or $la_chrom) and $st_cacheb and ($kc_chrome or $ban_cf) and filesize < 512KB
}
