/*
   Kimsuky GitPower — Git-hosted payload delivery targeting diplomats
   ------------------------------------------------------------------
   Kimsuky (APT43) expanded Operation GitPower to target Ukrainian
   diplomats using reply-baiting spear phishing with Git-hosted payloads.
   Delivery: LNK files disguised as PDFs → cmd.exe → curl → PowerShell
   chain fetching first.ini/help.ini from GitLab repos. Payloads are
   saved as VBE files (apple.vbe, shiba.vbe), install a fake Zoom
   binary (zoominstaller.exe), and persist via scheduled tasks named
   with Google-impersonating GUIDs. Exfiltration uses the GitHub
   Contents API to push system reconnaissance (SYS_*.tmp, DOWN_*.tmp)
   to an attacker-controlled repository.

   C2 relies on serveirc.com subdomains and a rotating set of free
   hosting providers (.onlinewebshop.net, .getenjoyment.net,
   .mygamesonline.org, .myartsonline.com, etc.). GitLab repos
   kickball12/bahubali, galata20/shiba, and account keresman host
   intermediate payloads.

   Related families: [[kimsuky-hellodoor]].

   Rule 1 — behavioural: cmd→curl→PowerShell delivery chain with
            first.ini/help.ini pattern, GoogleUpdateTaskMachineUA
            scheduled task GUID, GitHub Contents API exfiltration.
   Rule 2 — IOC sweep: serveirc.com subdomains, free-hosting C2
            domains, GitLab repo paths, payload filenames, email,
            hardcoded password. Co-occurrence guarded.
   Rule 3 — specimen pin: LNK/VBE structural anchor — LNK with
            Ukrainian/Korean filename markers + cmd/curl/powershell
            chain, or VBE with obfuscation markers.

   Sources:
     https://www.genians.co.kr/en/blog/threat_intelligence/operation-gitpower
*/

rule Kimsuky_GitPower_Behavioral : apt behavioral c2
{
    meta:
        description = "Kimsuky GitPower behavioural — cmd/curl/PowerShell delivery chain, scheduled-task GUID persistence, GitHub API exfiltration"
        author      = "synthetic-detections"
        date        = "2026-10-12"
        severity    = "critical"
        family      = "kimsuky-gitpower"
        reference   = "https://www.genians.co.kr/en/blog/threat_intelligence/operation-gitpower"

    strings:
        // Delivery chain anchors — the cmd→curl→PowerShell fetch pattern
        $dl_first   = "first.ini" ascii wide
        $dl_help    = "help.ini" ascii wide

        // Payload VBE names dropped by the delivery chain
        $vbe_apple  = "apple.vbe" ascii wide
        $vbe_shiba  = "shiba.vbe" ascii wide
        $vbe_wef    = "wef.vbe" ascii wide

        // Scheduled task persistence — Google-impersonating GUID pattern
        $schtask1   = "GoogleUpdateTaskMachineUA{1C791230-CA8D-6D04-AC55-E498ABE7C33}" ascii wide
        $schtask2   = "GoogleUpdateTaskMachineUA{1C791230-CA8D-6D04-AC55-F706378A30E}" ascii wide

        // GitHub Contents API exfiltration — attacker repo
        $exfil_repo = "omskiwdcvoiuyfd0998/0ijnbjfke8djfefhkehhdkefkeu90djfkefh" ascii wide

        // Exfiltration file naming pattern
        $exfil_sys  = /SYS_\d{4}-\d{2}-\d{2}_\d{4}\.tmp/ ascii wide
        $exfil_down = /DOWN_\d{4}-\d{2}-\d{2}_\d{4}\.tmp/ ascii wide

        // Staging paths used consistently
        $path_music  = "C:\\Users\\Public\\Music\\" ascii wide
        $path_videos = "C:\\Users\\Public\\Videos\\" ascii wide

    condition:
        (
            // Delivery chain: ini fetcher + VBE drop
            (any of ($dl_first, $dl_help) and any of ($vbe_apple, $vbe_shiba, $vbe_wef)) or
            // Scheduled task persistence GUID (globally unique)
            any of ($schtask1, $schtask2) or
            // Exfiltration repo path (globally unique)
            $exfil_repo or
            // Exfiltration naming pattern + staging path
            (any of ($exfil_sys, $exfil_down) and any of ($path_music, $path_videos))
        )
        and filesize < 10MB
}

rule Kimsuky_GitPower_IOC : apt c2 ioc
{
    meta:
        description = "Kimsuky GitPower IOC sweep — C2 domains, GitLab repos, payload names, email, hardcoded password"
        author      = "synthetic-detections"
        date        = "2026-10-12"
        severity    = "high"
        family      = "kimsuky-gitpower"
        reference   = "https://www.genians.co.kr/en/blog/threat_intelligence/operation-gitpower"

    strings:
        // serveirc.com C2 subdomains
        $c2_zoom     = "security-zooma.serveirc.com" ascii wide
        $c2_profile  = "security-profile.serveirc.com" ascii wide
        $c2_mail     = "mailsecurity.serveirc.com" ascii wide

        // Additional C2 domains
        $c2_koval    = "kovalenko.dothome.co.kr" ascii wide
        $c2_dofa     = "dofamini.com.ua" ascii wide

        // Free hosting C2 — need co-occurrence guard (too broad alone)
        $freehost1   = ".onlinewebshop.net" ascii wide
        $freehost2   = ".getenjoyment.net" ascii wide
        $freehost3   = ".mygamesonline.org" ascii wide
        $freehost4   = ".myartsonline.com" ascii wide
        $freehost5   = ".scienceontheweb.net" ascii wide
        $freehost6   = ".sportsontheweb.net" ascii wide
        $freehost7   = ".medianewsonline.com" ascii wide
        $freehost8   = ".mypressonline.com" ascii wide
        $freehost9   = ".mywebcommunity.org" ascii wide
        $freehost10  = ".atwebpages.com" ascii wide

        // GitLab payload repos
        $git_bahu    = "kickball12/bahubali" ascii wide
        $git_shiba   = "galata20/shiba" ascii wide
        $git_keres   = "gitlab.com/keresman" ascii wide

        // Campaign tokens for co-occurrence
        $tok_zoom    = "zoominstaller.exe" ascii wide
        $tok_pwd     = "MySecurePass123" ascii wide
        $tok_email   = "kcscon@proton.me" ascii wide

        // Obfuscation markers
        $obf_wefh    = "wefhskdf" ascii wide
        $obf_wudks   = "wudks" ascii wide
        $obf_asjdfi  = "-asjdfi&" ascii wide
        $obf_banna   = "Banna" ascii wide

        // C2 IPs
        $ip1         = "45.150.109.102" ascii wide
        $ip2         = "85.155.224.59" ascii wide
        $ip3         = "103.153.65.67" ascii wide
        $ip4         = "111.92.246.145" ascii wide
        $ip5         = "169.197.85.174" ascii wide
        $ip6         = "195.250.24.113" ascii wide

    condition:
        (
            // Named serveirc.com C2 subdomains fire standalone
            any of ($c2_zoom, $c2_profile, $c2_mail) or
            // Additional C2 domains fire standalone
            any of ($c2_koval, $c2_dofa) or
            // GitLab repos fire standalone
            any of ($git_bahu, $git_shiba, $git_keres) or
            // Free hosting domains need a second campaign token
            (any of ($freehost*) and any of ($tok_zoom, $tok_pwd, $tok_email, $obf_wefh, $obf_wudks, $obf_asjdfi, $obf_banna)) or
            // C2 IPs need a second campaign token
            (any of ($ip*) and any of ($tok_zoom, $tok_pwd, $tok_email, $obf_wefh, $c2_zoom, $c2_profile, $c2_mail)) or
            // Campaign tokens co-occurring: password + email, or password + fake zoom
            ($tok_pwd and ($tok_email or $tok_zoom)) or
            // Obfuscation marker cluster (3+ together is high confidence)
            (3 of ($obf_wefh, $obf_wudks, $obf_asjdfi, $obf_banna))
        )
        and filesize < 50MB
}

rule Kimsuky_GitPower_Specimen : apt specimen
{
    meta:
        description = "Kimsuky GitPower specimen pin — LNK/VBE structural anchor with campaign-specific markers"
        author      = "synthetic-detections"
        date        = "2026-10-12"
        severity    = "critical"
        family      = "kimsuky-gitpower"
        reference   = "https://www.genians.co.kr/en/blog/threat_intelligence/operation-gitpower"

    strings:
        // LNK filename markers — Ukrainian and conference-themed lures
        $lnk_ukr     = {D0 90 D0 BD D0 B0 D0 BB D1 96 D1 82 D0 B8 D1 87 D0 BD D0 B8 D0 B9}  // "Аналітичний" UTF-8
        $lnk_natalia  = {D0 9D D0 B0 D1 82 D0 B0 D0 BB D1 96 D1 97}                            // "Наталії" UTF-8
        $lnk_kcscon   = "KCSCON_2026" ascii wide
        $lnk_century  = "A_Century_Long_Peace" ascii wide

        // cmd/curl/powershell delivery chain in LNK target
        $chain_cmd    = "cmd.exe" ascii wide nocase
        $chain_curl   = "curl" ascii wide nocase
        $chain_ps     = "powershell" ascii wide nocase

        // VBE obfuscation markers — unique to this campaign
        $vbe_wolf     = "wolf" ascii wide
        $vbe_wefh     = "wefhskdf" ascii wide
        $vbe_wudks    = "wudks" ascii wide

        // VBE payload names
        $vbe_name1    = "apple.vbe" ascii wide
        $vbe_name2    = "shiba.vbe" ascii wide
        $vbe_name3    = "shibaa.vbe" ascii wide
        $vbe_name4    = "applee.vbe" ascii wide

        // desktop.ps1 / desktop.vbs in Public\Videos
        $desk_ps1     = "desktop.ps1" ascii wide
        $desk_vbs     = "desktop.vbs" ascii wide

    condition:
        (
            // LNK specimen: Ukrainian/Korean lure name + delivery chain
            (
                any of ($lnk_ukr, $lnk_natalia, $lnk_kcscon, $lnk_century) and
                2 of ($chain_cmd, $chain_curl, $chain_ps)
            ) or
            // VBE specimen: obfuscation markers + payload name
            (
                2 of ($vbe_wolf, $vbe_wefh, $vbe_wudks) and
                any of ($vbe_name1, $vbe_name2, $vbe_name3, $vbe_name4, $desk_ps1, $desk_vbs)
            )
        )
        and filesize < 1MB
}
