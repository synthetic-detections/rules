/*
   TraderTraitor / FLATROOF + ROOFDECK backdoors
   (disclosed 2026-10-08, Zscaler ThreatLabz)
   -----------------------------------------------
   North Korean supply-chain campaign delivering the FLATROOF backdoor
   via a trojanized Terraform provider ("terraform-provider-awsbeta").
   A Bash loader decrypts platform-specific FLATROOF payloads from
   font-file lookalikes (.woff) using AES, identified by an
   @@ENDFONT@@ end-of-file marker. FLATROOF establishes persistence
   across macOS/Windows/Linux and deploys the ROOFDECK second-stage
   implant. C2 infrastructure uses lookalike domains
   (hashicorp-terraform[.]io) and dynamic DNS services. Dead-drop
   resolvers on Pastebin provide backup C2 addresses.

   Configuration encrypted with AES key embedded in the binary.
   Targets cryptocurrency wallets: MetaMask, Phantom, Trust Wallet,
   Rabby. Performs Cortex XDR detection before proceeding.

   Attribution: TraderTraitor / Jade Sleet / UNC4899 / Slow Pisces

   Rule 1 — Behavioral: AES key + end-of-font marker, OR
            Terraform provider patterns + C2 infrastructure, OR
            FLATROOF install paths + persistence names.
   Rule 2 — IOC: globally unique campaign tokens fire standalone;
            generic domains require co-occurrence anchors.
   Rule 3 — Specimen pin: MD5 hashes of 12 known samples.

   Sources:
     https://www.zscaler.com/blogs/security-research/tradertraitor-flatroof-roofdeck-campaign-analysis
     https://www.sentinelone.com/labs/dprk-crypto-theft-tradertraitor-terraform-supply-chain/
*/

import "hash"

rule TraderTraitor_FLATROOF_Behavioral : backdoor behavioral loader
{
    meta:
        description = "TraderTraitor FLATROOF — loader AES key + font-file marker, Terraform supply-chain patterns, FLATROOF install paths and persistence names"
        author      = "synthetic-detections"
        date        = "2026-10-10"
        severity    = "critical"
        family      = "tradertraitor-flatroof"
        reference   = "https://www.zscaler.com/blogs/security-research/tradertraitor-flatroof-roofdeck-campaign-analysis"
    strings:
        // Loader AES key used to decrypt FLATROOF payloads from .woff files
        $aes_loader       = "PTa3WZPQZAjj55t@"
        // End-of-font marker appended to encrypted payloads
        $endfont          = "@@ENDFONT@@"
        // FLATROOF config decryption key
        $config_key       = "u73adF39ZT"
        // Config AES key
        $config_aes       = "a9d932dcfa3289a6"
        // Trojanized Terraform provider name
        $tf_provider      = "terraform-provider-awsbeta"
        // Lookalike domain impersonating HashiCorp
        $domain_hashicorp = "hashicorp-terraform.io"
        // FLATROOF install paths (cross-platform)
        $path_linux       = ".config/git/update"
        $path_macos       = "Library/com.apple.iTunesCloud/SystemUpdate"
        $path_windows     = "AppData/Local/Microsoft/Edge/service.exe"
        // Persistence service/daemon names
        $persist_snap     = "snap-imagent"
        $persist_imagent  = "imagent" fullword
        $persist_ps       = "powershell-config-service"
        // Run-once marker file
        $marker_lock      = "session.lock" fullword
        // Wallet targets
        $wallet_meta      = "MetaMask" nocase
        $wallet_phantom   = "Phantom" nocase
        $wallet_trust     = "Trust Wallet" nocase
        $wallet_rabby     = "Rabby" nocase
    condition:
        // Path 1: loader AES key + end-of-font marker (decryption routine)
        // Path 2: config keys together (FLATROOF binary internals)
        // Path 3: Terraform supply-chain — trojanized provider + lookalike domain
        // Path 4: FLATROOF install path + matching persistence name
        // Path 5: multiple install paths (cross-platform dropper logic)
        // Path 6: Terraform provider + wallet targets (supply-chain + crypto theft)
        // Path 7: config key + install path + run-once marker (FLATROOF deployment)
        // Path 8: loader key + config key (both AES layers present)
        (
            ($aes_loader and $endfont) or
            ($config_key and $config_aes) or
            ($tf_provider and $domain_hashicorp) or
            (any of ($path_linux, $path_macos, $path_windows) and any of ($persist_snap, $persist_imagent, $persist_ps)) or
            2 of ($path_linux, $path_macos, $path_windows) or
            ($tf_provider and 2 of ($wallet_*)) or
            ($config_key and any of ($path_*) and $marker_lock) or
            ($aes_loader and $config_key)
        )
        and filesize < 10MB
}

rule TraderTraitor_FLATROOF_IOC : c2 ioc
{
    meta:
        description = "TraderTraitor FLATROOF — campaign-unique C2 domains, AES keys, Pastebin dead drop, and staging URLs"
        author      = "synthetic-detections"
        date        = "2026-10-10"
        severity    = "high"
        family      = "tradertraitor-flatroof"
        reference   = "https://www.zscaler.com/blogs/security-research/tradertraitor-flatroof-roofdeck-campaign-analysis"
    strings:
        // Globally unique — fire standalone
        $unique_domain1 = "hashicorp-terraform.io"
        $unique_aes     = "PTa3WZPQZAjj55t@"
        $unique_cfgkey  = "u73adF39ZT"
        $unique_c2_sup  = "supportaru.serveftp.com"
        $unique_c2_aru  = "arusupport-region1-webhook.online"
        // C2 staging URLs (domain + path — unique enough standalone)
        $c2_diagnose    = "diagnose.hashicorp-terraform.io"
        $c2_pastebin    = "pastebin.com/raw/3yptBDhL"
        // Dynamic DNS C2 — require campaign anchor for co-occurrence
        $dyndns_delay   = "delay.servehttp.com"
        // Campaign anchors for co-occurrence guard
        $anchor_endfont = "@@ENDFONT@@"
        $anchor_tfprov  = "terraform-provider-awsbeta"
        $anchor_cfgaes  = "a9d932dcfa3289a6"
    condition:
        // Any globally unique IOC fires standalone
        // Dynamic DNS domain requires a campaign anchor
        (any of ($unique_*) or any of ($c2_*) or ($dyndns_delay and any of ($anchor_*)))
        and filesize < 50MB
}

rule TraderTraitor_FLATROOF_Specimen : specimen
{
    meta:
        description = "TraderTraitor FLATROOF/ROOFDECK — specimen pin on 12 known samples by MD5 hash"
        author      = "synthetic-detections"
        date        = "2026-10-10"
        severity    = "critical"
        family      = "tradertraitor-flatroof"
        reference   = "https://www.zscaler.com/blogs/security-research/tradertraitor-flatroof-roofdeck-campaign-analysis"
    condition:
        // terraform-provider-awsbeta_v1.0.0 (trojanized provider)
        // safari_updater (Bash loader)
        // HiraginoSans-Bold.woff (encrypted macOS x86 FLATROOF)
        // HiraginoSans-Regular.woff (encrypted macOS arm64 FLATROOF)
        // MalgunGothic-Bold.woff (encrypted PE32+ FLATROOF)
        // MalgunGothic-Italic.woff (encrypted PE32 FLATROOF)
        // NotoSansCJK-Bold.woff (encrypted ELF x86-64 FLATROOF)
        // NotoSansCJK-ExtraBold.woff (encrypted ELF ARM FLATROOF)
        // NotoSansCJK-Italic.woff (encrypted ELF 32-bit FLATROOF)
        // NotoSansCJK-Regular.woff (encrypted ELF ARM aarch64 FLATROOF)
        // imagent (macOS ROOFDECK)
        // update.exe (Windows ROOFDECK)
        filesize < 50MB
        and (
            hash.md5(0, filesize) == "9d78ece09457907b730d139e4e0c64dd" or
            hash.md5(0, filesize) == "73adaea97f003735335505858c1c6def" or
            hash.md5(0, filesize) == "116f7189ed7b41f1b339a749d56e63be" or
            hash.md5(0, filesize) == "be60c52ca8a01fef7dc15c2f0ebb77d8" or
            hash.md5(0, filesize) == "58fa0d651898446d5f5d2ed8a27a3330" or
            hash.md5(0, filesize) == "2621753691be9521288664bb551dfba6" or
            hash.md5(0, filesize) == "ad0b1b6d2c8b9d09d6473a4a299470ab" or
            hash.md5(0, filesize) == "4b8509cde757b5428e5f99c8dffe73ca" or
            hash.md5(0, filesize) == "3826dc7a9ba8bd5b1c143560c1530d89" or
            hash.md5(0, filesize) == "34a52e6a4d803e94fe497bab682abfd3" or
            hash.md5(0, filesize) == "2b81aceab0142472d94eb42e500b27b1" or
            hash.md5(0, filesize) == "9d88b4494c7bc27b10358b68a899ad54"
        )
}
