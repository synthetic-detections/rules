/*
   PATCHCORD / SHEETCORD / HACKERAI — APT36 (Transparent Tribe) cluster
   --------------------------------------------------------------------
   Source: Acronis Threat Research Unit (TRU), 2026-08-13 —
   "PATCHCORD: New malware cluster targets Afghan telecom and South Asian
   critical infrastructure."

   Campaign: APT36 (Transparent Tribe, Pakistan-nexus) targeting Afghan telecom
   (Afghan Telecom/AFTEL, Salaam Telecom) and South Asian critical infrastructure.
   Delivery = fake VPN / telecom-tool lures in Inno Setup (v6.7.0, 32-bit)
   installers:
     TMS_AfghanTelecom.exe, Bonus_Salaam_telecom.zip,
     "Ministry of Communication & Information Technology.msi", MCIT.pdf (decoy).
   PATCHCORD  = C/C++ implant; beacons via InternetOpenW with UA "Beacon/1.0.0".
   SHEETCORD  = Go implant; C2 over Google Sheets; persists as
                %APPDATA%\...\Startup\SystemHelper.vbs.
   HACKERAI C2 Agent = Go; C2 over GitHub Gists.
   Operator toolkit also seen: Antnium (Go C2), GateSentinel-C2-Rat-Hvnc,
   Metasploit, HackBrowserData, CVE-2024-6387 (regreSSHion) exploit tooling.
   C2: 108.187.42.63, 46.30.188.13.

   "Beacon/1.0.0" is a generic-looking user-agent, so rule 1 NEVER fires on the
   UA alone — it is always co-occurrence-guarded by a campaign/telecom token or a
   hard C2 IP. Rule 2 keys on the distinctive lure/persistence file names (>=2).
   Rule 3 pins the report's SHA-256 samples.

   Rule shape:
     (1) PATCHCORD_Beacon            — behavioural/critical: PE + "Beacon/1.0.0"
         UA co-occurring with a campaign token or C2 IP
     (2) PATCHCORD_Campaign_Artifacts— high: >=2 distinctive lure/persistence
         names (Afghan-telecom installers, SystemHelper.vbs, GateSentinel dir)
     (3) PATCHCORD_Samples           — specimen-pin/critical: report SHA-256 set
         (validate by construction; do NOT corpus-sweep a pure hash rule)

   Attribution: APT36 / Transparent Tribe (state-nexus espionage, Pakistan).
   Related: no prior APT36 family in this repo; filed with digest
   2026-08-14-clop-windchill-leak-wave-patchcord-apt36.
*/

import "hash"

private rule patchcord_is_pe {
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule PATCHCORD_Beacon {
    meta:
        description = "PATCHCORD implant — Beacon/1.0.0 UA guarded by APT36 campaign token or C2 IP"
        author = "synthetic-detections"
        date = "2026-08-14"
        severity = "critical"
        family = "patchcord-apt36"
        reference = "https://www.acronis.com/en/tru/posts/patchcord-new-malware-cluster-targets-afghan-telecom-and-south-asian-critical-infrastructure/"
    strings:
        $ua    = "Beacon/1.0.0" ascii wide
        $camp1 = "TMS_AfghanTelecom" ascii wide nocase
        $camp2 = "Salaam_telecom" ascii wide nocase
        $camp3 = "SystemHelper.vbs" ascii wide nocase
        $camp4 = "AFTEL" ascii wide
        $c2a   = "108.187.42.63" ascii wide
        $c2b   = "46.30.188.13" ascii wide
    condition:
        patchcord_is_pe and $ua and 1 of ($camp*, $c2*)
}

rule PATCHCORD_Campaign_Artifacts {
    meta:
        description = "APT36 PATCHCORD/SHEETCORD campaign — distinctive lure/persistence file names (>=2)"
        author = "synthetic-detections"
        date = "2026-08-14"
        severity = "high"
        family = "patchcord-apt36"
        reference = "https://www.acronis.com/en/tru/posts/patchcord-new-malware-cluster-targets-afghan-telecom-and-south-asian-critical-infrastructure/"
    strings:
        $f1 = "TMS_AfghanTelecom.exe" ascii wide nocase
        $f2 = "Bonus_Salaam_telecom.zip" ascii wide nocase
        $f3 = "Ministry of Communication & Information Technology.msi" ascii wide nocase
        $f4 = "MCIT.pdf" ascii wide nocase
        $f5 = "SystemHelper.vbs" ascii wide nocase
        $f6 = "GateSentinel-C2-Rat-Hvnc" ascii wide nocase
    condition:
        filesize < 40MB and 2 of ($f*)
}

rule PATCHCORD_Samples {
    meta:
        description = "PATCHCORD/SHEETCORD/HACKERAI — Acronis TRU SHA-256 sample pins"
        author = "synthetic-detections"
        date = "2026-08-14"
        severity = "critical"
        family = "patchcord-apt36"
        reference = "https://www.acronis.com/en/tru/posts/patchcord-new-malware-cluster-targets-afghan-telecom-and-south-asian-critical-infrastructure/"
    condition:
        filesize < 80MB and (
            hash.sha256(0, filesize) == "0f4073d3c866bc3daf55b25f71250b96ec120db94a4f9cc8fe85b7c9f9d346b3" or
            hash.sha256(0, filesize) == "1774e15e8eb96eb89bc03cb4768fc0620e10c09c5f795297f36dcc2aa5d9dd94" or
            hash.sha256(0, filesize) == "2323b55ea743c813e48689318e8ed54ae838cf9e8a2adbfc2488ea8a36dd0126" or
            hash.sha256(0, filesize) == "2eddfebb3f7419af27493a6a3bb601372cf6c494da8df62640cce7f830b4a73b" or
            hash.sha256(0, filesize) == "378484112b4e837d3850b5b0802fc509202c232bb124d6944a59fe66525ba668" or
            hash.sha256(0, filesize) == "50fc220347f9e281037e831c3755dc70a8ba7f663025aea35b301226918b016b" or
            hash.sha256(0, filesize) == "5e17360d32e9b272bb7e1b97c8e4dca34622ec9ce08fd240fe2758cc3f67dc4a" or
            hash.sha256(0, filesize) == "74d347785dc47f8cda3876826cdd3fb3935ac55dc8e9e0c0f96d5ef4e00089a2" or
            hash.sha256(0, filesize) == "959bbb09cd86ce3930406bf1cf32776ca477dfefe3fd63e90bf0017fccd90587" or
            hash.sha256(0, filesize) == "b56fab5a6834c51d85787e7c1177720dfba5a5823763f3fcf432196cd2a1bdf3" or
            hash.sha256(0, filesize) == "cf7184c0dfe882dc6e3016f16e4ede32b75d7648f83d6f4f87eb6a703be7b8d6" or
            hash.sha256(0, filesize) == "d46ee94d6a27ff9f02cff6fb57780acac2833ce48c95e63042a6274e24a040bb" or
            hash.sha256(0, filesize) == "ea0934472121848b80455581d289ce4480b1e5cc05678c1b90ecfc465b5ec350"
        )
}
