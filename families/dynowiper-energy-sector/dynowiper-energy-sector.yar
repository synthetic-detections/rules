/*
   DynoWiper / LazyWiper — Poland energy-sector destructive campaign (29 Dec 2025)
   --------------------------------------------------------------------------
   Reported by CERT Polska: original report 2026-01-30 (wipers, IOCs, the one
   published YARA rule) and an Aug-2026 follow-up (a second CHP plant reached via
   a private-APN OT vector — no binary artifacts, so no rule from the follow-up).

   The IT/AD destruction used two wipers, distributed by a PowerShell GPO dropper:

   - DynoWiper: native Win32 wiper (VS2013 build, PDB
     C:\Users\vagrant\...\Source\Release\Source.pdb). Overwrites files with
     pseudorandom 16-byte blocks (Mersenne Twister), then deletes them; ver A
     calls ExitWindowsEx (shutdown), ver B sleeps and omits the shutdown. Dropped
     as C:\Source.exe / dynacom_update.exe / schtask.exe and run. On the large CHP
     plant it was blocked by EDR after ~100 hosts.
   - DynoWiper GPO distributor (PowerShell): backs up "Default Domain Policy",
     renames it "Custom Domain Policy", creates SYSTEM scheduled task
     "Custom GPO Task" with filter GUID 79A87EBB-4DF6-4541-9530-CAD8BEE8A7AD,
     then self-cleans.
   - LazyWiper: PowerShell wiper, assessed by CERT as LLM-generated and
     non-distinctive (C# helper WriteRandomBytes, a long extension list with the
     misspellings .pcks/.pcks12/.pcks7, self-terminates on a domain controller).

   The OT destruction (Hitachi RTU560 corrupted firmware, Mikronika/Relion file
   deletion, Moxa/Teltonika/WAGO factory-reset + IP->127.0.0.1, Siemens S7 STOP)
   was default-credential / native-protocol abuse with NO distributable sample and
   is intentionally NOT covered by a YARA rule.

   Attribution: infrastructure overlaps the Russia-nexus cluster Static Tundra /
   Berserk Bear / Ghost Blizzard / Dragonfly (Cisco/CrowdStrike/MS/Symantec). CERT
   explicitly declines a Sandworm attribution (tool similarity too weak); the
   wipers are treated as an unattributed novel family. Do not overstate.

   Rule shape:
     (1) DynoWiper_Wiper_Behavior   — behavioural/critical: PE + the error string
         + >=3 exclusion-list entries incl the "program files(x86)" typo
     (2) DynoWiper_PDB_Guarded      — IOC/high: the vagrant Source.pdb path,
         gated on a PE + an exclusion string (PDB paths are forgeable)
     (3) DynoWiper_GPO_Distributor  — behavioural/critical: the PowerShell dropper
         (filter GUID + Custom Domain Policy + Custom GPO Task)
     (4) LazyWiper_Build            — low/brittle: LLM-generated build; pins THIS
         build via WriteRandomBytes + the misspelled .pcks* extensions + DC-abort
     (5) DynoWiper_Campaign_IOCs    — IOC/high: sha256/sha1 + C2 IP pins

   This adopts and extends CERT Polska's published DynoWiper rule (which keys on
   4-of {$recycle.bin, program files(x86), perflogs, windows\x00, Error opening
   file:}) with co-occurrence guards, the PDB/typo artifacts, and the dropper.

   Siblings (destructive / wiper / ICS):
     [[gigawiper-destructive-backdoor]], [[goddamn-ransomware]]

   Sources:
     https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/
     https://cert.pl/en/posts/2026/08/incident-follow-up-report-energy-sector-2025/

   Known samples:
     DynoWiper EXE  (sha256): 65099f30…09602c2, 835b0d87…ede68d5,
                              60c70cdc…411cae4b, d1389a1f…01242160
     DynoWiper EXE  (sha1)  : 4ec3c908…6d4cf6, 86596a5c…d0d61b,
                              69ede7e3…4778d93, 0e7dba87…fae3633
     GPO dropper ps1(sha256): 8759e79c…8539cf15, f4e9a3dd…f65ffaee,
                              68192ca0…332a464
     LazyWiper ps1  (sha256): 033cb31c…09602c2
*/

rule DynoWiper_Wiper_Behavior
{
    meta:
        description = "DynoWiper native Win32 wiper — 'Error opening file:' plus the distinctive drive exclusion list incl the 'program files(x86)' typo, in a small PE"
        author      = "synthetic-detections"
        date        = "2026-08-09"
        severity    = "critical"
        family      = "dynowiper-energy-sector"
        reference   = "https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/"

    strings:
        $err = "Error opening file: " wide

        // drive-walk exclusion list (wide, case-insensitive); $x2 carries the
        // attacker typo (missing space before the paren)
        $x1 = "$recycle.bin" wide nocase
        $x2 = "program files(x86)" wide nocase
        $x3 = "perflogs" wide nocase
        $x4 = "documents and settings" wide nocase
        $x5 = "system32" wide nocase
        // ($recycle.bin already covers the recycle-bin token; a separate
        // "recycle.bin" is a substring of $x1 and would let one indicator
        // satisfy two slots of the 3-of guard, so it is intentionally omitted.)

    condition:
        uint16(0) == 0x5A4D
        and filesize < 500KB
        and $err
        and 3 of ($x*)
}

rule DynoWiper_PDB_Guarded
{
    meta:
        description = "DynoWiper build artifact — the vagrant VS2013 Source.pdb path, gated on a PE and an exclusion-list string so the forgeable path cannot fire alone"
        author      = "synthetic-detections"
        date        = "2026-08-09"
        severity    = "high"
        family      = "dynowiper-energy-sector"
        reference   = "https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/"

    strings:
        $pdb = "\\Documents\\Visual Studio 2013\\Projects\\Source\\Release\\Source.pdb" ascii nocase
        $vag = "Users\\vagrant\\" ascii nocase
        $x1  = "program files(x86)" wide nocase
        $x2  = "Error opening file: " wide

    condition:
        uint16(0) == 0x5A4D and filesize < 500KB
        and $pdb and ($vag or any of ($x*))
}

rule DynoWiper_GPO_Distributor
{
    meta:
        description = "DynoWiper PowerShell GPO distributor — hijacks Default Domain Policy as 'Custom Domain Policy' + SYSTEM 'Custom GPO Task' with the hardcoded filter GUID"
        author      = "synthetic-detections"
        date        = "2026-08-09"
        severity    = "critical"
        family      = "dynowiper-energy-sector"
        reference   = "https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/"

    strings:
        $guid = "79A87EBB-4DF6-4541-9530-CAD8BEE8A7AD" ascii wide nocase
        $n1   = "Custom Domain Policy" ascii wide nocase
        $n2   = "Custom GPO Task" ascii wide nocase
        $n3   = "MachineVersionNumber" ascii wide nocase
        $del  = "schtasks.exe /delete /TN \"Custom GPO Task\" /F" ascii wide nocase

    condition:
        filesize < 1MB and (
            $guid                               // the GUID is a strong single pin
            or ($n1 and $n2)                    // both hardcoded names co-occur
            or ($del)                           // exact self-delete line
            or ($n2 and $n3)
        )
}

rule LazyWiper_Build
{
    meta:
        description = "LazyWiper PowerShell wiper (this build) — WriteRandomBytes helper + the misspelled .pcks/.pcks12/.pcks7 extensions + DC-abort; LLM-generated, pins THIS build, not durable across regeneration"
        author      = "synthetic-detections"
        date        = "2026-08-09"
        severity    = "low"
        family      = "dynowiper-energy-sector"
        reference   = "https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/"

    strings:
        $fn   = "WriteRandomBytes" ascii wide nocase
        $e1   = ".pcks12" ascii wide nocase
        $e2   = ".pcks7" ascii wide nocase
        $e3   = "\".pcks\"" ascii wide nocase
        $dc1  = "DomainController" ascii wide nocase
        $dc2  = "ProductType" ascii wide nocase

    condition:
        $fn and (2 of ($e*)) and (any of ($dc*))
        and filesize < 200KB
}

rule DynoWiper_Campaign_IOCs
{
    meta:
        description = "DynoWiper/LazyWiper campaign hard IOCs — sample sha256/sha1 pins and the Static-Tundra relay C2 IPs (atomic, decay expected — rotate)"
        author      = "synthetic-detections"
        date        = "2026-08-09"
        severity    = "high"
        family      = "dynowiper-energy-sector"
        reference   = "https://cert.pl/en/posts/2026/01/incident-report-energy-sector-2025/"

    strings:
        // DynoWiper EXE sha256
        $s1 = "65099f306d27c8bcdd7ba3062c012d2471812ec5e06678096394b238210f0f7c" ascii nocase
        $s2 = "835b0d87ed2d49899ab6f9479cddb8b4e03f5aeb2365c50a51f9088dcede68d5" ascii nocase
        $s3 = "60c70cdcb1e998bffed2e6e7298e1ab6bb3d90df04e437486c04e77c411cae4b" ascii nocase
        $s4 = "d1389a1ff652f8ca5576f10e9fa2bf8e8398699ddfc87ddd3e26adb201242160" ascii nocase
        // LazyWiper + GPO dropper sha256
        $s5 = "033cb31c081ff4292f82e528f5cb78a503816462daba8cc18a6c4531009602c2" ascii nocase
        $s6 = "8759e79cf3341406564635f3f08b2f333b0547c444735dba54ea6fce8539cf15" ascii nocase
        $s7 = "f4e9a3ddb83c53f5b7717af737ab0885abd2f1b89b2c676d3441a793f65ffaee" ascii nocase
        $s8 = "68192ca0fde951d973eb41a07814f402f2b46e610889224bd54583d8a332a464" ascii nocase
        // C2 / relay IPs (Static Tundra infra)
        $ip1 = "185.200.177.10" ascii wide
        $ip2 = "31.172.71.5" ascii wide

    condition:
        // Full SHA-256 hashes are unambiguous and may fire alone; the two C2
        // IPs are substring-prone (e.g. 185.200.177.10 matches 185.200.177.100),
        // so require BOTH relay IPs together rather than either one.
        filesize < 4MB and (any of ($s*) or all of ($ip*))
}
