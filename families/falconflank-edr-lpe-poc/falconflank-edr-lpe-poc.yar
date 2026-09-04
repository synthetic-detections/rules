/*
   FALCONFLANK -- CrowdStrike Falcon LPE PoC (Nightmare Eclipse / MSNightmare)
   (released 2026-09-03; uncoordinated public 0-day PoC)
   -----------------------------------------------------------------------
   Public C++ proof-of-concept that escalates from a low-privileged local
   user to SYSTEM by abusing CrowdStrike Falcon's "Microsoft Office file
   malicious macro removal" feature (a high-privilege remediation action).
   The PoC uses an oplock + filesystem-reparse (mount-point) race to redirect
   Falcon's privileged file write to a planted bcrypt.dll under the
   PowerShell v1.0 directory (DLL-search-order/planting), then triggers the
   "MareBackup" Application-Experience scheduled task to load it.

   Author aliases: Nightmare Eclipse / Chaotic Eclipse / Infinite Nightmare /
   MSNightmare. Same actor released, in the same wave:
     HardBreacher  -- Kaspersky Endpoint Security LPE (System32 DLL write)
     PrettyPrague  -- Avast/Gen Digital LPE, dumps SAM
     GreenSection  -- Nvidia driver memory-corruption crash
   As of 2026-09-03 CrowdStrike had not confirmed the flaw, assigned a CVE,
   or shipped a fix; mitigation is to disable the macro-removal policy.

   These rules detect the PUBLIC PoC binary/source (red-team + hunt for the
   dropped exploit), NOT the Falcon product. The distinctive named-pipe,
   planted-DLL path, and task-abuse strings are the anchors.

   Rule 1 -- Behaviour/source: exploit-specific strings co-occurring.
   Rule 2 -- IOC: PoC filenames + named pipe + Flanker marker.
   Rule 3 -- Specimen pin: compiled PoC SHA-256 (added once a sample lands).

   Sources:
     https://www.theregister.com/security/2026/09/03/prolific-microsoft-0-day-hunter-drops-crowdstrike-falcon-exploit-poc/5294318
     https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html
     https://www.securityweek.com/nightmare-eclipse-drops-hardbreacher-kaspersky-product-exploit/
   Related families in this repo:
     [[gentlekiller-edr-killer]]  -- other EDR-tamper tooling.
*/

import "hash"

rule FalconFlank_EDR_LPE_PoC_Behaviour
{
    meta:
        description = "FalconFlank CrowdStrike Falcon LPE PoC -- FALCONFLANK named pipe + planted PowerShell bcrypt.dll + MareBackup task-abuse + oplock/reparse race strings"
        author      = "synthetic-detections"
        date        = "2026-09-04"
        severity    = "critical"
        family      = "falconflank-edr-lpe-poc"
        reference   = "https://thehackernews.com/2026/09/researcher-releases-falconflank-poc.html"

    strings:
        $pipe   = "\\??\\pipe\\FALCONFLANK" ascii wide
        $dll    = "\\WindowsPowerShell\\v1.0\\bcrypt.dll" ascii wide
        $flank  = "Flanker_" ascii wide
        $task   = "\\Microsoft\\Windows\\Application Experience" ascii wide
        $mare   = "MareBackup" ascii wide
        $m1     = "Exploit succeeded, loading dll, please wait" ascii wide
        $m2     = "Failed to create oplock, error" ascii wide
        $m3     = "creating system32 directory" ascii wide
        $m4     = "Failed to connect to task scheduler service" ascii wide

    condition:
        $pipe
        or ($dll and $mare)
        or (2 of ($flank, $task, $m1, $m2, $m3, $m4))
}

rule FalconFlank_EDR_LPE_PoC_IOC
{
    meta:
        description = "FalconFlank PoC repository artifacts (MSNightmare / Nightmare Eclipse) -- project filenames and unique markers"
        author      = "synthetic-detections"
        date        = "2026-09-04"
        severity    = "high"
        family      = "falconflank-edr-lpe-poc"
        reference   = "https://www.theregister.com/security/2026/09/03/prolific-microsoft-0-day-hunter-drops-crowdstrike-falcon-exploit-poc/5294318"

    strings:
        $f1 = "FalconFlank.cpp" ascii wide
        $f2 = "FalconFlank.sln" ascii wide
        $f3 = "FalconFlank.vcxproj" ascii wide
        $n1 = "FALCONFLANK" ascii wide
        $n2 = "Flanker_" ascii wide

    condition:
        any of ($f1, $f2, $f3) or all of ($n1, $n2)
}

rule FalconFlank_EDR_LPE_PoC_Pin
{
    meta:
        description = "Hash pin for the compiled FalconFlank PoC binary (SHA-256) -- populate when a sample is captured"
        author      = "synthetic-detections"
        date        = "2026-09-04"
        severity    = "critical"
        family      = "falconflank-edr-lpe-poc"
        reference   = "https://github.com/MSNightmare/FalconFlank"

    condition:
        // placeholder pin (never matches) until the compiled PoC is hashed
        hash.sha256(0, filesize) == "0000000000000000000000000000000000000000000000000000000000000000"
}
