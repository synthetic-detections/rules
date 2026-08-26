/*
   SLEEPWALKER — passive Windows backdoor with a custom command language
   ---------------------------------------------------------------------
   Source: Dominik Reichel (r136a1), "SLEEPWALKER: A Passive Backdoor With Its
   Own Command Language" (2026-08-24); corroborated by The Register (2026-08-24)
   and SC Media. Previously-undocumented, currently UNATTRIBUTED.

   Tradecraft: a malicious dpapi.dll (spoofing seven DPAPI exports) is side-loaded
   into ESET's Management Agent (ERAAgent.exe) — it checks only the host PROCESS
   NAME, not signature/path. No C2 domain/IP, no listening port, no embedded
   payload: it sits dormant in memory and passively sniffs for a "magic packet"
   (min 48 bytes, length obfuscation XORing trailing 16-bit values vs 0xAAAA, then
   a CRC-32 check) which unwraps an AES-256-CCM bytecode program in a 23-instruction
   command language. It also weakens the host (Lsa\EveryoneIncludesAnonymous=1,
   an extra LanmanServer NullSessionPipes entry) and references a non-existent
   dpapisvc.dll.

   Because the seven DPAPI export names also appear in the LEGITIMATE dpapi.dll,
   rule 1 is always co-occurrence-guarded with the ESET-host / dpapisvc marker so a
   genuine dpapi.dll never fires. Rule 3 pins the sample's embedded AES-256-CCM key
   and config nonce (unique byte sequences).

   Rule shape:
     (1) SLEEPWALKER_ESET_Sideload  — critical/behavioural: PE + >=3 spoofed DPAPI
         exports + (ERAAgent.exe | dpapisvc.dll) host marker
     (2) SLEEPWALKER_Host_Weakening — high/behavioural: anonymous-access registry
         weakening co-occurring with the host markers
     (3) SLEEPWALKER_Crypto_Pin     — critical/specimen-pin: embedded AES-256-CCM
         key / config-nonce byte sequences

   File-hash IOC (tracked in the digest hash store):
     SHA-256 d347170752a28e2b8c4b8b9f3cab2e3a6541ba11682c94498d26eb9002779d60
     (59,904 bytes, imphash 4e2dbfa7e3efd4cca2f3662797df9735), not on MalShare 2026-08-26.

   Related: [[amazon-q-mcp-autoexec-cve-2026-12957]] (living-off-trusted-software),
   [[gunra-ransomware]] (same digest cadence).
*/

private rule sleepwalker_is_pe {
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and filesize < 8MB
}

rule SLEEPWALKER_ESET_Sideload {
    meta:
        description = "SLEEPWALKER dpapi.dll side-load into ESET ERAAgent — spoofed DPAPI exports + ESET/dpapisvc host marker"
        author = "synthetic-detections"
        date = "2026-08-26"
        severity = "critical"
        family = "sleepwalker-backdoor"
        reference = "https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/"
    strings:
        $x1 = "CryptProtectDataNoUI" ascii
        $x2 = "CryptProtectMemory" ascii
        $x3 = "CryptResetMachineCredentials" ascii
        $x4 = "CryptUnprotectDataNoUI" ascii
        $x5 = "CryptUnprotectMemory" ascii
        $x6 = "CryptUpdateProtectedState" ascii
        $x7 = "iCryptIdentifyProtection" ascii
        $host1 = "ERAAgent.exe" ascii wide nocase
        $host2 = "dpapisvc.dll" ascii wide nocase
    condition:
        sleepwalker_is_pe and filesize < 8MB and 3 of ($x*) and any of ($host*)
}

rule SLEEPWALKER_Host_Weakening {
    meta:
        description = "SLEEPWALKER host weakening — anonymous-access registry changes co-occurring with ESET/dpapisvc host markers"
        author = "synthetic-detections"
        date = "2026-08-26"
        severity = "high"
        family = "sleepwalker-backdoor"
        reference = "https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/"
    strings:
        $r1 = "EveryoneIncludesAnonymous" ascii wide
        $r2 = "NullSessionPipes" ascii wide
        $h1 = "ERAAgent.exe" ascii wide nocase
        $h2 = "dpapisvc.dll" ascii wide nocase
    condition:
        sleepwalker_is_pe and filesize < 8MB and $r1 and $r2 and any of ($h*)
}

rule SLEEPWALKER_Crypto_Pin {
    meta:
        description = "SLEEPWALKER embedded AES-256-CCM key / config nonce (specimen pin)"
        author = "synthetic-detections"
        date = "2026-08-26"
        severity = "critical"
        family = "sleepwalker-backdoor"
        reference = "https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/"
    strings:
        $key   = { 74 65 31 ff 37 8d bb 4b b5 1d 2a a2 b1 d3 8d 90 53 50 a9 59 58 31 86 ba f4 c6 90 f5 f3 16 b3 ae }
        $nonce = { 3a 6d 35 7f b9 bc 51 ea cc 8b 85 09 }
    condition:
        filesize < 8MB and any of them
}
