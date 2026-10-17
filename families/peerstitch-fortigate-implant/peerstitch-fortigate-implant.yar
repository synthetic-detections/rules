// peerstitch-fortigate-implant.yar
// --------------------------------------------------------------------------
// PEERSTITCH — a stealthy, memory-resident ARM64 implant for FortiGate
// appliances (Palo Alto Unit 42 cluster CL-STA-0954 / Mandiant UNC5820,
// suspected nation-state overlap). Operators chain CVE-2024-47575
// (FortiManager "FortiJump") to steal configs/keys for 500+ managed
// FortiGates, then CVE-2025-61624 (FortiOS auto-script path traversal) to
// deploy the implant. PEERSTITCH is a one-shot process-memory-patching
// injector against the FortiOS daemons /bin/miglogd and /bin/iked: it keeps
// no on-disk binary, opens no listening port, and makes no outbound
// connection, instead riding traffic from legitimate host processes. It is
// staged through an Emscripten/WebAssembly + Node.js orchestrator
// (pM.js -> ipssem.js / index.wasm) pulled from an attacker ACME-mimicking
// HTTP service.
//
// [[sibling]] fortigatesniffer-credential-harvester
// [[sibling]] fortisandbox-jsonrpc-cve-2026-39813
//
// References:
//   https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware.md
//   https://securityonline.info/fortios-peerstitch-malware-fortimanager/
// --------------------------------------------------------------------------

import "hash"

rule PEERSTITCH_Behavioural : implant peerstitch
{
    meta:
        description = "Detects the PEERSTITCH ARM64 FortiOS in-memory injector by its process-patching routine and daemon targeting"
        author      = "synthetic-detections"
        date        = "2026-10-17"
        severity    = "critical"
        family      = "peerstitch-fortigate-implant"
        reference   = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware.md"
    strings:
        // ARM64 mmap(RWX) shellcode bootstrap template
        $mmap_tmpl    = { 00 00 80 D2 01 00 88 D2 E2 00 80 D2 43 04 80 D2 04 00 80 D2 05 00 80 D2 C8 1B 80 D2 01 00 00 D4 01 84 BA 52 01 00 00 B9 00 00 1F D6 }
        // injection entry prologue (ADR + LDR + BLR, then stack setup)
        $inj_prologue = { 1E 00 00 10 DE C3 40 F8 C0 03 1F D6 }
        // NOP patch word written over daemon call sites (MOV X0, X0 -> 0xAA0003E0, LE)
        $nop_patch    = { E0 03 00 AA }
        // injected FortiOS daemons + process memory write path
        $miglogd      = "/bin/miglogd"
        $iked         = "/bin/iked"
        $procmem      = "/proc/%d/mem"
    condition:
        // ELF
        // EM_AARCH64
        uint32(0) == 0x464c457f
        and uint16(18) == 183
        and (
            ($procmem and ($miglogd or $iked) and ($mmap_tmpl or $inj_prologue)) or
            ($mmap_tmpl and $inj_prologue and $nop_patch) or
            ($procmem and $mmap_tmpl and $nop_patch)
        )
        and filesize < 30MB
}

rule PEERSTITCH_IOC : implant peerstitch
{
    meta:
        description = "Detects PEERSTITCH implant + stager artifacts by co-occurring IOC strings (daemon targets, ACME cover file, staging, stager filenames, C2)"
        author      = "synthetic-detections"
        date        = "2026-10-17"
        severity    = "high"
        family      = "peerstitch-fortigate-implant"
        reference   = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware.md"
    strings:
        $cover_path = "/tmp/apache2/conf/md-acme.conf"
        $cover_body = "#0 certs managed by ACME"
        $stage_dir  = "/data2/template/"
        $trav1      = "../../../../setup"
        $trav2      = "../../tmp/apache2/conf/md-acme.conf"
        $daemon1    = "/bin/miglogd"
        $daemon2    = "/bin/iked"
        // stager filenames (Emscripten/WASM + Node.js orchestrator)
        $f_pmjs     = "pM.js"
        $f_ipssem   = "ipssem.js"
        $f_lldprx   = "lldprx"
        // attacker IPs (installer / malware host + rogue FortiManager entries)
        $c2_1       = "23.240.77.233"
        $c2_2       = "47.18.167.159"
        $c2_3       = "45.32.41.202"
        $c2_4       = "198.199.122.22"
    condition:
        (
            ($cover_path and $cover_body) or
            ($cover_path and any of ($daemon*)) or
            (any of ($trav*) and $cover_path) or
            ($stage_dir and any of ($f_*) and any of ($daemon*)) or
            (2 of ($f_*) and any of ($c2_*)) or
            (2 of ($c2_*) and (any of ($daemon*) or $cover_path))
        )
        and filesize < 30MB
}

rule PEERSTITCH_Specimen : implant peerstitch
{
    meta:
        description = "Specimen pin for known PEERSTITCH implant + stager samples (Unit 42, 2026-10-14)"
        author      = "synthetic-detections"
        date        = "2026-10-17"
        severity    = "critical"
        family      = "peerstitch-fortigate-implant"
        reference   = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware.md"
    condition:
        filesize < 30MB
        and (
            hash.sha256(0, filesize) == "b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70" or
            hash.sha256(0, filesize) == "829b1cd270b30565739a478441833f49f10a49bd06f0d18cc96c8ae4a0431f11" or
            hash.sha256(0, filesize) == "bd064244dad748cf2a44074bee56f5bfab4a2b18ee944b75d1b3febd4c1fe02a" or
            hash.sha256(0, filesize) == "9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e" or
            hash.sha256(0, filesize) == "fc1b10c58057ef9f1f9a1e2a3d4a1c89f43b0ead451398c70ed7a6e0312b36ee" or
            hash.sha256(0, filesize) == "f84eea718526706afdf2d1a2774fab76ecb11c18fb61995a37be8249c5e379ab" or
            hash.sha256(0, filesize) == "b7ae166fd49a7ecfe6322a80b8aa56d6aa0825d8f5d106dab2e4fb7d14ce15a8"
        )
}
