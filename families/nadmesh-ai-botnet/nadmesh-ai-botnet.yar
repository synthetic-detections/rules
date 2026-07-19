/*
   NadMesh — AI/MCP-infrastructure-hunting Go botnet (QiAnXin XLab, 2026-07-17)
   ---------------------------------------------------------------------------
   Industrial-grade, Go-written botnet that folds scanning, exploitation and
   credential harvesting into a single closed-loop "mesh" platform. It weaponises
   20+ remote-code-execution vectors across 90+ cloud provider address ranges,
   targeting exposed Redis, Docker, Kubernetes/kubelet, etcd and MCP services,
   with a particular focus on AI platforms — ComfyUI, Ollama and Gradio — that it
   locates through the Shodan API. Post-exploitation it steals cloud access keys
   and Kubernetes ServiceAccount tokens (operator dashboard claimed 3,811 unique
   AWS keys). Builds use Garble obfuscation and UPX packing; persistence is
   redundant (SSH backdoors, agent processes, cron watchdogs). XLab named the
   family from the in-code control-layer marker "n4d mesh controller".

   Same XLab-tracked, AI-infra-hunting niche as the CAI / PCPJack cloud worms,
   but a separate Go family. See sibling [[rustduck-botnet]] (also XLab, Go/ELF
   botnet) for the shared Garble+UPX ELF tradecraft.

   Rules target unpacked / memory-scanned samples (Rules 1-2); UPX-packed builds
   will NOT match until unpacked or memory-scanned.

   Rule 1 — Behavioral (critical): the "n4d mesh" control marker co-occurring with
            AI-platform target names and exposed-service exploitation strings.
   Rule 2 — IOC (high): network IOCs (C2 IP, C2 domain) guarded by co-occurrence
            with a family/Go-mesh marker to suppress FPs on shared infrastructure.
   Rule 3 — Specimen (critical): pins the XLab-published agent sample by its
            distinctive string set + size; hash recorded in meta.

   Sources:
     https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html
     https://gbhackers.com/new-nadmesh-botnet/
     https://cyberpress.org/nadmesh-targets-ai-servers/
*/

rule NadMesh_Botnet_Behavior
{
    meta:
        description = "NadMesh Go botnet — n4d-mesh control marker co-occurring with AI-platform targeting and exposed-service RCE (post-unpack / memory)"
        author      = "synthetic-detections"
        date        = "2026-07-19"
        severity    = "critical"
        family      = "nadmesh-ai-botnet"
        reference   = "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"

    strings:
        // Control-layer marker the family is named after
        $marker1 = "n4d mesh controller" ascii nocase
        $marker2 = "n4d mesh" ascii nocase
        $marker3 = "nadmesh" ascii nocase

        // AI / MCP platform targets discovered via Shodan
        $ai_comfy  = "ComfyUI" ascii nocase
        $ai_ollama = "ollama" ascii nocase
        $ai_gradio = "Gradio" ascii nocase
        $ai_mcp    = "mcp" ascii fullword nocase
        $ai_shodan = "shodan" ascii nocase

        // Exposed-service exploitation surface
        $svc_redis   = "redis" ascii nocase
        $svc_docker  = "/v1.24/containers" ascii
        $svc_kubelet = "kubelet" ascii nocase
        $svc_k8s     = "serviceaccount/token" ascii nocase
        $svc_etcd    = "etcd" ascii nocase

    condition:
        // the distinctive mesh marker plus real targeting/exploitation context
        (any of ($marker*))
        and 2 of ($ai_*)
        and 2 of ($svc_*)
        and filesize < 40MB
}

rule NadMesh_IOC
{
    meta:
        description = "NadMesh network IOCs (XLab): C2 IP / domain, guarded by co-occurrence with a family or Go-mesh marker"
        author      = "synthetic-detections"
        date        = "2026-07-19"
        severity    = "high"
        family      = "nadmesh-ai-botnet"
        reference   = "https://gbhackers.com/new-nadmesh-botnet/"

    strings:
        $c2_ip     = "209.99.186.235" ascii
        $c2_domain = "cdnorigin.net" ascii nocase

        // co-occurrence guards (suppress FP on shared/benign infra references)
        $g_marker1 = "n4d mesh" ascii nocase
        $g_marker2 = "nadmesh" ascii nocase
        $g_ai      = "ComfyUI" ascii nocase
        $g_shodan  = "shodan" ascii nocase

    condition:
        (any of ($c2_*)) and (any of ($g_*)) and filesize < 40MB
}

rule NadMesh_Agent_Specimen
{
    meta:
        description = "NadMesh — pins the XLab-published agent sample by distinctive string set + size"
        author      = "synthetic-detections"
        date        = "2026-07-19"
        severity    = "critical"
        family      = "nadmesh-ai-botnet"
        reference   = "https://thehackernews.com/2026/07/new-nadmesh-botnet-hunts-exposed-ai.html"
        hash        = "31c69b3e12936abca770d430066f379ec1d997ec"

    strings:
        $s1 = "n4d mesh controller" ascii nocase
        $s2 = "ComfyUI" ascii nocase
        $s3 = "ollama" ascii nocase
        $s4 = "shodan" ascii nocase
        $s5 = "cdnorigin.net" ascii nocase

    condition:
        3 of them and filesize < 40MB
}
