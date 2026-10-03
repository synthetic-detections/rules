/*
   APT28 PROMPTSTEAL / LAMEHUG -- LLM-driven data miner
   =====================================================
   APT28 (GRU Unit 26165, FROZENLAKE, UAC-0001) malware that queries
   Qwen2.5-Coder-32B-Instruct via the Hugging Face Inference API to
   generate one-line Windows commands at runtime. First documented by
   Google GTIG (November 2025) as "the first malware querying an LLM
   deployed in live operations." CERT-UA independently tracks it as
   LAMEHUG (advisory #16039, July 2025).

   Two known versions:
     v1 (image.py / Dodatok.pif): plaintext prompts, SFTP exfil via paramiko
     v2 (AI_generator*.exe): base64-encoded prompts, HTTP POST exfil

   Both versions are PyInstaller-packaged Python targeting Windows.

   Three rules:
     1. APT28_PROMPTSTEAL_LLM_Behavior
        Behavioural -- co-occurrence of Hugging Face LLM API query
        strings with local staging directory. Catches both v1 and v2.

     2. APT28_PROMPTSTEAL_IOCs
        IOC -- C2 domains, IPs, exfil endpoints, delivery filenames.
        Will fire on threat-intel docs containing these strings.

     3. APT28_PROMPTSTEAL_Script_Shape
        Structural -- PROMPTSTEAL-unique function names (LLM_QUERY_EX,
        xlsx_open, query_image) in raw Python or PyInstaller PE.

   Author: synthetic-detections, 2026-06-16
   Sources:
     GTIG: https://services.google.com/fh/files/misc/advances-in-threat-actor-usage-of-ai-tools-en.pdf
     CERT-UA #16039: https://cert.gov.ua/article/6284730
     Cato CTRL: https://www.catonetworks.com/blog/cato-ctrl-threat-research-analyzing-lamehug/
     ThreatLocker: https://www.threatlocker.com/blog/what-is-lamehug-how-apt28-is-using-llms-to-generate-attack-commands
     SentinelOne: https://www.sentinelone.com/labs/prompts-as-code-embedded-keys-the-hunt-for-llm-enabled-malware/
   Sample hashes:
     766c356d6a4b00078a0293460c5967764fcd788da8c1cd1df708695f3a15b777 (Dodatok.pif, v1)
     d6af1c9f5ce407e53ec73c8e7187ed804fb4f80cf8dbd6722fc69e15e135db2e (AI_generator v0.9, v2)
     bdb33bbb4ea11884b15f67e5c974136e6294aa87459cdc276ac2eea85b1deaa3 (AI_image_generator v0.95, v2)
     384e8f3d300205546fb8c9b9224011b3b3cb71adc994180ff55e1e6416f65715 (image.py, v1)
*/

rule APT28_PROMPTSTEAL_LLM_Behavior
{
    meta:
        description = "PROMPTSTEAL runtime LLM query pattern -- Hugging Face API + Qwen model + staging directory co-occurrence"
        author      = "synthetic-detections"
        date        = "2026-06-16"
        severity    = "critical"
        family      = "PROMPTSTEAL"
        reference   = "https://services.google.com/fh/files/misc/advances-in-threat-actor-usage-of-ai-tools-en.pdf"
    strings:
        // Hugging Face API endpoints used by PROMPTSTEAL
        $api_chat    = "hyperbolic/v1/chat/completions"
        $api_image   = "nebius/v1/images/generations"
        $api_host    = "router.huggingface.co"
        // Model identifier
        $model       = "Qwen2.5-Coder-32B-Instruct"
        // LLM payload role string
        $role        = "Windows systems administrator"
        // Prompt tail strings -- separate ascii and base64 variants because
        // YARA 4.5.2 treats `ascii base64` as "base64 of ascii input",
        // NOT "match either ascii or base64"
        $prompt_v1a  = "Return only commands, without markdown"
        $prompt_v1b  = "Return only command, without markdown"
        $prompt_v2a  = "Return only commands, without markdown" base64
        $prompt_v2b  = "Return only command, without markdown" base64
        // On-host staging directory (double-backslash for Python source,
        // single-backslash for compiled bytecode / PyInstaller)
        $staging_dbl = "Programdata\\\\info" nocase
        $staging_sgl = "Programdata\\info" nocase
    condition:
        2 of ($api_*, $model, $role) and any of ($staging_*, $prompt_*) and filesize < 10MB
}

rule APT28_PROMPTSTEAL_IOCs
{
    meta:
        description = "PROMPTSTEAL/LAMEHUG IOCs -- C2, exfil endpoints, delivery filenames"
        author      = "synthetic-detections"
        date        = "2026-06-16"
        severity    = "high"
        family      = "PROMPTSTEAL"
        hash1       = "766c356d6a4b00078a0293460c5967764fcd788da8c1cd1df708695f3a15b777"
        hash2       = "d6af1c9f5ce407e53ec73c8e7187ed804fb4f80cf8dbd6722fc69e15e135db2e"
        hash3       = "bdb33bbb4ea11884b15f67e5c974136e6294aa87459cdc276ac2eea85b1deaa3"
        hash4       = "384e8f3d300205546fb8c9b9224011b3b3cb71adc994180ff55e1e6416f65715"
    strings:
        // C2 / exfil -- HTTP POST (v2)
        $c2_domain = "stayathomeclasses.com" nocase
        $c2_path   = "/slpw/up.php"
        // C2 / exfil -- SFTP (v1)
        $sftp_ip   = "144.126.202.227"
        // Additional infrastructure
        $infra_ip  = "107.180.50.236"
        // Delivery filenames
        $fn_pif    = "Dodatok.pif" nocase
        $fn_gen09  = "AI_generator_uncensored_Canvas_PRO"
        $fn_gen095 = "AI_image_generator_v0.95"
        // Operator email (compromised sender)
        $email     = "boroda70@meta.ua" nocase
    condition:
        any of them and filesize < 50MB
}

rule APT28_PROMPTSTEAL_Script_Shape
{
    meta:
        description = "PROMPTSTEAL script structure -- PROMPTSTEAL-unique function names in raw Python or PyInstaller PE"
        author      = "synthetic-detections"
        date        = "2026-06-16"
        severity    = "critical"
        family      = "PROMPTSTEAL"
        reference   = "https://cert.gov.ua/article/6284730"
    strings:
        // PROMPTSTEAL-unique function/variable names (survive in both
        // raw .py source and PyInstaller-embedded bytecode)
        $fn_llm     = "LLM_QUERY_EX"
        $fn_xlsx    = "xlsx_open"
        $fn_qimage  = "query_image"
        $fn_sshsend = "ssh_send"
        $var_xlsxb  = "xlsx_base"
        $var_imgapi = "Image_API_URL"
        // Threading pattern
        $thread_llm = "llm_query_thread"
        $thread_img = "image_thread"
    condition:
        $fn_llm
        and any of ($fn_xlsx, $fn_qimage, $fn_sshsend, $var_*, $thread_*)
        and filesize < 10MB
}
