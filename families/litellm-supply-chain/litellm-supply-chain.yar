/*
   LiteLLM v1.107.0 supply-chain compromise, 2026-10-21
   -----------------------------------------------------
   On 2026-10-21, LiteLLM's release pipeline was compromised via stolen
   developer credentials. Malicious v1.107.0 was published to PyPI and
   Docker for ~104 minutes. The payload drops cook.pth, cook.py
   ("privcollect"), and sitecustomize.py into site-packages. cook.py
   harvests cloud/CI/LLM credentials and exfiltrates to litellm[.]dev;
   sitecustomize.py spawns a daemon polling a GitHub dead-drop for
   arbitrary code execution.

   Rule 1 — Behavioural: privcollect stealer operational shape.
   Rule 2 — IOC: campaign-specific file paths, exfil domain, dead-drop
            repository, and marker/lock files.
   Rule 3 — Specimen pin: SHA-256 hashes of the three malicious files.

   Sources:
     https://www.rescana.com/post/litellm-1-107-0-supply-chain-compromise-october-2026

   [[sibling]] litellm-march-2026 (earlier LiteLLM compromise, different
   tooling and infrastructure)
*/

import "hash"

rule LiteLLM_SupplyChain_Privcollect : python stealer supplychain
{
    meta:
        description = "LiteLLM v1.107.0 supply-chain stealer — behavioural detection of the privcollect credential harvester"
        author      = "synthetic-detections"
        date        = "2026-10-24"
        severity    = "critical"
        family      = "litellm-supply-chain"
        reference   = "https://www.rescana.com/post/litellm-1-107-0-supply-chain-compromise-october-2026"
    strings:
        $class      = "privcollect"
        $marker     = ".pc_once_"
        $exfil_ep   = "/healthcheck"
        $cred_aws   = ".aws/credentials"
        $cred_azure = ".azure/accessTokens"
        $cred_gcp   = "application_default_credentials"
        $cred_kube  = ".kube/config"
        $cred_vault = ".vault-token"
        $cred_ssh   = ".ssh/id_rsa"
    condition:
        $class and $marker and ($exfil_ep or 3 of ($cred_*)) and filesize < 500KB
}

rule LiteLLM_SupplyChain_IOC : python stealer supplychain
{
    meta:
        description = "LiteLLM v1.107.0 supply-chain compromise — campaign IOCs: exfil domain, dead-drop, marker and lock files"
        author      = "synthetic-detections"
        date        = "2026-10-24"
        severity    = "high"
        family      = "litellm-supply-chain"
        reference   = "https://www.rescana.com/post/litellm-1-107-0-supply-chain-compromise-october-2026"
    strings:
        $exfil_domain = "litellm.dev" nocase
        $dead_drop    = "letters9813/pythonclient-test"
        $marker_file  = ".pc_once_72129118c59f5636c0bb"
        $lock_file    = "remote_code_loader.lock"
        $cook_pth     = "import cook"
        $codepy_path  = "/codepy"
    condition:
        2 of them and filesize < 500KB
}

rule LiteLLM_SupplyChain_Specimen : python stealer supplychain
{
    meta:
        description = "LiteLLM v1.107.0 supply-chain compromise — specimen pin on known malicious file hashes"
        author      = "synthetic-detections"
        date        = "2026-10-24"
        severity    = "critical"
        family      = "litellm-supply-chain"
        reference   = "https://www.rescana.com/post/litellm-1-107-0-supply-chain-compromise-october-2026"
    condition:
        filesize < 5MB
        and (
            hash.sha256(0, filesize) == "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb" or
            hash.sha256(0, filesize) == "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25" or
            hash.sha256(0, filesize) == "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa"
        )
}
