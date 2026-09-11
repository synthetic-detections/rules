import "hash"

/*
 * BraZetsu — AI-enhanced IAB framework (Exilware, Brazil)
 *
 * Source: Group-IB blog "Anatomy of BraZetsu", 2026-09-03
 *         https://www.group-ib.com/blog/brazetsu-ai-enhanced-iab-marketplace/
 *
 * [[sibling]] — none yet
 */

rule BraZetsu_Behavioural {
    meta:
        description = "Detects BraZetsu IAB framework via behavioural strings"
        author = "synthetic-detections"
        date = "2026-09-10"
        severity = "critical"
        family = "brazetsu"
        reference = "https://www.group-ib.com/blog/brazetsu-ai-enhanced-iab-marketplace/"

    strings:
        $xor_key    = "p4st3_s3cr3t_k3y" ascii wide
        $reg_name   = "MonitorSystem" ascii wide
        $cnab       = "CNAB" ascii wide
        $dll1       = "temp_agente.dll" ascii wide nocase
        $dll2       = "agenteV2_historico_detect.dll" ascii wide nocase
        $exe1       = "wifi_driver.exe" ascii wide nocase
        $pastebin   = "pastebin.com/raw/" ascii wide

    condition:
        $xor_key or
        ($reg_name and $cnab) or
        ($dll1 or $dll2) or
        (any of ($exe1, $pastebin) and $reg_name)
}

rule BraZetsu_IOC {
    meta:
        description = "Detects BraZetsu via C2 infrastructure IOCs"
        author = "synthetic-detections"
        date = "2026-09-10"
        severity = "high"
        family = "brazetsu"
        reference = "https://www.group-ib.com/blog/brazetsu-ai-enhanced-iab-marketplace/"

    strings:
        $c2_1 = "c2.installscenter.com" ascii wide nocase
        $c2_2 = "infectonline.store" ascii wide nocase
        $c2_3 = "infect.online" ascii wide nocase
        $c2_4 = "caixaentradas1inboxshop.site" ascii wide nocase
        $c2_ip = "38.242.246.176" ascii fullword

    condition:
        any of them
}

rule BraZetsu_Specimen {
    meta:
        description = "Pins known BraZetsu samples by SHA-256"
        author = "synthetic-detections"
        date = "2026-09-10"
        severity = "critical"
        family = "brazetsu"
        reference = "https://www.group-ib.com/blog/brazetsu-ai-enhanced-iab-marketplace/"

    condition:
        hash.sha256(0, filesize) == "f775fe06a4c2563cb03e1aa42eb4e9532840cce9dc168ea2ca97cee7972e6b17" or
        hash.sha256(0, filesize) == "54e313434a7f3fa349e439857e23ab536a95c9927cf62f8358b5cdd9fabf2700" or
        hash.sha256(0, filesize) == "91f225dcc7a01f926b03e8540d8b5e2d6c8e3763cc30f57381d702ce638fa6b0" or
        hash.sha256(0, filesize) == "cd8fc8effea20d28e76c53f3386c783e55dcb309e1525b27f7a141d51b6f6c78" or
        hash.sha256(0, filesize) == "d881a60ccd03b5417a1eed184143a18a333e7e9e9e351596a7a765843643af99" or
        hash.sha256(0, filesize) == "0fa785bb9f95b113539bb909da88e6cac9a433a07935571d9bcd2d85746fc5bf" or
        hash.sha256(0, filesize) == "1510823e7c80b4db5333dd18cd5992881496da30032d6d69b2a82e1c5cf30246" or
        hash.sha256(0, filesize) == "96960409b6e1abf20eeb689d9e0a170008a15096de6a06ca5ae0d5aa56579042" or
        hash.sha256(0, filesize) == "0cd0cc49ea4ff48c675368f725e183608494f22fefa92d2f33577f70bb6c0d5d" or
        hash.sha256(0, filesize) == "30af2ec2437af0f4910d528440715540dbec6a5587f86f327316a7a781c1e2fe" or
        hash.sha256(0, filesize) == "10de6185e31539cf01c8b05d9559e65e8693efd695f315de54667ef8c04de39c" or
        hash.sha256(0, filesize) == "bc91f90a5677404cf9c8f4bed7b36c22027b1549ffefee129b41fab3db3108b8" or
        hash.sha256(0, filesize) == "93bb4a4812e77ddc17c2722340d915bd5c8387316bbdbc394c201a28cb9b7c88" or
        hash.sha256(0, filesize) == "67fcfbdaab397ad1273135a3c6aa1d220ab76491cf945df081503401cc9732d2" or
        hash.sha256(0, filesize) == "c4dd46e5b450349fd9fbf686a5a22f55f8371123b098104db663a3980646e138" or
        hash.sha256(0, filesize) == "3f2f48525cf082672e38808480e214775e03dd943ff2df86172665aad96a5eaa"
}
