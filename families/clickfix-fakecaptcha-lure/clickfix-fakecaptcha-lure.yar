/*
  clickfix-fakecaptcha-lure.yar
  -----------------------------------------------------------------------------
  ClickFix / FakeCAPTCHA social-engineering lure PAGES (HTML/JS).

  ClickFix tricks a victim into running an attacker-supplied command themselves:
  a fake "verify you are human" / reCAPTCHA / Cloudflare page silently copies a
  PowerShell/mshta/curl command to the clipboard (the "stageClipboard" routine)
  and instructs the victim to paste it into the Windows Run dialog (Win+R),
  PowerShell, or a terminal. Coined by Proofpoint; in the wild since 2024-03
  (TA571/ClearFake); by 2025 the #1-2 initial-access vector industry-wide.
  MITRE ATT&CK T1204.004 (Malicious Copy and Paste). Also covers the 2025
  "FileFix" variant (paste into the File Explorer address bar).

  Detection key: the DISCRIMINATOR is clipboard-staging of a shell command +
  fake-verification framing — NOT the CAPTCHA text alone (a legitimate reCAPTCHA
  or Cloudflare Turnstile page also says "verify you are human" but never copies
  a command to the clipboard or tells you to press Win+R).

  Rules fire on saved lure HTML / harvested pages, not on binaries.
*/

private rule cf_clipboard_write {
    strings:
        $stage     = "stageClipboard" ascii wide nocase
        $sccd      = "setClipboardCopyData" ascii wide nocase
        $writetext = "clipboard.writeText" ascii wide nocase
        $ec1       = "execCommand('copy')" ascii wide nocase
        $ec2       = "execCommand(\"copy\")" ascii wide nocase
    condition:
        any of them
}

private rule cf_exec_cradle {
    // an obfuscated / remote-execution command cradle (not a plain admin command)
    strings:
        $c1 = /powershell(\.exe)?\s+-[wnepc]{1,3}\b/ ascii wide nocase
        $c2 = "-EncodedCommand" ascii wide nocase
        $c3 = /-e(nc)?\s+[A-Za-z0-9+\/]{20,}/ ascii wide nocase
        $c4 = /iwr\s+[^\n]{0,160}\|\s*iex/ ascii wide nocase
        $c5 = /curl\s+[^\n]{0,200}\|\s*(iex|powershell|bash|zsh|sh)\b/ ascii wide nocase
        $c6 = "mshta http" ascii wide nocase
        $c7 = /conhost(\.exe)?\s+--headless/ ascii wide nocase
        $c8 = /Invoke-(Expression|WebRequest|RestMethod)/ ascii wide nocase
    condition:
        any of them
}

private rule cf_verify_ploy {
    // fake human-verification framing that is near-unique to ClickFix lures
    strings:
        $p1 = "reCAPTCHA Verification Hash" ascii wide nocase
        $p2 = "reCAPTCHA Verification ID" ascii wide nocase
        $p3 = "I am not a robot - reCAPTCHA" ascii wide nocase
        $p4 = "Cloud Identificator" ascii wide nocase
        $p5 = "Verification ID:" ascii wide nocase
        $p6 = "Verify you are human" ascii wide nocase
        $p7 = "Checking if you are human" ascii wide nocase
        $p8 = "ray id" ascii wide nocase
    condition:
        any of them
}

rule clickfix_stageclipboard_routine {
    meta:
        author = "synthetic-detections"
        description = "ClickFix lure: the near-unique clipboard-staging routine (stageClipboard/setClipboardCopyData)"
        reference = "https://attack.mitre.org/techniques/T1204/004/"
        technique = "T1204.004"
        severity = "high"
    strings:
        $stage = "stageClipboard" ascii wide nocase
        $sccd  = "setClipboardCopyData" ascii wide nocase
    condition:
        filesize < 3MB and any of them
}

rule clickfix_clipboard_staged_cradle {
    meta:
        author = "synthetic-detections"
        description = "ClickFix lure: a clipboard-copy of an obfuscated/remote-exec command cradle"
        reference = "https://attack.mitre.org/techniques/T1204/004/"
        technique = "T1204.004"
        severity = "high"
    condition:
        filesize < 3MB and cf_clipboard_write and cf_exec_cradle
}

rule clickfix_fakecaptcha_verify_ploy {
    meta:
        author = "synthetic-detections"
        description = "ClickFix lure: fake human-verification ploy + clipboard staging or a command cradle"
        reference = "https://attack.mitre.org/techniques/T1204/004/"
        technique = "T1204.004"
        severity = "high"
    condition:
        filesize < 3MB and cf_verify_ploy and (cf_clipboard_write or cf_exec_cradle)
}

rule clickfix_run_dialog_instructions {
    meta:
        author = "synthetic-detections"
        description = "ClickFix lure: paste-and-run (Win+R / File Explorer / PowerShell) instructions with a command cradle"
        reference = "https://attack.mitre.org/techniques/T1204/004/"
        technique = "T1204.004"
        severity = "high"
    strings:
        // open-the-runner / FileFix framing
        $r1 = /Win(dows)?\s*(key|button|logo)?\s*\+?\s*R\b/ ascii wide nocase
        $r2 = "Run dialog" ascii wide nocase
        $r3 = "Open PowerShell" ascii wide nocase
        $r4 = "Windows Terminal" ascii wide nocase
        $r5 = "File Explorer" ascii wide nocase
        $r6 = "How to fix" ascii wide nocase
        $r7 = "address bar" ascii wide nocase
        // paste + execute step
        $s1 = /Ctrl\s*\+?\s*V/ ascii wide nocase
        $s2 = "press Enter" ascii wide nocase
        $s3 = "paste" ascii wide nocase
    condition:
        filesize < 3MB and (1 of ($r*)) and (1 of ($s*)) and cf_exec_cradle and cf_verify_ploy
}
