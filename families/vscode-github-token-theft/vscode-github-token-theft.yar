/*
   VS Code 1-click GitHub OAuth token theft — Ammar Askar PoC (disclosed 2026-06-02)
   ----------------------------------------------------------------------------------
   A maliciously crafted github.dev workspace (or any .ipynb / Markdown page that
   renders in VS Code's webview) chains:
     1. simulated keyboard events dispatched via window.dispatchEvent(),
     2. the webview's hostMessaging.postMessage('did-keydown', ...) bridge that
        forwards synthetic keystrokes to the main VS Code window,
     3. installation of an attacker-controlled extension through
        `workbench.extensions.installExtension` with `skipPublisherTrust: true`
        and `donotSync: true` to bypass marketplace trust prompts,
     4. extraction of the GitHub OAuth token that github.com POSTs to github.dev,
        then enumeration of the victim's private repos via api.github.com.

   Rule 1 — behavioural: VS Code webview message-passing + synthetic keyboard
            chain + install-extension command. Survives PoC-string rotation.
   Rule 2 — IOC sweep: Askar PoC strings (extension id, repo path, exact
            keyboard-chord command targets).
   Rule 3 — malicious extension manifest pin: package.json that wires
            `workbench.extensions.installExtension` to a keybinding with
            `skipPublisherTrust: true` — the bypass primitive itself.

   Sources:
     https://blog.ammaraskar.com/github-token-stealing/
     https://thehackernews.com/2026/06/one-click-github-dev-attack-lets.html
     https://www.bleepingcomputer.com/news/security/vs-code-zero-day-lets-hackers-steal-github-tokens-in-one-click/
*/

rule VSCode_GitHub_Token_Theft_WebviewChain
{
    meta:
        description = "Webview-message-passing + synthetic-keypress chain used to bypass VS Code marketplace trust and steal github.dev OAuth tokens"
        author      = "synthetic-detections"
        date        = "2026-06-04"
        severity    = "critical"
        family      = "vscode-github-oauth-theft"
        reference   = "https://blog.ammaraskar.com/github-token-stealing/"

    strings:
        // VS Code webview message-passing identifiers
        $vsc_api      = "acquireVsCodeApi" ascii
        $vsc_msg      = "did-keydown" ascii
        $vsc_bridge   = "hostMessaging" ascii
        $vsc_handler  = "handleInnerKeydown" ascii

        // Synthetic keyboard-event dispatch with the modifier shape used by the PoC
        $kbd_ctor     = /new\s+KeyboardEvent\s*\(\s*["']keydown["']/ ascii
        $kbd_chord_a  = /ctrlKey\s*:\s*true[^}]{0,80}shiftKey\s*:\s*true/ ascii
        $kbd_chord_b  = /shiftKey\s*:\s*true[^}]{0,80}ctrlKey\s*:\s*true/ ascii
        $kbd_codeA    = /code\s*:\s*["']KeyA["']/ ascii
        $kbd_codeF1   = /code\s*:\s*["']F1["']/ ascii
        $kbd_dispatch = "window.dispatchEvent" ascii

        // Target of the chain: install an extension or open the command palette
        $cmd_install  = "workbench.extensions.installExtension" ascii
        $cmd_palette  = "workbench.action.showCommands" ascii
        $cmd_notif    = "Notifications: Accept Notification Primary Action" ascii

        // GitHub OAuth / token exfiltration surface
        $gh_dev       = "github.dev" ascii nocase
        $gh_api       = "api.github.com" ascii nocase
        $gh_user_repo = "/user/repos" ascii

    condition:
        filesize < 2MB
        and
        // Co-occurrence: webview API + synthetic keypress + extension-install OR palette OR notification accept
        (
            2 of ($vsc_api, $vsc_msg, $vsc_bridge, $vsc_handler)
            and $kbd_ctor
            and $kbd_dispatch
            and any of ($kbd_chord_a, $kbd_chord_b)
            and any of ($kbd_codeA, $kbd_codeF1)
            and any of ($cmd_install, $cmd_palette, $cmd_notif)
            and any of ($gh_dev, $gh_api, $gh_user_repo)
        )
}

rule VSCode_GitHub_Token_Theft_IOC
{
    meta:
        description = "Static IOCs for the Askar VS Code github.dev OAuth-theft PoC — extension id, repo coordinate, exact PoC strings"
        author      = "synthetic-detections"
        date        = "2026-06-04"
        severity    = "high"
        family      = "vscode-github-oauth-theft"
        reference   = "https://blog.ammaraskar.com/github-token-stealing/"

    strings:
        $poc_ext    = "AmmarTest.hello-ammar-github" ascii
        $poc_repo   = "ammaraskar/github-dev-token-steal-poc" ascii nocase
        $poc_file   = "github-dev-token-steal-poc" ascii nocase

        // Bypass-primitive flags as a verbatim co-occurrence
        $skip_trust = "skipPublisherTrust" ascii
        $dont_sync  = "donotSync" ascii

        // Exact notification-accept primary-action label (PoC uses Ctrl+Shift+A binding)
        $notif_lbl  = "Notifications: Accept Notification Primary Action" ascii

    condition:
        filesize < 50MB and any of them
}

rule VSCode_GitHub_Token_Theft_MaliciousExtensionManifest
{
    meta:
        description = "VS Code extension package.json that binds workbench.extensions.installExtension to a keybinding with skipPublisherTrust — the marketplace-trust-bypass primitive at the heart of the Askar chain"
        author      = "synthetic-detections"
        date        = "2026-06-04"
        severity    = "critical"
        family      = "vscode-github-oauth-theft"
        reference   = "https://blog.ammaraskar.com/github-token-stealing/"

    strings:
        $contrib    = "\"contributes\"" ascii
        $keybinds   = "\"keybindings\"" ascii
        $cmd_field  = "\"command\"" ascii
        $cmd_value  = "\"workbench.extensions.installExtension\"" ascii
        $args_field = "\"args\"" ascii
        $skip_trust = "\"skipPublisherTrust\"" ascii
        $skip_true  = /["']skipPublisherTrust["']\s*:\s*true/ ascii

    condition:
        filesize < 256KB
        and $contrib
        and $keybinds
        and $cmd_field
        and $cmd_value
        and $args_field
        and ($skip_trust or $skip_true)
}
