# Test transcript — `vscode-github-token-theft.yar`

## Environment

- YARA: `4.5.2`
- Platform: `Linux host 6.12.88+deb13-amd64 x86_64 GNU/Linux`
- Date: `2026-06-04T09:09:22+02:00`
- Source advisories:
  - Askar PoC writeup: <https://blog.ammaraskar.com/github-token-stealing/>
  - The Hacker News: <https://thehackernews.com/2026/06/one-click-github-dev-attack-lets.html>
  - BleepingComputer: <https://www.bleepingcomputer.com/news/security/vs-code-zero-day-lets-hackers-steal-github-tokens-in-one-click/>

## Corpus

| File | Kind | Intended rule | Expected |
|---|---|---|---|
| `specimens/webview-chain.html` | synthetic webview payload — keypress chain + VS Code bridge + install-extension target + github.dev | `…_WebviewChain` | match |
| `specimens/malicious-extension-package.json` | the Askar PoC manifest — installExtension keybinding + skipPublisherTrust | `…_MaliciousExtensionManifest` | match |
| `specimens/poc-ioc-dump.txt` | text dump of PoC IOCs | `…_IOC` | match |
| `benign/normal-webview.html` | a real-shape VS Code webview using `acquireVsCodeApi` + `postMessage` but no synthetic keypress / install / github.dev | none | no match |
| `benign/legit-extension-package.json` | a real Prettier-style extension manifest with a `keybindings` array | none | no match |
| `benign/random-200k.bin` | 200 KiB urandom | none | no match |

## Compile check

```
$ yara -w families/vscode-github-token-theft/vscode-github-token-theft.yar /dev/null && echo "COMPILE OK"
COMPILE OK
```

## Run — should-match (`specimens/`)

```
$ yara -r -s families/vscode-github-token-theft/vscode-github-token-theft.yar \
        families/vscode-github-token-theft/specimens/
VSCode_GitHub_Token_Theft_IOC                       …/specimens/poc-ioc-dump.txt
VSCode_GitHub_Token_Theft_WebviewChain              …/specimens/webview-chain.html
VSCode_GitHub_Token_Theft_IOC                       …/specimens/webview-chain.html
VSCode_GitHub_Token_Theft_IOC                       …/specimens/malicious-extension-package.json
VSCode_GitHub_Token_Theft_MaliciousExtensionManifest …/specimens/malicious-extension-package.json
```

(Full string-level output captured during the test run; see `string matches` section below.)

### String matches observed

- **`poc-ioc-dump.txt` → IOC:** `AmmarTest.hello-ammar-github`, `ammaraskar/github-dev-token-steal-poc` (×2),
  `github-dev-token-steal-poc` (×2), `skipPublisherTrust`, `donotSync`, the notification-label string.
- **`webview-chain.html` → WebviewChain:** `acquireVsCodeApi`, `did-keydown` (×2),
  `hostMessaging` (×2), `handleInnerKeydown` (×3), the `new KeyboardEvent("keydown"…` constructor,
  `ctrlKey: true, shiftKey: true`, `code: "KeyA"`, `window.dispatchEvent`,
  `workbench.extensions.installExtension`, the notification-label string,
  `github.dev` (×2), `api.github.com`, `/user/repos`.
- **`webview-chain.html` → IOC (secondary):** matched on the notification-label IOC string only —
  expected because the PoC's primary keybinding maps Ctrl+Shift+A to that exact label.
- **`malicious-extension-package.json` → MaliciousExtensionManifest:** all manifest anchors hit,
  including the `"skipPublisherTrust": true` regex.
- **`malicious-extension-package.json` → IOC (secondary):** extension id + bypass flags — expected.

## Run — should-not-match (`benign/`)

```
$ yara -r -s families/vscode-github-token-theft/vscode-github-token-theft.yar \
        families/vscode-github-token-theft/benign/
(no output — clean)
```

## Result summary

| File | Expected | Observed | Result |
|---|---|---|---|
| `webview-chain.html` | `…_WebviewChain` (+ IOC fallback) | both fired | PASS |
| `malicious-extension-package.json` | `…_MaliciousExtensionManifest` (+ IOC fallback) | both fired | PASS |
| `poc-ioc-dump.txt` | `…_IOC` | `…_IOC` | PASS |
| `normal-webview.html` | clean | clean | PASS |
| `legit-extension-package.json` | clean | clean | PASS |
| `random-200k.bin` | clean | clean | PASS |

## Why the benign cases don't false-positive

- **`normal-webview.html`** — uses `acquireVsCodeApi` and `postMessage`, but:
  - no `new KeyboardEvent("keydown"…)` constructor,
  - no `dispatchEvent`,
  - no `ctrlKey/shiftKey` modifier object,
  - no `workbench.extensions.installExtension` / palette / notification-accept target,
  - no `github.dev` / `api.github.com` mention.
  The WebviewChain rule needs **all four** conditions co-present; this file fails on
  every one of them after the first.
- **`legit-extension-package.json`** — has a `keybindings` array (so it shares two
  anchors with the malicious manifest), but:
  - the keybinding `command` is `editor.action.formatDocument`, **not**
    `workbench.extensions.installExtension`,
  - no `args` field with extension-install arguments,
  - no `skipPublisherTrust` token anywhere.
  The MaliciousExtensionManifest rule requires the exact bypass command + `args` +
  `skipPublisherTrust`; this manifest fails the command match.
- **`random-200k.bin`** — urandom, no multi-byte literal hits anywhere.

## Caveats

- All specimens are **synthetic** — modelled on Askar's writeup verbatim. They prove
  condition logic, not byte-level fidelity against an in-the-wild lure.
- **Microsoft mitigated the chain server-side at github.dev on 2026-06-03.** The rule still
  catches the *technique* (webview synthetic-keypress + extension-install + token target),
  which is what we want for detection of imitator chains — but the original PoC URL no
  longer pops a real token. Test against a sample PoC instead of a live target.
- The `…_IOC` rule is `severity = "high"` rather than critical because public threat-intel
  writeups (and this transcript) will legitimately contain the same PoC strings. Triage
  by file context (skip `*.md`, `*.pdf`, `*-test-results.md`, blog source).
- The MaliciousExtensionManifest rule will fire on the Askar PoC's manifest verbatim **and**
  on any imitator that copies the `installExtension` + `skipPublisherTrust` keybinding
  primitive. It will NOT fire on a malicious extension that achieves token theft via a
  different VS Code abuse path (e.g. activation events, MCP server, runtime API surface).

## Not covered

- **Server-side detection at github.dev** — the actual OAuth token POST is between
  github.com and github.dev's hosted webview; YARA over filesystem artefacts won't see
  that traffic. Pair with HTTP detections (referer chains, unexpected `vscode-webview://`
  → `api.github.com` flows).
- **Token exfiltration over alternative channels** — the rule anchors on `api.github.com`
  / `/user/repos` because that's what the PoC exercises; an imitator using
  `git@github.com` SSH listings or a different REST path would slip past unless one of
  the other co-occurrence anchors lights up.
- **Markdown / .ipynb lure pages** — if an attacker delivers the chain via a notebook
  that gets rendered by VS Code's built-in Jupyter, the same webview-message-passing
  anchors apply, but the lure itself might be obfuscated. Add specimen variants if seen.
