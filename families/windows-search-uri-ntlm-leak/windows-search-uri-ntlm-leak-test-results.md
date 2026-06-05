# Test transcript — `windows-search-uri-ntlm-leak.yar`

## Environment

- YARA: `4.5.2`
- Platform: `Linux host 6.12.88+deb13-amd64 x86_64 GNU/Linux`
- Date: `2026-06-04T10:14:00+02:00`
- Source: <https://www.huntress.com/blog/unpatched-ntlm-leak-windows-search-uri-handler>

## Corpus

| File | Kind | Intended rule(s) | Expected |
|---|---|---|---|
| `specimens/lure.html` | HTML anchor + Markdown variant carrying `crumb=location:` | `…_Lure`, `…_HtmlAnchor` | match |
| `specimens/start-cmd.bat` | command-line `start "" "search:..."` invocation | `…_Lure`, `…_HtmlAnchor` | match |
| `specimens/registry-anchor.reg` | DelegateExecute CLSID for `search:` | `…_RegistryAnchor` | match |
| `benign/normal-page.html` | onboarding page with UNC paths but no `search:` URI | none | no match |
| `benign/search-config.json` | config listing `search:` scheme names + UNC paths but no `crumb=location:` | none | no match |
| `benign/random-200k.bin` | 200 KiB urandom | none | no match |

## Compile check

```
$ yara -w families/windows-search-uri-ntlm-leak/windows-search-uri-ntlm-leak.yar /dev/null && echo "COMPILE OK"
COMPILE OK
```

## Run — should-match

```
$ yara -r -s families/windows-search-uri-ntlm-leak/windows-search-uri-ntlm-leak.yar \
        families/windows-search-uri-ntlm-leak/specimens/
WindowsSearch_URI_NTLM_Leak_Lure          …/start-cmd.bat
WindowsSearch_URI_NTLM_Leak_HtmlAnchor    …/start-cmd.bat
WindowsSearch_URI_NTLM_Leak_Lure          …/lure.html
WindowsSearch_URI_NTLM_Leak_HtmlAnchor    …/lure.html
WindowsSearch_URI_NTLM_Leak_RegistryAnchor …/registry-anchor.reg
```

(String-level output captured during the run includes the `search:` and
`search-ms:` scheme hits, the `crumb=location:` parameter, both raw and
JSON-escaped UNC pointers `\\10.0.1.100\share` and
`\\reports.attacker.example\public`, the `<a href="search:...crumb=location:...">`
anchor regex, the Markdown-link regex, the `start "" "search:..."`
command-line regex, and the `90b9bce2-...-35917ea1081b` CLSID alongside
`DelegateExecute`.)

## Run — should-not-match

```
$ yara -r -s families/windows-search-uri-ntlm-leak/windows-search-uri-ntlm-leak.yar \
        families/windows-search-uri-ntlm-leak/benign/
(no output — clean)
```

## Result summary

| File | Expected | Observed | Result |
|---|---|---|---|
| `lure.html` | Lure + HtmlAnchor | both fired | PASS |
| `start-cmd.bat` | Lure + HtmlAnchor (`startcmd` regex) | both fired | PASS |
| `registry-anchor.reg` | RegistryAnchor | fired | PASS |
| `normal-page.html` | clean | clean | PASS |
| `search-config.json` | clean | clean | PASS |
| `random-200k.bin` | clean | clean | PASS |

## Why the benign cases don't false-positive

- **`normal-page.html`** — has UNC paths and a link to learn.microsoft.com,
  but **no `search:` / `search-ms:` URI scheme anywhere**. Lure rule fails
  on the scheme check; HtmlAnchor rule fails because no anchor `href` opens
  with the scheme; RegistryAnchor rule fails because no DelegateExecute CLSID.
- **`search-config.json`** — contains the literal `"search:"` and `"search-ms:"`
  scheme strings **and** escaped UNC paths, but **does not contain
  `crumb=location:`**. The Lure rule requires that parameter as the bypass
  primitive — its absence kills the rule.
- **`random-200k.bin`** — urandom, no multi-byte literal hits.

The first benign was specifically built to be structurally similar to the
malicious case (it contains the literal URI schemes and UNC paths). That
the rule still rejects it confirms the `crumb=location:` parameter is doing
the discriminative work, not the scheme name alone.

## Caveats

- All specimens are **synthetic**, modelled on the Huntress writeup's
  examples. They prove condition logic, not byte-level fidelity against
  an in-the-wild lure.
- Microsoft has **declined to fix** this variant and assigned no CVE; the
  primitive will remain exploitable on patched Windows for the foreseeable
  future. The behavioural rule keys on the *technique*, not a transient
  campaign.
- `RegistryAnchor` (severity `high`) will fire on any registry export
  containing the CLSID — including benign system-state snapshots. Triage
  by context (path, exporting host).
- The Lure rule's `$unc_raw` / `$unc_escaped` regexes are bounded
  (`{1,253}` for hostname, `{1,80}` for share) to prevent catastrophic
  backtracking on large blobs.

## Not covered

- **LNK / .url shortcut delivery** — the byte-level structure of those
  files contains the URI in encoded form. The `…_Lure` rule will still hit
  if the URI is present as readable ASCII in the file (it usually is in
  `.url` and `.website` shortcuts), but a structurally weaponised LNK may
  need a dedicated rule.
- **Email body delivery** — for HTML email saved as `.eml`, the
  `…_HtmlAnchor` rule fires on the embedded `<a href="search:...">`. For
  Outlook `.msg` (CFB compound files), the URI is stored encoded and the
  rule may need a wide variant.
- **Wire-level NTLM relay** — this is a filesystem rule. Pair with network
  detections for `<click>` → outbound SMB to non-allowlisted destinations.
