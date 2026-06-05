# Test transcript — `http2-bomb.yar`

## Environment

- YARA: `4.5.2`
- Platform: `Linux host 6.12.88+deb13-amd64 x86_64 GNU/Linux`
- Date: `2026-06-04T10:14:00+02:00`
- Sources:
  - <https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb>
  - <https://seclists.org/oss-sec/2026/q2/790>
  - <https://thehackernews.com/2026/06/new-http2-bomb-vulnerability-allows.html>
  - <https://www.securityweek.com/http-2-bomb-exploit-knocks-web-servers-offline-in-seconds/>

## Scope and limitations

HTTP/2 Bomb is a **wire-level DoS**; the actual attack happens in HTTP/2
frames on the network. YARA over filesystem artefacts cannot see those
frames. These rules therefore target:

- **Public PoC source code** (Codex / Calif.io reference repo, weaponised
  derivatives written in Python / Go / etc.)
- **Cached writeups, IOC references, threat-intel notes**
- **Local clones of `califio/publications/MADBugs/http2-bomb`** on machines
  that shouldn't have offensive tooling

For actual exploitation detection, pair with WAF / reverse-proxy signatures
that count HPACK indexed references per stream and watch for
`SETTINGS_INITIAL_WINDOW_SIZE = 0` with sustained `WINDOW_UPDATE 1` drip.

## Corpus

| File | Kind | Intended rule | Expected |
|---|---|---|---|
| `specimens/h2bomb-poc.py` | synthetic PoC code shape (HPACK indexed bomb + zero window + WINDOW_UPDATE drip + crumb splitting) | `…_PoC_SourceCode` | match |
| `specimens/poc-ioc-readme.md` | reference dump of repo path, CVE, author handles | `…_PoC_IOC` | match |
| `benign/normal-h2-client.py` | real-shape h2.connection HTTP/2 GET client; no zero-window stall, no drip | none | no match |
| `benign/random-200k.bin` | 200 KiB urandom | none | no match |

(Three specimens preferred per house style, but the wire-level nature of
the vulnerability means most artefacts collapse into "PoC source" and
"reference notes" — two distinct shapes is honest.)

## Compile check

```
$ yara -w families/http2-bomb/http2-bomb.yar /dev/null && echo "COMPILE OK"
COMPILE OK
```

## Run — should-match

```
$ yara -r families/http2-bomb/http2-bomb.yar families/http2-bomb/specimens/
HTTP2_Bomb_PoC_IOC        families/http2-bomb/specimens//poc-ioc-readme.md
HTTP2_Bomb_PoC_SourceCode families/http2-bomb/specimens//h2bomb-poc.py
```

String-level run confirmed:

- `poc-ioc-readme.md` → IOC rule: `califio/publications/tree/main/MADBugs/http2-bomb`,
  `MADBugs/http2-bomb`, `MADBugs`, `CVE-2026-49975`, `Quang Luong`,
  `Jun Rong`, `Duc Phan`, `Stefan Eissing`, `blog.calif.io`.
- `h2bomb-poc.py` → SourceCode rule: technique strings (`HPACK`,
  `Indexed Reference Bomb` ×3, `indexed reference`, `dynamic table` ×2),
  framing tells (`SETTINGS_INITIAL_WINDOW_SIZE`, `PRI * HTTP/2.0`,
  `h2.connection`), the stall (`initial_window_size = 0`), the drip
  (`WINDOW_UPDATE 1` ×2), and the cookie-crumb bypass phrases.

## Run — should-not-match

```
$ yara -r -s families/http2-bomb/http2-bomb.yar families/http2-bomb/benign/
(no output — clean)
```

## Result summary

| File | Expected | Observed | Result |
|---|---|---|---|
| `h2bomb-poc.py` | PoC_SourceCode (+ IOC if any IOC strings present, none here) | SourceCode | PASS |
| `poc-ioc-readme.md` | PoC_IOC | IOC | PASS |
| `normal-h2-client.py` | clean | clean | PASS |
| `random-200k.bin` | clean | clean | PASS |

## Why the benign case doesn't false-positive

`normal-h2-client.py` uses the **same `h2.connection` library** as the PoC
and shares the HPACK-aware code path. The rule does not match because:

- The `$technique` string (`Indexed Reference Bomb`) is absent — that's
  the verbatim PoC name and the strongest single anchor.
- The co-occurrence branch requires `$zero_window` (`initial_window_size = 0`)
  **and** `$drip` (`WINDOW_UPDATE 1`) **and** an HPACK / crumb amplification
  anchor, simultaneously. The benign client only has the library import.

Earlier iterations of the rule tripped on a benign sample that mentioned
"cookie-crumb" in a *negation* docstring ("does not do cookie-crumb
splitting"). That was a self-inflicted FP from the test sample, not from
the rule — but the lesson informed a tightening: `$crumb_phrase` is now
gated by the co-occurrence branch (zero-window + drip) and cannot trigger
the rule on its own. RFC documentation that mentions cookie crumbs without
exhibiting the stall pattern will not match.

## Caveats

- Specimens are **synthetic**. They prove condition logic against the
  technique shape, not byte-level fidelity to the real Codex PoC. Drop
  the real `califio/publications/MADBugs/http2-bomb` files into
  `specimens/` for stronger validation.
- The `$technique` string ("Indexed Reference Bomb") is operator-coined
  and will be the first thing renamed if the technique is rediscovered or
  rebadged. The co-occurrence branch is the rotation-resistant fallback.
- The IOC rule is `severity = "high"` rather than critical because public
  threat-intel writeups (including this transcript) contain the same
  strings. Triage by file context.

## Not covered

- **Real HTTP/2 traffic** — out of scope for YARA. Use WAF rules that
  count indexed-reference fan-out per stream or alert on
  `SETTINGS_INITIAL_WINDOW_SIZE = 0` followed by sustained
  `WINDOW_UPDATE 1`.
- **Vulnerable-server fingerprints** — detecting unpatched `mod_http2`
  (< v2.0.41) or nginx (< 1.29.8) belongs in a config-audit tool, not in
  YARA.
- **IIS / Pingora** — both had no patch at disclosure. Detection of
  the *attack* against those is purely network-side.
