# Test transcript — `fluttershell-flutterbridge.yar`

## Environment

- YARA: `4.5.2`
- Date: 2026-06-07
- Source: <https://unit42.paloaltonetworks.com/flutterbridge-new-fluttershell-backdoor/>

## Corpus

| File | Kind | Intended rule | Expected |
|---|---|---|---|
| `specimens/fluttershell.macho` | synthetic Mach-O with `com.app.podcastsLounge` bundle id + `Yasar Sever (UBZDAAV97Y)` Dev ID | `…_MachOBundle` | match |
| `specimens/webview-payload.js` | synthetic WebView JS with `flutterInvoke` + 9 native commands + 5 C2 paths + `summarize-text` | `…_WebViewJSBridge` (+ IOC via C2 hostname) | match |
| `specimens/ioc-dump.txt` | IOC reference dump | `…_IOC` + `…_WebViewJSBridge` (it quotes the verbatim path-shapes) | match |
| `benign/legit-flutter.macho` | real-shape Mach-O with a benign bundle id and Team ID | none | no match |
| `benign/normal-webview.js` | standard postMessage WebView, no campaign anchors | none | no match |
| `benign/random.bin` | 5 KiB urandom | none | no match |

## Compile check

```
$ yara -w families/fluttershell-flutterbridge/fluttershell-flutterbridge.yar /dev/null && echo OK
OK
```

## Result summary

| File | Expected | Observed | Result |
|---|---|---|---|
| `fluttershell.macho` | `…_MachOBundle` | fired | PASS |
| `webview-payload.js` | `…_WebViewJSBridge` (+ IOC) | both fired | PASS |
| `ioc-dump.txt` | `…_IOC` (+ WebViewJSBridge crossover from quoted path-shapes) | both fired | PASS |
| `legit-flutter.macho` | clean | clean | PASS |
| `normal-webview.js` | clean | clean | PASS |
| `random.bin` | clean | clean | PASS |

## Self-inflicted FP fixed

The first iteration of `benign/normal-webview.js` had a comment line
that mentioned the campaign by name in negation form ("no flutterInvoke
channel, no FlutterShell C2 path-shapes"). The literal `FlutterShell`
matched the IOC rule's `$m_mal_name` anchor. Rewrote the comment to
say "no campaign anchors of any kind" — same recurring lesson as
Phantom Gyp / Miasma original.

## Caveats

- **Apple Developer IDs are burnable.** The three Dev IDs and Team IDs
  (Yasar Sever / UBZDAAV97Y, Batuhan Dabag / FW9NHQ8922, Yusuf Bal /
  B73CHZ24Y8) were valid Apple credentials the operator used to sign +
  notarise the malicious apps. Apple will revoke them on disclosure
  (typically within days). The rule keeps them anyway: future researchers
  hunting historical samples need the strings, and the rule's
  bundle-ID anchors will also fire on fresh resigned samples.
- **The `flutterInvoke` bridge name is the load-bearing anchor.** If
  the operator rotates the channel name they break their own JS payload
  library (which expects `window.flutterInvoke` on the WebView). Rotation
  cost is high enough to make this a durable detection.
- **C2 path-shapes (`/getConfig`, `/update-thanks.html`, etc.) are
  more persistent than C2 hostnames.** The Snort/Suricata sibling rules
  in this family cover the wire side via TLS SNI + DNS + HTTP path.

## Not covered

- **Apple notarisation revocation.** Once Apple revokes the Dev IDs,
  Gatekeeper will block execution of these specific binaries; YARA is
  still useful for historical forensic sweeps but live blocking is
  handled by macOS itself.
- **Google Ads vetting bypass tradecraft.** Unit 42 documents the shell
  companies used to purchase the ads; that's an upstream-of-host signal
  not visible at the endpoint.
- **Fresh-resigned variants.** A re-up of the same FlutterShell payload
  with a new Apple Dev ID would slip the Dev-ID anchors. Rule 1's
  bundle-ID set is the next-best catch; ultimately rule 2's
  `flutterInvoke` bridge is the durable anchor.
