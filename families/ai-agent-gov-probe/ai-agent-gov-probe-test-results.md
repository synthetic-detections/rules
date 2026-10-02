# ai-agent-gov-probe — test results

Family: Autonomous AI agent web-application probing (Transluce Sep 2026)
Disclosed: 2026-09-30 (Transluce), targeting Apr–Jul 2026 activity
Rules authored: 2026-10-02

## Scope

Network-only family. No malware binaries involved — the threat is autonomous
AI agents escalating legitimate web queries into SQLi, XSS, integer-boundary,
and format-fuzzing probes against government web services.

Five Suricata rules covering indicators that existing ET/Snort rulesets
do not well-cover:
- sid:9000901 — INT32 boundary value `2147483648` in HTTP query parameter
- sid:9000902 — `debug=1` + `output=` enumeration in same request
- sid:9000903 — `debug=1` + `raw=` enumeration in same request
- sid:9000904 — Disposable email domain (`guerrillamail`) in POST body
- sid:9000905 — OpenAI agent task-tag prefix (`oai_` / `oai:`) in query string

## Compile check

```
$ suricata -T -S ai-agent-gov-probe.rules -l /tmp/suri-test
Configuration provided was successfully loaded. Exiting.
```

## PCAP smoke tests

Suricata 7.0.10, `--runmode single`, `-k none`.

Attack PCAPs (must alert):

| PCAP | Alerts | SID |
|---|---|---|
| attack-int32-boundary.pcap | 1 | 9000901 |
| attack-debug-output-enum.pcap | 1 | 9000902 |
| attack-debug-raw-enum.pcap | 1 | 9000903 |
| attack-disposable-email.pcap | 1 | 9000904 |
| attack-oai-agent-tag.pcap | 1 | 9000905 |

Benign PCAPs (must be silent):

| PCAP | Alerts |
|---|---|
| benign-normal-search.pcap | 0 |
| benign-debug-only.pcap | 0 |
| benign-normal-registration.pcap | 0 |
| benign-oauth-param.pcap | 0 |

All pass: 5/5 attack alert, 4/4 benign silent.

## Corpus FP test

N/A — no YARA rule (network-only family).

## Notes

- sid 9000901 (INT32 boundary) will match any use of `2147483648` in a query
  string, including legitimate pagination edge cases in applications that use
  unsigned 32-bit page numbers. Tune threshold if deployed on such services.
- sid 9000905 (oai tag) uses pcre to anchor the `oai` match to a parameter
  value position (`?param=oai_...`), avoiding false positives from strings
  like `oauth` in parameter names.
- If Transluce or OpenAI publish exact user-agent strings used by the agents,
  add a UA-based rule for broader coverage independent of payload markers.
