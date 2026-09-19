# Test transcript — `arangodb-authbypass-taskrce-2026.rules`

## Environment
- Engine: **Snort 3.10.0.0** (validated directly; also cross-checked with Suricata 7.0.10).
  221 rules loaded including these two; run per PCAP with `-A alert_fast`.
- Platform: `Linux 6.12.101+deb13-amd64`
- Date: 2026-09-19
- Source: <https://remedio.io/blog/trust-me-im-the-system-arango-db-bugs-secure-system-architecture/>

## The vulnerabilities
ArangoDB unauth-to-root chain, advisories 2026-09-06, affected <= 3.12.10.1, fixed 3.12.11:
- **GHSA-rrgq-978q-36mq (9.8):** raw-vs-decoded URL mismatch — `/%5fapi/...` bypasses the auth
  gate and reaches `/_api/...`. Derived from the vendor patch test `test-api-bypass.js`
  (`PUT /%5fapi/simple/remove-by-example`).
- **GHSA-rvhw-4hpw-9vrx (9.9):** `POST /_api/tasks` with `"isSystem": true` escalates to
  internal context; ArangoDB-as-root turns the task's file-write into root RCE. Derived from
  `test-system-tasks-bypass.js`.

## PCAPs
| PCAP | Shape | Expected |
|---|---|---|
| `pcaps/attack-stage1-authbypass.pcap` | `PUT /%5fapi/simple/remove-by-example` | sid 2026091901 |
| `pcaps/attack-stage2-systemtask.pcap` | `POST /_api/tasks` body `"isSystem":true` | sid 2026091902 |
| `pcaps/benign-normal-api.pcap` | `GET /_api/version` | clean |
| `pcaps/benign-task-nosystem.pcap` | `POST /_api/tasks` legit task, no isSystem | clean |

## Results
```
attack-stage1-authbypass : [1:2026091901:1]
attack-stage2-systemtask : [1:2026091902:1]
benign-normal-api        : (clean)
benign-task-nosystem     : (clean)
```

## Why it discriminates
- **sid 2026091901** matches on the RAW URI (not the normalised one — normalising `%5f` back
  to `_` would erase the bypass). `nocase` covers `%5F`. Anchored to `%5f` immediately before a
  known internal endpoint (`api`/`admin`/`db`/`system`/`users`), so a stray `%5f` in a query
  value does not fire. No legitimate client percent-encodes the underscore in `/_api`.
- **sid 2026091902** requires POST + `api/tasks` in the raw URI (covers both `/_api/tasks` and a
  chained `/%5fapi/tasks`) + `"isSystem": true` in the body. A normal task creation omits
  `isSystem`, so it stays clean (benign-task-nosystem confirms).

## Corpus FP test
Not applicable — network (Snort/Suricata) signatures, no binary corpus. Discrimination shown by
the two benign PCAPs staying clean.

## Caveats
- **HTTPS terminates the rule** — ArangoDB is often behind TLS (187 of 451 exposed instances);
  deploy where traffic is inspected in cleartext (behind a terminating proxy) or on the
  plaintext instances. Patch to 3.12.11 regardless.
- Double-encoded (`%25%35api`) and `%2f_api` variants exist in the patch tests; sid 2026091901
  targets the primary single-encoded `%5f` vector. Add a companion content for `%25%35api` if
  double-encoding is seen in the wild.
