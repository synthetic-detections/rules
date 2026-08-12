# deadlock-ransomware — YARA test results

Source: Microsoft Threat Intelligence, "DeadLock ransomware: Breaking down a
Rust-based encryptor with decentralized recovery infrastructure" (2026-08-10);
The Hacker News on the Polygon smart-contract C2 (2026-08-10).

## Rules

| Rule | Severity | Keys on |
|------|----------|---------|
| DeadLock_Encryptor | critical | PE + dDlK footer + .dlock ext + a ransom-note name + service-kill token |
| DeadLock_Ransom_Note | high | both note filenames, or HOW_RECOVER + 2 of (Session/liveblog365/.dlock) |
| DeadLock_Blockchain_C2 | high | ≥2 of the Polygon contract addrs/selectors + leak-site domains + pubkey |

## In-repo smoke test

```
$ yara -r deadlock-ransomware.yar specimens/
DeadLock_Blockchain_C2 specimens//c2_config.txt
DeadLock_Encryptor specimens//deadlock_encryptor.bin
DeadLock_Ransom_Note specimens//deadlock_encryptor.bin
DeadLock_Blockchain_C2 specimens//HOW_RECOVER.note.txt

$ yara -r deadlock-ransomware.yar benign/
(no output — clean)
```

Benign set is structurally similar on purpose: a normal Rust PE that merely
mentions a `windefend` token (no dDlK/.dlock/note → Encryptor must not fire), a
generic ransom note with no DeadLock markers, and a report citing a single
Polygon contract address (guards the ≥2 count on the C2 rule).

## Corpus FP test

PENDING — corpus-scan service unavailable at authoring time (DNS resolution
failure to the scan host). Keys are highly specific (the `dDlK` footer magic
co-occurring with `.dlock` and a DeadLock note name; the exact Polygon contract
addresses), so broad FPs are not expected. Re-run per rule on a recent slice once
the service is reachable; any hit on this recent family is a candidate FP.

## Notes

- The `dDlK` footer + `.dlock` + note-name co-occurrence is the strongest signal;
  the encryptor rule requires all three plus a service-kill token to avoid firing
  on IOC writeups.
- File-hash IOC (encryptor `a1fdf650…`) lives in the 2026-08-12 digest hash store,
  keeping the rule content-based.
- Attribution: partial RaaS, affiliate overlap with Lynx/INC per Microsoft; no
  state nexus claimed.
