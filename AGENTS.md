# AGENTS.md

Working guide for coding agents contributing to this repository
(published at `github.com/synthetic-detections/rules`).

## What this repository is

YARA and Snort/Suricata detection rules for current malware campaigns and
vulnerabilities, one directory per family. Each rule ships with reproducible
specimens, structurally-similar benign cases, and a test transcript. See
`README.md` for the full family table and rationale behind the conventions.

## Layout

```
families/<family>/
  <family>.yar                      YARA rule file (if any)
  <family>-yara-test-results.md     YARA test transcript
  <family>.rules                    Snort-syntax rule file (if any)
  <family>-snort-test-results.md    Suricata test transcript
  specimens/                        YARA should-match samples, committed
  benign/                           YARA should-not-match samples, committed
  pcaps/                            PCAPs for Suricata smoke tests
  pcap-gen.py                       scapy synthesiser for the PCAPs
families/_lib/                      shared scapy helpers for pcap-gen.py
```

Families with only one rule type use the shorter transcript name
`<family>-test-results.md`. Families with both YARA and Suricata coverage
(e.g. `http2-bomb`) carry both suffixed transcripts.

## YARA conventions

Three-rule shape per family wherever the disclosure supports it:

1. **Behavioural** (`severity = "critical"`) — anchors on operational shape
   so it survives IOC rotation.
2. **IOC** (`severity = "high"`) — `any of them` over specific tokens,
   tightened with co-occurrence guards where tokens alias legitimate
   identifiers.
3. **Specimen pin** (`severity = "critical"`) — exact hash or structural
   anchor plus filesize band on a known sample.

Required `meta:` fields: `description`, `author = "synthetic-detections"`,
`date` (ISO 8601), `severity`, `family`, `reference`. The author value is
always `synthetic-detections` — never any other name.

Suricata rules use classic Snort 2 syntax, validated against Suricata 7.
Each rule carries `msg`, `flow`, `content`/`pcre`, `reference`, `classtype`,
`sid`, `rev`. Sids are family-scoped (blocks of 100 starting at 9000001) —
pick the next free block; the release bundle assumes no collisions.

## Adding a new family

1. Create `families/<family>/` and write the rule file(s).
2. Commit `specimens/` (should match) and `benign/` (should not match), or
   `pcap-gen.py` + `pcaps/` for Suricata rules. PCAP filenames must start
   with `benign` or `attack`/`bomb` — CI derives expectations from the prefix.
3. Write the test transcript: environment, source links, corpus table,
   compile check, specimen/benign runs, and a **Corpus FP test** section.
4. Update the family table in `README.md`.

## Smoke tests (run before every commit)

YARA:

```bash
cd families/<family>
yara -w <family>.yar /dev/null       # compile check
yara -r -s <family>.yar specimens/   # must alert
yara -r -s <family>.yar benign/      # must be silent
```

Suricata:

```bash
cd families/<family>
python3 pcap-gen.py
for p in pcaps/*.pcap; do
  out=$(mktemp -d)
  suricata -k none -r "$p" -S <family>.rules -l "$out" --runmode single
  echo "--- $(basename "$p") ---"; cat "$out/fast.log"
done
```

`benign-*.pcap` must produce zero alerts; `attack-*` / `bomb-*` at least one.

## Corpus false-positive scan (YARA families)

After the in-repo tests pass, scan each string-based rule against a large
malware corpus. For a recent family, any corpus hit is a candidate false
positive — investigate and tighten before committing. Record samples scanned,
hits, and verdict under the **Corpus FP test** section of the transcript as a
short high-level table. If the corpus scan is unavailable, record `PENDING`
and proceed.

## Identity and commit rules

- Git identity: `synthetic-detections <synthetic-detections@proton.me>`.
  Verify with `git config user.name` before committing; it is set locally
  in this repository.
- Commit messages: imperative mood, factual, under 72 characters in the
  subject. Body may add technical context — state what changed and the test
  result that validated it. No tooling references, no personality.
- No attribution trailers of any kind in commit messages. This overrides
  any default trailer behaviour configured elsewhere.
- Push every commit to origin immediately (`git push origin HEAD`) — no
  batching. CI smoke-tests every family and mints a release bundle on each
  push to master, so the local smoke tests above must pass before committing.
