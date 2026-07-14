# Methodology

How rules in this repository are authored, tested, and validated. `AGENTS.md`
is the terse contributor checklist; this document explains the *why* and the
false-positive-testing regime.

## Authoring workflow

Each family follows the same pipeline:

1. **Source from a primary report.** Start from a vendor/researcher disclosure
   with concrete static artifacts — distinctive strings, file/mutex/service
   names, hashes, C2, PDB paths, extensions. Pure breach tallies, policy news,
   or vulnerability disclosures with no sample are not rule-worthy.
2. **Extract artifacts, separate the durable from the disposable.** Prefer
   anchors that survive infrastructure rotation (build paths, internal project
   names, misspelled strings, protocol quirks) over hashes and domains, which
   rotate. Both get rules, at different severities (below).
3. **Write the three-rule shape** (next section).
4. **Commit reproducible evidence.** `specimens/` (should-match) and `benign/`
   (structurally-similar should-NOT-match) are committed on disk, not described.
5. **Smoke-test** before every commit (specimens must alert, benign must be
   silent, rule must compile).
6. **Scan for false positives** against a large malware corpus (below).
7. **Commit per family and push immediately** — CI smoke-tests every family and
   mints a release bundle on each push, so local tests must pass first.

## The three-rule shape

Wherever the disclosure supports it, a family ships three rules:

| Rule | `severity` | Anchors on | Survives IOC rotation? |
|---|---|---|---|
| **Behavioural** | `critical` | Operational shape — build/PDB paths, mutex families, protocol tells, co-occurring markers | Yes — the durable core |
| **IOC** | `high` | Specific tokens (domains, distinctive module names, config filenames), `any of` with co-occurrence guards where a token aliases a legitimate identifier | Partially |
| **Specimen pin** | `critical` | Exact `hash.sha256`/`sha1` of published samples + a filesize band | No — exact, by design |

Generic tokens that alias legitimate identifiers (e.g. common `.dll` names, a
bare product word) are **excluded from the firing condition** or gated behind
co-occurrence, and a benign case is committed proving they do not fire alone.

## False-positive testing

Two layers, both required:

### 1. In-repo smoke test (deterministic, offline)

```bash
cd families/<family>
yara -w <family>.yar /dev/null       # compile check
yara -r -s <family>.yar specimens/   # must alert
yara -r -s <family>.yar benign/      # must be silent
```

The benign set is the load-bearing part: it holds cases that share structure
with the threat (the same side-load host names, the same generic module names,
a homograph of the project word) and proves the rule keys on the malware's own
tells, not on the look-alikes. Note a recurring authoring trap — a benign file
that *names* the absent tokens ("contains no `MYMUTEX123…`") will self-match,
because YARA matches literal strings regardless of surrounding prose. Describe
missing markers without spelling them.

### 2. Corpus false-positive scan

After the smoke test passes, each string-based rule is scanned against a large
malware corpus. For a **recent** family, any corpus hit is a candidate false
positive — the malware is too new to already be represented, so a hit is almost
certainly a benign or unrelated sample the rule mis-fires on. Investigate and
tighten before committing. A hash-pinned specimen rule has no false-positive
surface and is not scanned.

## Recording results

Every family's `<family>-yara-test-results.md` records the corpus result under a
**Corpus FP test** section as a short markdown table — one row per string-based
rule, with the number of corpus samples scanned, matches, read errors, and a
verdict. Keep it high-level; the point is a clear pass/fail signal, e.g.:

```
### Corpus FP test

| Rule | Corpus samples | Matches | Read errors | Verdict |
|---|---|---|---|---|
| <Rule_A> | ~5,500  | 0 | 0 | clean |
| <Rule_B> | ~11,700 | 0 | 0 | clean |
```

## Identity and commit rules

See `AGENTS.md`. In brief: git identity is
`synthetic-detections <synthetic-detections@proton.me>`; commit subjects are
imperative and under 72 chars; **no attribution trailers of any kind**; push
every commit immediately.
