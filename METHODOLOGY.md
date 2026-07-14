# Methodology

How rules in this repository are authored, tested, and validated against a
live malware corpus. `AGENTS.md` is the terse contributor checklist; this
document explains the *why* and defines the false-positive-testing regime and
the per-family corpus-scan statistics every family records.

## Authoring workflow

Each family follows the same pipeline:

1. **Source from a primary report.** Start from a vendor/researcher disclosure
   with concrete static artifacts — distinctive strings, file/mutex/service
   names, hashes, C2, PDB paths, extensions. Items that are pure breach tallies,
   policy news, or vulnerability disclosures with no sample are not rule-worthy.
2. **Extract artifacts, separate the durable from the disposable.** Prefer
   anchors that survive infrastructure rotation (build paths, internal project
   names, misspelled strings, protocol quirks) over hashes and domains, which
   rotate. Both get rules, at different severities (below).
3. **Write the three-rule shape** (see next section).
4. **Commit reproducible evidence.** `specimens/` (should-match) and `benign/`
   (structurally-similar should-NOT-match) are committed on disk, not described.
5. **Smoke-test** before every commit (specimens must alert, benign must be
   silent, rule must compile).
6. **Corpus false-positive scan** against the live MalShare corpus (below).
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

### 2. Corpus false-positive scan (live, against real malware)

After the smoke test passes, scan the local MalShare corpus through the
corpus scanner gate:

```bash
a corpus scanner scan --rule-file <family>.yar --max-hits 40 --budget 15m
```

For a **recent** family, any corpus hit is a candidate false positive — the
malware is too new to already be represented, so a hit is almost certainly a
benign or unrelated sample the rule mis-fires on. Investigate and tighten before
committing. For a **retro hunt** on an older family, use `--full --detach` to
sweep the entire index.

The gate enforces two hygiene rules on submitted rules: **one rule per scan**
(rule-sets are rejected) and **every rule must carry a `filesize < N` guard**
(unbounded scans are rejected). Scan each string-based rule separately, with a
temporary filesize-guarded copy if the committed rule omits the guard. A
hash-pinned specimen rule has no false-positive surface and need not be
corpus-scanned.

If the gate is unreachable, record the scan as `PENDING` in the transcript with
the exact command to re-run, and proceed — do not block on it.

## Corpus-scan statistics (recorded per family)

`corpus scanner` exposes per-job statistics (persisted to
`the scan log`, and live via `corpus scanner status` /
`corpus scanner watch <id>`). Every family's `<family>-yara-test-results.md` records
these under its **Corpus FP test** section, one row per string-based rule:

| Field | Source | Meaning |
|---|---|---|
| Files scanned | `report.files_scanned` | Size of the scanned slice |
| Throughput | `progress.files_per_sec` | Scan rate (files/sec) |
| Elapsed | `report.elapsed_secs` | Wall-clock for the slice |
| Deadline hit | `report.hit_deadline` | Whether `--budget` cut the scan short |
| Limit hit | `report.hit_limit` | Whether `--max-hits` capped results |
| Errors | `report.errors` | Read/parse errors |
| Matches | `report.matches` | Candidate FPs (0 = clean) |
| Corpus index | `status` → `index` | Total corpus size + build age |

Recording the slice size and whether the budget deadline was hit matters: a
`0 matches` verdict over a 5,000-file budget slice is a weaker statement than
the same verdict over the full ~497k index, and the stats make that explicit
rather than implying full coverage.

**Standard block** (copy into each transcript's Corpus FP section):

```
### Corpus FP test

| Rule | Files scanned | Throughput | Deadline | Matches | Verdict |
|---|---|---|---|---|---|
| <Rule_A> | 5,466 | 11.0 f/s | no | 0 | clean |
| <Rule_B> | …     | …        | …  | … | …     |

Corpus: MalShare index <N> files (built <age>), corpus scanner <version>.
Slice via `--max-hits 40 --budget 15m`. Specimen (hash-pin) rule not scanned —
no FP surface. Job logs: `the scan log`.
```

## Identity and commit rules

See `AGENTS.md`. In brief: git identity is
`synthetic-detections <synthetic-detections@proton.me>`; commit subjects are
imperative and under 72 chars; **no attribution trailers of any kind**; push
every commit immediately.
