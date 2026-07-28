# sourtrade-browser-assembled — test results

Family: SourTrade — browser-assembled malware via malvertising
Disclosed: 2026-07-23 (Confiant, Michael Steele)
Rules authored: 2026-07-28

## Rules

- `SourTrade_Browser_Assembler_JS` (critical) — the browser-side loader: `/config` build
  instructions (`random.seed`/`random.size`/`template`/`standaloneUrl`) + the streamsaver
  ServiceWorker download protocol (`streamsaver:ping/open/abort`, `/sw.js`) + in-browser Bun/AES-CTR
  PE assembly. Three co-occurrence paths so a legit Bun app or StreamSaver page doesn't match.
- `SourTrade_Assembled_PE_BunSection` (high) — the assembled Windows PE with a `.bun` section
  carrying JavaScriptCore bytecode for `app.js` (MZ-gated).
- `SourTrade_IOC_Hashes` (high) — the 3 Confiant SHA-256 pins. Noted in meta as point-in-time only:
  SourTrade mints a unique hash per victim, so hashes are not a stable family signature.
- Suricata `sourtrade-browser-assembled.rules` — `/config` response (standaloneUrl+random.seed),
  `/config` request, and TLS SNI for a sample of the 100+ infra domains. Validated `suricata -T`
  (7.0.10, config loaded OK).

## Smoke test (in-repo)

Specimens (should match):
```
SourTrade_Assembled_PE_BunSection  specimens/assembled_sample.exe.bin
SourTrade_Browser_Assembler_JS     specimens/loader.js
```
Benign (should NOT match): clean — `benign/legit_streamsaver.js` (real StreamSaver.js download page,
registers a `/sw.js` but lacks the campaign message triple / config-assembly shape) and
`benign/legit_bun_app.exe.bin` (legit Bun standalone PE with `Bun`/`app.js` but no `.bun` malicious
section) both produce no hits.

Result: PASS on first iteration.

## Corpus FP test

PENDING — the corpus-scan service unreachable at authoring time (connection refused). Re-run:
a corpus false-positive scan.
Watch item: `SourTrade_Assembled_PE_BunSection` keys on a `.bun` section + Bun/JSC markers — any
legitimately Bun-compiled Windows app could carry those, so the rule additionally requires the `.bun`
section name specifically (Bun's own `--compile` uses `.bun`); corpus scan should confirm whether
benign Bun-compiled binaries in the corpus trip it. The JS assembler rule's config+streamsaver
combination is campaign-specific and low-FP-risk.

## Notes

- 3 SHA-256 hashes recorded to the digest hash store (family=sourtrade); all absent on MalShare at
  time of writing (per-victim polymorphism means public sample availability will stay low).
- Related in-repo: asyncrat-screenconnect-seo, steam-clickfix-xmrig (malvertising/loader chains).
