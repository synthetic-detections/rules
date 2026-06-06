# ai-generated-detection-rules

A growing corpus of **AI-authored** YARA and Snort / Suricata detection
rules for current malware campaigns and vulnerabilities. Each rule ships
with reproducible specimens, structurally-similar benign cases, and a
test transcript that explains *why* the rule discriminates.

The rules in this repository were authored by an AI assistant
collaborating with a human operator. Each commit lists the public
source the rule was derived from and the test results that validated
it before commit. **Treat them as a starting point** — tune the
thresholds, package coordinates, and IOC lists for your environment
before deploying.

## What's covered

| Family | YARA | Snort / Suricata | Disclosure |
|---|:--:|:--:|---|
| `clawhavoc` | ✅ | — | 2026-05 — ClawHavoc / OpenClaw agent-skill marketplace compromise |
| `famous-chollima-packagist` | ✅ | — | 2026-05-30 Socket — DPRK supply-chain compromise of `roberts/leads` |
| `http2-bomb` | ✅ | ✅ | 2026-06-03 Codex / Calif.io — HTTP/2 DoS, CVE-2026-49975 (Apache) |
| `ironworm-npm-worm` | ✅ | — | 2026-06-04 JFrog / OX / Phoenix — Rust npm worm, eBPF, Tor C2 |
| `kimsuky-hellodoor` | ✅ | — | 2026-05 Securelist — Kimsuky / APT43 Rust PebbleDash variant |
| `kirki-cve-2026-8206` | — | ✅ | 2026-06-02 — Kirki WordPress plugin admin takeover |
| `marimo-cve-2026-39987` | — | ✅ | 2026-05-29 Sysdig — Marimo notebook `/terminal/ws` RCE |
| `miasma-redhat-npm` | ✅ | — | 2026-06-01 Wiz / Aikido / Snyk — Mini Shai-Hulud against `@redhat-cloud-services` |
| `miasma-v2-phantom-gyp` | ✅ | — | 2026-06-05 Semgrep / StepSecurity / Corgea — binding.gyp install-time abuse + forged SLSA provenance |
| `sidecopy-xenofiscal` | — | ✅ | 2026-06-02 Seqrite — APT36 / SideCopy XenoRAT against Afghan MoF |
| `vscode-github-token-theft` | ✅ | — | 2026-06-02 Ammar Askar — github.dev OAuth theft chain |
| `windows-search-uri-ntlm-leak` | ✅ | — | 2026-06-03 Huntress — unpatched NTLM leak (no CVE; Microsoft declined to fix) |

## Layout

```
families/<campaign-or-family>/
  <name>.yar                       - YARA rule file (if any)
  <name>-yara-test-results.md      - YARA test transcript (if applicable)
  <name>.rules                     - Snort syntax rule file (if any)
  <name>-snort-test-results.md     - Snort/Suricata test transcript (if applicable)
  specimens/                       - YARA should-match samples, committed on disk
  benign/                          - YARA should-not-match samples, committed on disk
  pcaps/                           - PCAPs for Snort/Suricata smoke tests
  pcap-gen.py                      - scapy synthesiser for the PCAPs
families/_lib/h2c_http_helper.py   - shared scapy TCP/HTTP helper used by pcap-gen.py
```

A family folder co-locates everything related to one threat — wire and
filesystem rules side-by-side, with their own specimens, benigns, PCAPs,
and transcripts. Some families have only YARA, some have only Snort, one
(`http2-bomb`) has both.

## Conventions

### YARA

Three-rule shape per family wherever the disclosure supports it:

1. **Behavioural** (`severity = "critical"`) — anchors on the operational
   shape (markers, co-occurring features) so it survives rotation.
2. **IOC** (`severity = "high"`) — `any of them` over specific tokens,
   tightened with co-occurrence guards where individual tokens alias
   legitimate identifiers (e.g. legit package names).
3. **Specimen pin** (`severity = "critical"`) — exact hash or structural
   anchor + filesize band on a known sample.

Required `meta:` fields: `description`, `author = "synthetic-detections"`,
`date` (ISO), `severity`, `family`, `reference`.

### Snort / Suricata

Authored in classic Snort 2 rule syntax and validated against
**Suricata 7.0.10** (Snort itself is not packaged for Debian 13, and
Suricata reads Snort syntax natively while also providing an HTTP/2
inspector that Snort 2 lacks).

Each rule includes `msg`, `flow`, `content` / `pcre`, `reference`,
`classtype`, `sid`, and `rev`. Suricata-only keywords (e.g.
`http2.frametype`) are labelled in the rule's header comment.

### Hard-won lessons baked into the rules

- **YARA IOC tightening:** an `any of them` over package coordinates is
  too loose — legitimate packages legitimately mention their own names.
  Require co-occurrence with a higher-confidence anchor (theme phrase,
  fingerprint UA, specific bad version). See
  `miasma-redhat-npm-test-results.md` for the FP that drove the fix.
- **Suricata reassembly dedup:** repeated `content:` matches on a TCP
  stream are deduplicated to one event per flow under default stream
  inspection — `detection_filter` never accumulates. Pin per-packet
  inspection with `dsize:N;` where N is the exact target frame size.
  Used in `http2-bomb.rules` sids 9000002 and 9000003.

## Running the smoke tests

### YARA

```bash
cd families/<family>
yara -r -s <family>.yar specimens/   # should produce alerts
yara -r -s <family>.yar benign/      # should produce no alerts
```

### Snort / Suricata

```bash
sudo apt-get install -y --no-install-recommends suricata python3-scapy tcpdump
sudo systemctl stop suricata && sudo systemctl disable suricata   # don't run on the live interface

cd families/<family>
python3 pcap-gen.py                  # writes pcaps/benign-*.pcap and pcaps/<attack>-*.pcap
for p in pcaps/*.pcap; do
  out=/tmp/sout-$(basename "$p" .pcap)
  rm -rf "$out" && mkdir -p "$out"
  suricata -k none -r "$p" -S <family>.rules -l "$out" --runmode single
  echo "--- $(basename "$p") ---"
  cat "$out/fast.log"
done
```

`-k none` disables checksum validation; scapy-synthesised PCAPs can carry
invalid TCP/IP checksums.

## Status

- **Authored**: AI, supervised by the operator. Each commit message
  describes what was changed and the test result that validated it.
- **Provenance**: see commit history and per-family `*-test-results.md`
  for the public source(s) each rule was derived from.
- **Not yet published**: this repo is currently a local working copy.
  Mid-term goal is publication on GitHub with a permissive open-source
  licence.

## Caveats and honesty

- **AI-authored, human-verified.** The rules and their tests are written
  by the assistant; the human operator reviewed and committed each one.
  Verifying detection on a real sample of the threat is the deploying
  team's responsibility.
- **Synthetic specimens.** Where we don't hold real malware samples, the
  specimens are minimal structurally-correct files that prove condition
  logic. They are not byte-equivalent to the in-the-wild artefacts.
- **Public-source dependence.** Some IOCs (package coordinates, C2 IPs,
  staging hostnames) age fast. The behavioural rule in each family is the
  rotation-resistant detection; the IOC rule is for the current window
  and retro hunts.

## Licence

To be decided before publication. Likely permissive (Apache-2.0 or MIT).
