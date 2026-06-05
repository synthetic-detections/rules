# HelloDoor YARA rule — test transcript

Companion to `hellodoor.yar`. Records the smoke-test results so the
rule's expected behaviour is documented alongside the rule itself.

> **Samples live in the research repo.** The `specimens/` and `benign/`
> directories referenced below are committed to
> `~/repos/another repo/kimsuky-hellodoor/`, not in this repo.
> To re-run the smoke test:
> ```
> cd ~/repos/another repo/kimsuky-hellodoor
> yara -r ~/repos/ai-generated-detection-rules/families/kimsuky-hellodoor/hellodoor.yar specimens/
> yara -r ~/repos/ai-generated-detection-rules/families/kimsuky-hellodoor/hellodoor.yar benign/
> ```
> Re-verified 2026-06-05 after relocation; results unchanged from the
> table below.

## Environment

| Item | Value |
|---|---|
| YARA version | 4.5.2 (classic), 1.17.0 (YARA-X) |
| Platform | Debian 13 (Linux 6.12) |
| Test date | 2026-05-30 |

## Revision history

| Date | Change |
|---|---|
| 2026-05-30 | Initial 3-rule version with synthetic MZ+padding specimen |
| 2026-05-30 | Hardening pass: dropped weak `$cmd_set` regex (anchored on a 1-byte atom); added `wide` modifier to phonetic-typo strings (ASCII-only, so widening is safe — unlike the emoji strings, where `wide` would mangle multi-byte UTF-8); rule 3 now uses portable PE+DLL gate `uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and (pe.characteristics & pe.DLL) != 0`; specimens rebuilt as minimal valid PE32 DLLs so the `pe` module can parse them; verified under both engines. |

## Test corpus

Five files: three should match, two should not. Specimens are committed
under `specimens/` and `benign/` so the test is reproducible.

| File | Expected | Got |
|---|---|---|
| `specimens/dll-strings.bin` — synthetic Rust DLL (MZ + padding + LLM tells + RC4 key + C2 host) | `Kimsuky_HelloDoor_LLM_Tells` + `Kimsuky_HelloDoor_IOCs` + `Kimsuky_HelloDoor_PE_DLL` | ✓ all three |
| `specimens/ioc-dump.txt` — flat IOC list (C2, RC4, persistence) | `Kimsuky_HelloDoor_IOCs` only | ✓ |
| `specimens/persistence.reg` — verbatim Windows .reg from the HelloDoor disclosure | `Kimsuky_HelloDoor_IOCs` only | ✓ |
| `benign/normal.dll` — synthetic PE with generic Rust panic strings, no HelloDoor signals | No match | ✓ no match |
| `benign/random.bin` — 5KB urandom | No match | ✓ no match |

Raw output:

```
$ yara -r hellodoor.yar specimens/
Kimsuky_HelloDoor_IOCs specimens//ioc-dump.txt
Kimsuky_HelloDoor_IOCs specimens//persistence.reg
Kimsuky_HelloDoor_LLM_Tells specimens//dll-strings.bin
Kimsuky_HelloDoor_IOCs specimens//dll-strings.bin
Kimsuky_HelloDoor_PE_DLL specimens//dll-strings.bin

$ yara -r hellodoor.yar benign/
(no output, exit 0)

$ yr scan -r hellodoor.yar specimens/
Kimsuky_HelloDoor_IOCs specimens/persistence.reg
Kimsuky_HelloDoor_IOCs specimens/ioc-dump.txt
Kimsuky_HelloDoor_LLM_Tells specimens/dll-strings.bin
Kimsuky_HelloDoor_IOCs specimens/dll-strings.bin
Kimsuky_HelloDoor_PE_DLL specimens/dll-strings.bin

$ yr scan -r hellodoor.yar benign/
(no output, exit 0)
```

## Why the benign files don't false-positive

`benign/normal.dll` has the PE magic, Rust panic-handler strings, and is
sized within the rule 3 band — i.e. it satisfies the necessary preconditions
for the PE rule. It still doesn't match because rule 3 requires *at least
one HelloDoor-unique string* alongside the PE magic, and the benign DLL
contains none of: the RC4 key, the emoji telemetry, or the phonetic typos.

Rule 1 (LLM tells) requires **both** an emoji string and a phonetic typo.
Either alone is plausible in benign software — some apps use emoji logging,
and typos exist everywhere. The co-occurrence is the AI-authorship
fingerprint and is what makes rule 1 high-fidelity.

Rule 2 (IOCs) is `any of them` and would catch a benign file that legitimately
mentioned the HelloDoor strings (e.g. a threat-intel note). This is expected,
hence the `high` rather than `critical` severity.

## Coverage notes

- **Rule 1** is the strongest signal. The Securelist disclosure stresses that
  the combination of emoji-laden production telemetry and phonetic typos
  (`decrytion failed`, `autorum failed`) in a Rust DLL targeting GPKI is
  unprecedented in human-authored DPRK malware. Operators may strip the
  emoji in later waves; the phonetic typos are harder to spot in review and
  will likely persist longer.
- **Rule 2** will catch:
  - the Cloudflare-Tunnel C2 host (will rotate post-disclosure)
  - the RC4 key (more resilient — changing it requires reissuing the
    server-side decryption logic)
  - the PebbleDash 10-char-repeating query-string structure (very durable;
    it is a family-level habit across multiple Kimsuky implants)
  - the regsvr32 persistence registry pattern (specific value name `tdll`)
- **Rule 3** is intentionally permissive on the PE-side: MZ + size band +
  *any* HelloDoor string. The discriminator strings are unique enough to
  carry the false-positive risk on their own; the PE/size gating just keeps
  the rule from firing on text dumps that happen to contain them.

## Caveats

1. The `dll-strings.bin` specimen is **not a real Mach-O/PE**. It is an MZ
   header followed by padding and string blobs. The condition logic and
   string detection are exercised correctly; full PE-section walking would
   require a real sample. Pull a verified-malicious HelloDoor sample from
   VT (Securelist did not publish hashes in the public writeup; check their
   private feed or the AV vendor's blog updates) for full validation.

2. Rule 1 anchors on Securelist-verbatim strings. Post-disclosure, operators
   may rewrite the telemetry. If the emoji vanish, rule 1 will start
   missing; rule 2's RC4 key and PebbleDash query fingerprint compensate
   until those rotate too.

3. The Linux/macOS variants (if any emerge) are not covered. Rule 3 is
   PE-only; the LLM-tells rule is format-agnostic and would catch a Rust
   ELF carrying the same strings, but it has not been tested against one.

4. **`hellodoor/` source files match rule 2** by design — they contain the
   IOCs as documentation. This is the same expected behaviour as the
   ClawHavoc IOC rule and is the reason rule 2 is `high` not `critical`.

## How to invoke

```bash
yara -r -s hellodoor.yar /path/to/scan/target/
```

Same flags as the rest of the corpus: `-r` recursive, `-s` for forensic
string output during triage. Drop `-s` for one-line-per-match in pipelines.
