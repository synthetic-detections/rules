# PoeLLM — YARA test results

Family: `poellm`
Rule file: `poellm.yar`
Author: synthetic-detections
Date: 2026-10-09
Disclosure: 2026-10-07 (Lumen Black Lotus Labs — PoeLLM / Canto Incognito cryptomining botnet targeting AI infrastructure)

## Rules

1. `PoeLLM_Behavioral` (critical, behavioural) — ELF binary with `libgcrypt` masquerade
   filename combined with mining-related strings (xmrig, iron, kryptex, stratum+) or
   GitHub-based C2 resolution via `ejejejdfbbebe` repo. Requires ELF magic header.
2. `PoeLLM_IOC` (high) — static IOC sweep. The GitHub repo name `ejejejdfbbebe` fires
   standalone (globally unique). Active C2 IPs require at least one corroborator
   (libgcrypt filename, kryptex pool, or a second C2 IP). Historical C2 IPs require
   at least two together plus a corroborator.
3. `PoeLLM_Specimen` (critical, specimen-pin) — exact SHA-256 hashes of the three known
   PoeLLM ELF payloads reported by Black Lotus Labs.

## In-repo smoke test

Specimens (should match — all pass):
- `specimens/poellm-behavioral-stub.elf.bin` -> `PoeLLM_Behavioral` + `PoeLLM_IOC`
  (synthetic ELF stub carrying masquerade filename, miner strings, C2 IPs, and GitHub repo)
- `specimens/poellm-ioc-sweep.txt` -> `PoeLLM_IOC`
  (IOC reference document with all C2 IPs, GitHub repo, and corroborating strings)

Note: `PoeLLM_Specimen` (rule 3) uses `hash.sha256()` against known sample hashes and
therefore does not match synthetic stubs. The rule is validated by construction — only
files with the exact SHA-256 of a known payload will match.

Benign (structurally similar — must NOT match, all clean):
- `benign/legit-libgcrypt-header.txt` — GNU libgcrypt C header file. Contains "libgcrypt"
  but no mining strings, no C2 IPs, no ELF header. Confirms the libgcrypt name alone
  does not fire.
- `benign/legit-mining-config.txt` — legitimate crypto portfolio tracker config with
  "kryptex" exchange name and "xmrig" pool monitor reference. No ELF header, no
  `ejejejdfbbebe`, no C2 IPs. Confirms mining terminology alone does not fire.
- `benign/legit-github-raw-fetch.txt` — Python script using `raw.githubusercontent.com`
  to fetch Linux kernel changelogs. No `ejejejdfbbebe`, no mining strings, no C2 IPs.
  Confirms raw GitHub URL alone does not fire.

Result: 2/2 specimens hit their intended rules; 0/3 benign files matched.

## Known residual FP risk

`PoeLLM_IOC` fires standalone on the GitHub username `ejejejdfbbebe`. This is accepted
because the string is globally unique and strongly associated with this campaign. Any
file containing this string warrants investigation.

The `$miner_iron` string ("iron") in the behavioural rule is common in English text but
is guarded by the ELF magic check, `libgcrypt` filename requirement, and filesize limit,
making standalone FP extremely unlikely.

## Corpus FP test

| Rule              | Slice  | Hits | Verdict |
|-------------------|-------:|-----:|---------|
| PoeLLM_Behavioral | 11,674 |    0 | Clean   |
| PoeLLM_IOC        | 10,605 |    0 | Clean   |
