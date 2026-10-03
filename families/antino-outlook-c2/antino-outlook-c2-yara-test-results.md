# Antino Outlook C2 — YARA test results

Family: `antino-outlook-c2`
Rule file: `antino-outlook-c2.yar`
Author: synthetic-detections
Date: 2026-10-03
Disclosure: 2026-10-03 (The Hacker News — Rust backdoor using Outlook/OneDrive C2, actor UAT-11587)

## Rules

1. `Antino_DllSideload_Behavioral` (critical, behavioural) — DLL sideloading via GatherOsState.exe
   with Outlook Graph API C2 subject prefix `command_req_`. Anchors on the sideloading pair
   (GatherOsState + slc.dll) combined with Graph API endpoint strings.
2. `Antino_IOC` (high) — static IOC sweep. Globally-unique tokens (`rsproxy.cn`,
   `d32tpl7xt7175h.cloudfront.net`) fire standalone; the Outlook subject prefix requires
   co-occurrence with DLL/host indicators; the zh-CN/UTC+08:00 build metadata requires both
   a DLL name and the subject prefix to fire.
3. `Antino_Specimen` (critical, specimen-pin) — structural anchor for the Antino DLL: PE file
   with Rust compilation markers (`.rustc` / `rust_panic` / `/rustc/`), the `command_req_`
   subject prefix, and Graph API endpoint strings.

## In-repo smoke test

Command: `yara -r antino-outlook-c2.yar specimens/` and `… benign/`

Specimens (should match — all pass):
- `specimens/antino-sideload-stub.dll.bin` → `Antino_DllSideload_Behavioral` + `Antino_IOC`
  (synthetic stub carrying the full indicator set)
- `specimens/antino-ioc-sweep.txt` → `Antino_DllSideload_Behavioral` + `Antino_IOC`
  (IOC reference document)
- `specimens/antino-behavioral-stub.txt` → `Antino_DllSideload_Behavioral` + `Antino_IOC`
  (behavioural pattern test)

Note: `Antino_Specimen` (rule 3) requires `pe.is_pe` and therefore does not match the synthetic
text stubs. The rule is validated by construction — a real Antino DLL carrying Rust compiler
artifacts plus the `command_req_` subject prefix and Graph API strings would match.

Benign (structurally similar — must NOT match, all clean):
- `benign/legit-graph-client.txt` — legitimate Graph API client referencing `/me/messages` and
  `/me/drive`; no sideloading indicators, no subject prefix. Confirms Graph API usage alone
  does not fire.
- `benign/legit-rust-binary.txt` — benign Rust binary metadata with `.rustc` / `rust_panic` /
  `/rustc/` markers; no Antino-specific strings. Confirms Rust artifacts alone do not fire.
- `benign/legit-cloudfront-config.txt` — legitimate CloudFront configuration with a different
  distribution ID. Confirms CloudFront references alone do not fire.

Result: 3/3 specimens hit their intended rules; 0/3 benign files matched.

## Known residual FP risk

`Antino_IOC` fires standalone on `rsproxy.cn` (a legitimate Rust crate mirror). This is accepted
because the domain is also C2 infrastructure for this campaign — any file referencing `rsproxy.cn`
warrants investigation. The domain alone does not trigger the behavioural or specimen rules.

## Corpus FP test

| Rule                           |  Slice | Hits | Verdict |
|--------------------------------|-------:|-----:|---------|
| Antino_DllSideload_Behavioral  | 10,118 |    0 | Clean   |
| Antino_IOC                     | 10,443 |    0 | Clean   |
