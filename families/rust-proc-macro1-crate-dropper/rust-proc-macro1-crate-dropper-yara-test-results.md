# rust-proc-macro1-crate-dropper — YARA test results

Family: `rust-proc-macro1-crate-dropper`
Rules: `Rust_ProcMacro1_Dropper_Behavior` (critical), `Rust_ProcMacro1_Dropper_IOC` (high),
`Rust_ProcMacro1_Dropper_Specimen` (critical).
Disclosure: 2026-08-20 — crates.io / Rust Security Response WG supply-chain compromise.
Sources:
- https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/
- https://www.stepsecurity.io/blog/arrayref-rust-crate-supply-chain-attack
- https://www.aikido.dev/blog/two-popular-rust-crates-arrayref-and-append-only-vec-compromised-in-supply-chain-attack
- https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html

## Artifacts keyed on
- **Build.rs dropper shape**: base64 URL-fragment arrays `SRC_URL_PARTS` / `END_URL_PARTS`
  (chunks `aHR0cHM6Ly8=`, `MjMuMjU0Lg==`, `MTY1Lg==`, `MTEyOg==`, `OTA4OS8=`, `NDQz` →
  `https://23.254.165.112:9089/` and `23.254.165.112:443`); TLS-verify bypass
  (`AcceptAll` / `ServerCertVerifier` / `ServerCertVerified::assertion`); `run_unix_payload`;
  drop/exec sinks `/tmp/rust-setup`, `rust-setup.ps1`, `rust-setup-launch.vbs`,
  `std::mem::forget(child)`; OS/arch payload selectors `rust-crate_0.1.0`..`0.4.0`.
- **Infrastructure**: `23.254.165.112:9089` (payload), `23.254.165.112:443` (C2),
  stage-2 C2 `23.254.167.216`, `23.254.167.107`, `hwsrv-798836.hostwindsdns.com` (Hostwinds).
- **Persistence**: `~/.config/AzureKits`, `~/.config/ServiceKit`, `MonoService`, `MonoXpc`.
- **Attacker crates**: `proc-macro1`, `proc-macro-en`, `aovine`, `arone`, `aronenao`, `tinymember`.
- **SHA-256 (.crate)**: arrayref-0.3.10 `25ad70…9373ae`, proc-macro1-1.0.107 `611981…b34d4`,
  proc-macro1-1.0.106 `b5c1b5…fbe436`.

Poisoned crates: `arrayref 0.3.10`, `internment 0.8.7`, `append-only-vec 0.1.9` (last safe:
0.3.9 / 0.8.6 / 0.1.8). Lure: arrayref 0.3.5–0.3.9 were yanked so cargo's "consider a version
that is not yanked" nudge steered resolution to malicious 0.3.10.

## In-repo smoke test — PASS
```
$ yara -w rust-proc-macro1-crate-dropper.yar /dev/null      # compile check
(OK — no warnings)

$ yara -r rust-proc-macro1-crate-dropper.yar specimens/
Rust_ProcMacro1_Dropper_IOC       specimens/proc-macro1-Cargo.toml.txt
Rust_ProcMacro1_Dropper_Behavior  specimens/proc-macro1-build.rs
Rust_ProcMacro1_Dropper_IOC       specimens/proc-macro1-build.rs
Rust_ProcMacro1_Dropper_Specimen  specimens/proc-macro1-build.rs

$ yara -r rust-proc-macro1-crate-dropper.yar benign/
(no output — clean)
```
- `specimens/proc-macro1-build.rs` — reconstructed weaponised build.rs; matches all three rules.
- `specimens/proc-macro1-Cargo.toml.txt` — reconstructed manifest surface (injected dependency,
  build-dependencies, attacker crate names, infra, hashes); matches the IOC rule.
- `benign/legit-proc-macro2-build.rs` — real proc-macro2-style feature-probe build.rs (shares the
  "build.rs in a proc-macro crate" surface, none of the dropper markers). Correctly NOT matched.
- `benign/legit-http-client-Cargo.toml.txt` — legit crate pulling `base64` + `ureq` + `rustls` as
  ordinary runtime deps (the same library trio the dropper abuses at build time). Correctly NOT matched.

## Corpus false-positive scan
Behavioral rule (`Rust_ProcMacro1_Dropper_Behavior`) submitted as a single rule. IOC and Specimen
rules are hash/infra/structure-pinned (near-zero FP by construction — the sample SHA-256s and the
`SRC_URL_PARTS`/`END_URL_PARTS` array names do not occur in benign files) and are not corpus-swept.

The behavioral condition cannot be tripped by any single generic token: it requires the two build.rs
URL-fragment array names together, or a TLS-verify-bypass helper co-occurring with a drop/exec sink,
or the named `run_unix_payload` routine plus a drop artifact, or three host-reassembly fragments plus
a drop/selector token, or two distinct `rust-crate_*` payload selectors plus a drop path.

| Date | Samples scanned | Matches | Read-errors | Verdict |
|---|---|---|---|---|
| 2026-08-22 | 10,115 | 0 | 0 | CLEAN — no false positives; the behavioral condition needs the chunked-URL constants plus a dropper artefact, nothing generic trips it |
