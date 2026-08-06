# QuickFox / FDMTP supply-chain — YARA test results

Rule file: `quickfox-fdmtp-supply-chain.yar` (3 rules)
Source report: Fortinet FortiGuard Labs, 2026-08-04
Authored: 2026-08-06

## Rules

1. **QuickFox_FDMTP_LoaderChain** (critical) — the sideload/decrypt/beacon chain.
   Anchors: campaign AES-128-ECB key `POt_L[Bsh0=+@0a.`; `quickfox\updated`
   staging path co-occurring with the sideload artifacts (`Microsoft.ServiceHosting.Tools.dll`
   / `csmonitor.exe` / `update.bin`); the `Dotnet-TcpDmtp` protocol tag with a
   registration endpoint; or two of the `GetCluster`/`GetEndpoints`/`GetNodes`
   endpoints together with the IME plugin hive or sideload DLL. Legit Azure-SDK
   filenames never fire alone — co-occurrence is required.
2. **QuickFox_FDMTP_LoaderShape** (high) — the injected-JS fingerprinting stage.
   Anchors: the `r1muVuL` base91 wrapper; or the `steam.exe` abort guardrail with
   4+ target-process tokens; or both fake Firebase SDK filenames with 2+ target
   tokens.
3. **QuickFox_FDMTP_IOC** (high) — C2 domains, cluster IPs (2-of to avoid single
   shared-host FPs), and the 10 SHA-256 sample hashes from the Fortinet appendix.

## In-repo smoke test

```
$ yara -r quickfox-fdmtp-supply-chain.yar specimens/
QuickFox_FDMTP_IOC          specimens/mock-ioc-report.txt
QuickFox_FDMTP_LoaderChain  specimens/mock-fdmtp-loader-config.txt
QuickFox_FDMTP_IOC          specimens/mock-fdmtp-loader-config.txt
QuickFox_FDMTP_LoaderShape  specimens/mock-injected-loader.js
QuickFox_FDMTP_IOC          specimens/mock-injected-loader.js

$ yara -r quickfox-fdmtp-supply-chain.yar benign/
(clean — no matches)
```

Every specimen hits its intended rule; the two structurally-similar benign files
(a legit Electron+Firebase bootstrap; Azure Compute Emulator install notes that
name `csmonitor.exe` / `Microsoft.ServiceHosting.Tools.dll`) stay clean, confirming
the co-occurrence guards hold.

## Corpus FP test

**PENDING** — the corpus-scan service was unreachable at author time (connection
refused). Re-run when the service is back:
`scan --rule-file quickfox-fdmtp-supply-chain.yar --max-hits 40 --budget 15m`.
For a recent family any corpus hit is a candidate FP to investigate/tighten.

## Notes

- Microsoft.ServiceHosting.Tools.dll and csmonitor.exe are legitimate Azure SDK
  components; the rules never key on either in isolation.
- No public samples on MalShare at author time (0/14 hashes present), so the
  hash strings in the IOC rule are the report appendix, unverified against a live
  specimen.
