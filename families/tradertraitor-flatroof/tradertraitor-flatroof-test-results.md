# TraderTraitor FLATROOF — Test Results

## YARA scan results

### Specimens (should match)

| File | Rule | Result |
|------|------|--------|
| mock-flatroof-loader.sh | TraderTraitor_FLATROOF_Behavioral | MATCH |
| mock-flatroof-loader.sh | TraderTraitor_FLATROOF_IOC | MATCH |
| mock-flatroof-ioc-report.txt | TraderTraitor_FLATROOF_Behavioral | MATCH |
| mock-flatroof-ioc-report.txt | TraderTraitor_FLATROOF_IOC | MATCH |
| mock-flatroof-terraform-dropper.txt | TraderTraitor_FLATROOF_Behavioral | MATCH |
| mock-flatroof-terraform-dropper.txt | TraderTraitor_FLATROOF_IOC | MATCH |

### Benign (should NOT match)

| File | Rule | Result |
|------|------|--------|
| legit-terraform-provider.txt | all | CLEAN |
| legit-font-config.txt | all | CLEAN |
| legit-systemd-service.txt | all | CLEAN |

## Rule design notes

**Rule 1 — Behavioral (critical):** TraderTraitor_FLATROOF_Behavioral — loader AES key (PTa3WZPQZAjj55t@) paired with @@ENDFONT@@ marker, config keys co-occurrence, Terraform provider + lookalike domain, cross-platform install paths + persistence names, wallet targets + supply-chain anchor. Eight detection paths with filesize < 10MB guard.

**Rule 2 — IOC (high):** TraderTraitor_FLATROOF_IOC — globally unique tokens (hashicorp-terraform.io, PTa3WZPQZAjj55t@, u73adF39ZT, supportaru.serveftp.com, arusupport-region1-webhook.online) fire standalone. C2 staging URLs (diagnose subdomain, Pastebin dead drop) also standalone. Dynamic DNS domain (delay.servehttp.com) requires campaign anchor co-occurrence.

**Rule 3 — Specimen (critical):** TraderTraitor_FLATROOF_Specimen — MD5 pin on 12 known samples: 1 trojanized Terraform provider, 1 Bash loader, 6 encrypted FLATROOF payloads (.woff font-file disguise), 2 FLATROOF platform payloads, 2 ROOFDECK implants.

## Campaign context

- Attribution: TraderTraitor / Jade Sleet / UNC4899 / Slow Pisces (North Korea)
- Supply chain: trojanized Terraform provider (terraform-provider-awsbeta)
- Payload delivery: AES-encrypted binaries disguised as .woff font files
- Multi-platform: macOS (x86/arm64), Windows (PE32/PE32+), Linux (x86-64/ARM/aarch64/32-bit)
- Persistence: snap-imagent (Linux), imagent (macOS), powershell-config-service (Windows)
- C2: lookalike domains, dynamic DNS, Pastebin dead drop
- Targets: MetaMask, Phantom, Trust Wallet, Rabby cryptocurrency wallets
- Anti-analysis: Cortex XDR path detection

## Corpus FP test

Corpus FP scan pending.
