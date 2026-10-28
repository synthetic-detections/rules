# Convertr Magecart — YARA test results

Rule file: `convertr-magecart.yar` (3 rules)
Family: `convertr-magecart`
Sources: Sansec supply-chain research, BleepingComputer coverage.

## Rules
1. `Convertr_Magecart_JS_Skimmer_Behaviour` (critical) — behavioural
   detection of the JS obfuscation pattern: fromCharCode decode loop +
   indirect eval + no-cors POST with keepalive + base64 exfiltration,
   gated on checkout page reference. Survives IOC domain rotation.
2. `Convertr_Magecart_IOC` (high) — exfiltration domain list (1x0.is +
   14 historical rotation domains), Discord webhook IDs, and exfil script
   names (cartao.php, pagamento.php). Co-guarded with card/cpf/cvv/checkout
   field references to reduce false positives.
3. `Convertr_Magecart_Specimen_Pin` (critical) — SHA-256 pin of the
   infected Convertr Plausible analytics tracker captured 2026-10-26.

## Specimens (synthetic)

- `convertr-skimmer-behaviour.js` — reconstructed JS skimmer with
  fromCharCode decode loop, indirect eval, no-cors POST to 1x0.is/ws,
  btoa-encoded pipe-delimited payload, checkout gate check.
- `convertr-skimmer-ioc.js` — JS file containing exfiltration domains,
  Discord webhook IDs, cartao.php script path, and card/cpf/cvv field
  references matching the IOC rule.
- `plausible-analytics-clean.js` (benign) — clean Plausible Analytics
  tracker script with normal pageview event tracking.
- `checkout-form-validation.js` (benign) — generic e-commerce checkout
  form validation with card/cvv/cpf field names but no exfiltration
  patterns or domains.

## In-repo smoke test

Environment: YARA 4.5.2, Linux x86_64, 2026-10-28.

`yara -r convertr-magecart.yar specimens/` — 2 hits:

| Specimen | Rule matched |
|---|---|
| `convertr-skimmer-behaviour.js` | `Convertr_Magecart_JS_Skimmer_Behaviour` |
| `convertr-skimmer-ioc.js` | `Convertr_Magecart_IOC` |

`yara -r convertr-magecart.yar benign/` — **0 hits (clean)**.

Both benign files (clean Plausible tracker and generic checkout
validation) correctly avoided triggering either string-based rule.
The co-occurrence guards on the IOC rule prevent matching on
legitimate checkout code that references card/cvv/cpf fields.

## Corpus FP test

Corpus FP scan pending.
