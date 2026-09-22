# indexed-btree-npm-2026 — YARA test results

Family: `indexed-btree-npm-2026`
Rules: `INDEXEDBTREE_Loader_Behavior` (critical), `INDEXEDBTREE_IOC` (high), `INDEXEDBTREE_Package_Pin` (critical)
Date: 2026-09-22

## Smoke test (in-repo)

Specimens (should match):

| file | rules hit |
|---|---|
| specimens/indexed-btree-loader.js | Loader_Behavior, IOC, Package_Pin |
| specimens/indexed-btree-iocs.txt | IOC |

`specimens/cluster-package-names.txt` deliberately does NOT match: package
names alone are too weak (would flag benign lockfiles); `Package_Pin` requires
a cluster name AND the runtime-loader method or Sepolia contract to co-occur.

Benign (should stay clean):

| file | result |
|---|---|
| benign/legit-sorted-btree.js | clean (genuine `sorted-btree`, no C2) |
| benign/legit-ecdh-util.js | clean (legit X25519 ECDH, no contract/tokens) |

Result: all specimens hit, both benign files clean.

## Design notes

- `Loader_Behavior` is the durable behavioural rule: the loader wired into
  `BTree.prototype.set` co-occurring with a Sepolia-contract X25519/AES
  second-stage fetch. It does not depend on any single IOC.
- `IOC` needs >=2 hard indicators to avoid firing on IOC write-ups that quote
  one value.
- Hard indicators (Sepolia contract, X25519 pubkey, Slack/Telegram bot tokens,
  RPC keys) are campaign-specific and will decay as infra is rotated; the
  behavioural rule is the long-lived detector.

## Corpus FP test

Corpus false-positive scan pending.
