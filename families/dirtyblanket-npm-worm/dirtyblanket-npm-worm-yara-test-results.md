# DirtyBlanket npm worm — YARA test results

Family: `dirtyblanket-npm-worm`
Rule file: `dirtyblanket-npm-worm.yar`
Author: synthetic-detections
Date: 2026-10-03
Disclosure: 2026-10-03 (SafeDep — Express.js typosquat worm; npm account "dirtyblanket")

## Rules

1. `DirtyBlanket_NpmManifest` (critical, behavioural) — `package.json` carrying a DirtyBlanket
   typosquat package name (xeprews, express-javascript, express-nodejs, react-nodejs, exprdd,
   exprrdd, exptrdd, exptred, exptredd) with a lifecycle hook (preinstall/postinstall).
2. `DirtyBlanket_IOC` (high) — static IOC sweep. Globally-unique tokens (Tor C2 onion
   `s5n2uyo6gb6dhirsm5pihwohi6e7ayrwojx4xjow4cqabmbowpezenid`, campaign email
   `dirtyblanket@proton.me`) fire standalone; the fake systemd service name `systemd-fontd`
   requires co-occurrence with the Codeberg account `hellscripter` or the npm account
   `dirtyblanket` to avoid matching legitimate systemd references.
3. `DirtyBlanket_Specimen` (critical, specimen-pin) — SHA-256 pins for `linux.sh`
   (`65f0a95b…919577`) and `systemd-fontd` (`2c9dbc14…9793c2`), plus a heuristic fallback
   (file < 1 MB carrying the Tor C2 onion address and fake service name).

## In-repo smoke test

Command: `yara -r dirtyblanket-npm-worm.yar specimens/` and `… benign/`

Specimens (should match — all pass):
- `specimens/package.json` → `DirtyBlanket_NpmManifest` (typosquat name "xeprews" + preinstall hook)
- `specimens/dirtyblanket-ioc-sweep.txt` → `DirtyBlanket_IOC` + `DirtyBlanket_Specimen` (carries
  the full IOC set including Tor C2 and fake service name)
- `specimens/dropper-stub.sh` → `DirtyBlanket_IOC` + `DirtyBlanket_Specimen` (synthetic stub
  exercising the Tor C2 + systemd-fontd heuristic)

Benign (structurally similar — must NOT match, all clean):
- `benign/package.json` — legitimate Express package with a preinstall hook running a different
  script; confirms rule 1 keys on the typosquat *name*, not generic preinstall usage.
- `benign/legit-systemd-config.txt` — legitimate systemd unit file; confirms `systemd-fontd`
  alone does not fire.
- `benign/ssh-deploy-helper.sh` — legitimate deployment script referencing `authorized_keys` and
  `web.archive.org`; confirms propagation-vector strings alone do not fire without a campaign
  anchor.

Result: 3/3 specimens hit their intended rules; 0/3 benign files matched.

## Known residual FP risk

`DirtyBlanket_NpmManifest` fires on any package.json whose `"name"` is one of the nine typosquat
identifiers. These names are campaign-specific and do not collide with legitimate packages.

## Corpus FP test

| Rule                      | Slice | Hits | Verdict |
|---------------------------|------:|-----:|---------|
| DirtyBlanket_NpmManifest  | 6,385 |    0 | Clean   |

DirtyBlanket_IOC and DirtyBlanket_Specimen scans pending.
