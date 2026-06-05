# Test transcript — `miasma-redhat-npm.yar`

## Environment

- YARA: `4.5.2`
- Platform: `Linux host 6.12.88+deb13-amd64 x86_64 GNU/Linux`
- Date: 2026-06-05
- Sources:
  - <https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages>
  - <https://www.aikido.dev/blog/red-hat-npm-packages-compromised-credential-stealing-worm>
  - <https://snyk.io/blog/miasma-supply-chain-attack-malicious-code-redhat-cloud-services-npm-packages/>
  - <https://access.redhat.com/security/vulnerabilities/RHSB-2026-006>

## Corpus

| File | Kind | Intended rule | Expected |
|---|---|---|---|
| `specimens/malicious-index.js` | obfuscated JS with `eval(var)`, ROT-decode helper, GCP UA, credential targets, ~70 KiB | `…_ObfuscatedIndexJS` (+ IOC fallback via GCP UA) | match |
| `specimens/package-redhat.json` | `@redhat-cloud-services/frontend-components@7.7.3` with `preinstall: node ./index.js` | `…_NpmPackageManifest` | match |
| `specimens/ioc-dump.txt` | text dump of compromised package list + Miasma theme + GCP UA | `…_IOC` | match |
| `benign/legit-redhat-package.json` | real-shape `@redhat-cloud-services/frontend-components@7.7.1` with no `preinstall` and no IOC tokens | none | no match |
| `benign/normal-index.js` | a normal React component module, no eval, no GCP UA, no credential sweep | none | no match |
| `benign/random-200k.bin` | 200 KiB urandom | none | no match |

The benign `legit-redhat-package.json` is structurally similar to the
malicious case — same package coordinate, same scope — but lacks the
`preinstall` hook and the IOC tokens. It's the critical benign for proving
the rules don't fire on legitimate `@redhat-cloud-services` packages.

## Compile check

```
$ yara -w families/miasma-redhat-npm/miasma-redhat-npm.yar /dev/null && echo "COMPILE OK"
COMPILE OK
```

## Run — should-match

```
$ yara -r families/miasma-redhat-npm/miasma-redhat-npm.yar families/miasma-redhat-npm/specimens/
Miasma_IOC                    …/ioc-dump.txt
Miasma_NpmPackageManifest     …/package-redhat.json
Miasma_ObfuscatedIndexJS      …/malicious-index.js
Miasma_IOC                    …/malicious-index.js
```

## Run — should-not-match

```
$ yara -r families/miasma-redhat-npm/miasma-redhat-npm.yar families/miasma-redhat-npm/benign/
(no output — clean)
```

## Result summary

| File | Expected | Observed | Result |
|---|---|---|---|
| `malicious-index.js` | ObfuscatedIndexJS + IOC (via GCP UA + theme) | both | PASS |
| `package-redhat.json` | NpmPackageManifest | fired | PASS |
| `ioc-dump.txt` | IOC | fired | PASS |
| `legit-redhat-package.json` | clean | clean | PASS |
| `normal-index.js` | clean | clean | PASS |
| `random-200k.bin` | clean | clean | PASS |

## The IOC-tightening lesson

First iteration of `Miasma_IOC` used `any of them` over the package-name list.
That caused the legit `@redhat-cloud-services/frontend-components` package.json
to match — the coordinate string alone is in both the malicious and
legitimate manifests. Tightened to:

- `$theme_miasma` (verbatim "Miasma: The Spreading Blight") — fires alone
- `$gcp_ua` (the Google API UA fingerprint) — fires alone
- any `$ver*` (specific known-bad version pin like `frontend-components@7.7.2`) — fires alone
- `$theme_spartan` only counts when paired with a package coordinate
  (raw "spartan" is a noisy English word)
- two or more package coordinates co-occurring — catches IOC dumps and
  threat-intel writeups but not a single legitimate manifest

Legit `frontend-components@7.7.1` package.json now cleans because it has
only one package coordinate and none of the higher-confidence markers.

## Why the benign cases don't false-positive

- **`legit-redhat-package.json`** — same scope and package name as the
  malicious case but no `preinstall` field, no `index.js` invocation, no
  IOC tokens, only one matching package coordinate (so the 2-of-pkgs
  branch doesn't trip), no version-pin string, no theme marker, no GCP UA.
- **`normal-index.js`** — contains no `eval(...)`, no ROT-decode helper,
  no GCP UA, no credential-sweep target list. The obfuscated-JS rule
  requires `eval()` *and* either the GCP UA *or* the helper-plus-targets
  combination; the benign satisfies none of those.
- **`random-200k.bin`** — urandom.

## Caveats

- **Per-infection uniquely-encrypted payload.** Wiz explicitly notes
  hash-based IOCs are not durable for Miasma. The behavioural rule keys
  on the *shape* of the obfuscation (eval + ROT + UA + credential sweep)
  rather than any specific hash.
- **GCP UA is fingerprintable.** A future Miasma variant rotating the UA
  string would silently evade `$gcp_ua`. The `$rot_helper_a/b` +
  credential-target co-occurrence remains.
- **IOC severity is `high`** because public writeups will contain the
  package names and theme markers; the version-pin and GCP-UA branches
  are the high-confidence triggers.
- **Sibling family.** `[[ironworm-npm-worm]]` — the Rust+eBPF evolution
  of the same Mini Shai-Hulud playbook. Watch for IronWorm-style
  preinstall + ELF dropper appearing in `@redhat-cloud-services` packages
  too; cross-family rules would benefit from both files being scanned.

## Not covered

- **GitHub-account compromise.** Initial access per RHSB-2026-006 was a
  hijacked GitHub account; the OIDC pipeline then dutifully published
  the poisoned versions. YARA can flag the malicious commits' artefacts;
  it can't see the auth-side compromise. Pair with GitHub audit-log
  review for the implicated organisations.
- **Trusted Publishing token theft.** Same caveat as IronWorm — npm
  registry-side monitoring required.
