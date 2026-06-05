# Test transcript — `famous-chollima-packagist.yar`

## Environment

- YARA: `4.5.2`
- Platform: `Linux host 6.12.88+deb13-amd64 x86_64 GNU/Linux`
- Date: `2026-06-01T23:55:20+02:00`
- Source advisory: <https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package>

## Corpus

| File | Kind | Intended rule | Expected |
|---|---|---|---|
| `specimens/loader-marker.js` | synthetic JS, contains campaign markers | `…_Loader` (marker branch) | match |
| `specimens/loader-shape.js`  | synthetic JS, blockchain RPC + spawn + eval | `…_Loader` (co-occurrence branch) | match |
| `specimens/ioc-dump.txt`     | text dump of IOCs | `…_IOC` | match |
| `benign/tailwind.config.js`  | real-shape Tailwind config (no payload) | none | no match |
| `benign/random-200k.bin`     | 200 KiB urandom | none | no match |

The third rule (`…_Specimen`) pins SHA-256 `96afdba8…77dc3` of the real `tailwind.js`. The
actual bytes were not republished by Socket and are not held locally, so the rule cannot
be validated end-to-end here. It compiles, and the size band + `tailwind` token gate
prevents it from matching any of the corpus files — verified by the `benign/` clean run
and by the absence of `…_Specimen` from the specimen output.

## Compile check

```
$ yara -w families/famous-chollima-packagist/famous-chollima-packagist.yar /dev/null && echo "COMPILE OK"
COMPILE OK
```

## Run — should-match (`specimens/`)

```
$ yara -r -s families/famous-chollima-packagist/famous-chollima-packagist.yar \
        families/famous-chollima-packagist/specimens/
FamousChollima_Packagist_TailwindJS_Loader families/famous-chollima-packagist/specimens//loader-shape.js
0x143:$rpc_tron: trongrid
0x17f:$rpc_aptos: aptoslabs
0x19d:$rpc_bsc1: bsc-dataseed
0x1cf:$rpc_eth: eth_getTransactionByHash
0x2ac:$spawn1: windowsHide
0x29c:$spawn2: detached
0xb6:$eval: eval(varname)
0x25f:$eval: eval(payloadStr)
FamousChollima_Packagist_TailwindJS_Loader families/famous-chollima-packagist/specimens//loader-marker.js
0x13d:$m_global1: global['!']='9-0264-2'
0x159:$m_obf_id: _$_1e42
0x17f:$m_artef: rmcej%otb%
FamousChollima_Packagist_TailwindJS_IOC families/famous-chollima-packagist/specimens//ioc-dump.txt
0x1e:$pkg: roberts/leads
0x92:$pkg: roberts/leads
0xa5:$branch: drewroberts/feature/test-case
0xd9:$commit: 6c5c3c7655ce76399af11126b7e9a9058eb2e45d
0x11b:$tron1: TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP
0x140:$tron2: TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG
0x180:$apt1: 0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e
0x1c5:$apt2: 0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3
0x225:$xor1: 2[gWfGj;<:-93Z^C
0x238:$xor2: m6:tTh^D)cBz?NM]
0x269:$h_file: 96afdba882046385242cbed46871e41147c8055c5d9eff7460847b2c01a77dc3
0x2c1:$h_arch: 522b28a2f78771715497ba53729d4ab9a50e982322c391379f3bddf7c8cb363f
```

## Run — should-not-match (`benign/`)

```
$ yara -r -s families/famous-chollima-packagist/famous-chollima-packagist.yar \
        families/famous-chollima-packagist/benign/
(no output — clean)
```

## Result summary

| File | Expected | Observed | Result |
|---|---|---|---|
| `loader-marker.js` | `…_Loader` | `…_Loader` (via `$m_*`) | PASS |
| `loader-shape.js`  | `…_Loader` | `…_Loader` (via co-occurrence) | PASS |
| `ioc-dump.txt`     | `…_IOC` | `…_IOC` (all 12 IOC anchors hit) | PASS |
| `tailwind.config.js` | clean | clean | PASS |
| `random-200k.bin`  | clean | clean | PASS |

## Why the benign cases don't false-positive

- **`tailwind.config.js`** — legitimate Tailwind config. Fails every rule because:
  - `…_Loader` marker branch: none of `global['!']='9-0264-2'`, `global['_V']='A9-0264-2'`,
    `_$_1e42`, `rmcej%otb%` are present.
  - `…_Loader` co-occurrence branch: zero blockchain-RPC anchors, no `windowsHide`, no
    `detached`, no `eval(...)`.
  - `…_IOC`: no wallet, key, hash, package, or commit token present.
  - `…_Specimen`: SHA-256 does not match the pinned digest (and the file is too small to
    plausibly equal it).
- **`random-200k.bin`** — 200 KiB urandom. Probability of any multi-byte literal appearing
  is negligible; verified clean.

## Caveats

- All `specimens/*` are **synthetic** — modelled on the disclosure but stripped of any
  payload retrieval or execution. They prove the rule's condition logic, not byte-level
  fidelity against the real `tailwind.js`.
- `…_Specimen` (SHA-256 pin) is **untested on the live sample**: the original `tailwind.js`
  bytes are not redistributed by Socket. The rule compiles and is filesize-gated; it will
  fire on any future republication of the exact hash.
- Post-disclosure rotation risk: the campaign markers in the marker branch
  (`9-0264-2`, `_$_1e42`, `rmcej%otb%`) are operator-controlled strings and may change in
  a future build. The co-occurrence branch (blockchain RPC + hidden detached spawn + eval)
  is the rotation-resistant fallback.
- The `…_IOC` rule is `severity = "high"` rather than critical because public threat-intel
  writeups will legitimately contain the same wallet / hash strings. Triage by file
  context (e.g. ignore `*.md`, `*.pdf`, `*-ioc*` paths).

## Not covered

- Encrypted next-stage retrieved from BSC `eth_getTransactionByHash` — this rule covers the
  loader, not the final-stage RAT (BeaverTail / DEV#POPPER / OmniStealer). Pair with
  existing end-stage detectors for those families.
- Other compromised packages on Packagist or npm published by the same operator — none
  named in this advisory; widen the IOC rule scope when more coordinates appear.
