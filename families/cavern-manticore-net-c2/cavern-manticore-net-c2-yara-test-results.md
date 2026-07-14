# Test transcript — `cavern-manticore-net-c2.yar`

## Environment

- YARA: `4.5.2`
- Platform: `Linux localhost 6.12.90+deb13.1-amd64 x86_64 GNU/Linux`
- Date: 2026-07-14
- Sources:
  - <https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/>
  - <https://thehackernews.com/2026/07/iran-linked-hackers-use-new-cavern-c2.html>
  - <https://www.infosecurity-magazine.com/news/new-iran-hacking-group-targets/>

## Corpus

| File | Kind | Intended rule | Expected |
|---|---|---|---|
| `specimens/cavern_agent_strings.txt` | reconstructed agent string dump — `\Desktop\Modules\cavern\` PDB, `MYMUTEX123HELLP04`, `Cav3rn`, misspelled tunnel diagnostics, `.Cvn*.png`, `Cvn.cfg` | `…_Behavior` (+`…_IOC`) | match |
| `specimens/cavern_ioc_dump.txt` | C2 domains, `n-*.dll` modules, mutex, `Cvn.cfg` | `…_IOC` | match |
| `benign/legit_uxtheme_winshell.txt` | legitimate `uxtheme.dll` + `WinDirStat.exe` + ordinary .NET build path, no framework markers | none | no match |
| `benign/generic_dotnet_modules.txt` | generic `mhm.dll`/`db.dll`/`ode.dll` modules, plain word "Cavern", `X-User-token` + `/cac.aspx` | none | no match |
| `benign/random-200k.bin` | 200 KiB urandom | none | no match |

The rules key on the **Cavern framework's own tells**, never on the side-load
hosts: `uxtheme.dll` and `WinDirStat.exe` are legitimate binaries the agent
impersonates. `benign/legit_uxtheme_winshell.txt` carries both of those names
plus a normal .NET build path and proves they do not fire alone.
`benign/generic_dotnet_modules.txt` is the critical benign: it contains the
GENERIC module names (`mhm.dll`/`db.dll`/`ode.dll`) that were deliberately
**excluded** from the IOC rule, the plain English word "Cavern" (the behaviour
rule keys on the leetspeak `Cav3rn`), and the generic `X-User-token`/`/cac.aspx`
tokens (kept out of the firing condition) — proving none of those alias
legitimate identifiers into a hit.

The `…_Specimen` rule pins six **published** SHA-256 hashes (agent `uxtheme.dll`,
`n-HTCommp.dll` comms, `mhm.dll` file manager) via the `hash` module. The genuine
binaries are not redistributed in-repo, so no in-repo file fires that rule by
design — it is verified by clean compilation and matches only the real samples.

## Compile + smoke test

```
$ yara -w cavern-manticore-net-c2.yar /dev/null && echo "COMPILE OK"
COMPILE OK

$ yara -r -w cavern-manticore-net-c2.yar specimens/
Cavern_Manticore_IOC specimens//cavern_ioc_dump.txt
Cavern_Manticore_Agent_Behavior specimens//cavern_agent_strings.txt
Cavern_Manticore_IOC specimens//cavern_agent_strings.txt

$ yara -r -w cavern-manticore-net-c2.yar benign/
(no output — clean)
```

Specimens hit the intended rules; the structurally-similar benign set is clean.
Note during authoring the first benign draft enumerated the absent tokens by
name and self-matched — YARA matches literal strings regardless of surrounding
"no"/"absent" prose. The benign files were rewritten to describe the missing
markers without spelling them.

## Corpus FP test

Each string-based rule was additionally scanned against a large malware corpus.
The hash-pinned `…_Specimen` rule has no false-positive surface and is not
scanned. High-level results:

| Rule | Corpus samples | Matches | Read errors | Verdict |
|---|---|---|---|---|
| `Cavern_Manticore_IOC` | ~5,500 | 0 | 0 | clean |
| `Cavern_Manticore_Agent_Behavior` | ~11,700 | 0 | 0 | clean |

No corpus false positives — the misspelled internal strings, the
`MYMUTEX123HELLP` mutex, `Cvn.cfg`, the `n-*.dll` module names, and the
published C2 domains are effectively unique.
