# Test transcript — `codedome-pakistan-police-implant.yar`

## Environment

- YARA: `4.5.2`
- Platform: `Linux localhost 6.12.90+deb13.1-amd64 x86_64 GNU/Linux`
- Date: 2026-07-12
- Sources:
  - <https://www.sentinelone.com/labs/one-target-china-india-espionage-converge-on-pakistani-law-enforcement/>
  - <https://thehackernews.com/2026/07/hackers-weaponize-balochistan-police.html>
  - <https://therecord.media/india-pakistan-cyber-campaign-apt>

## Corpus

| File | Kind | Intended rule | Expected |
|---|---|---|---|
| `specimens/cms_plugin_strings.txt` | reconstructed string dump — `D:\codedome\...Client2.pdb`, fake-update lure, 360Safe masquerade, `xinshi`, Chinese log | `…_Behavior` | match |
| `specimens/ioc-dump.txt` | delivery URL/host, `cms_plugin.exe`, AsyncRAT C2, SHA-1s | `…_IOC` | match |
| `benign/legit_360safe_readme.txt` | legitimate Qihoo 360 `360Safe.exe` mention, ordinary build path, no codedome/lure | none | no match |
| `benign/normal_dotnet_build.txt` | a real `Client\Client2\obj\Debug\Client2.pdb` under a NON-codedome prefix + a similar-but-different success message | none | no match |
| `benign/random-200k.bin` | 200 KiB urandom | none | no match |

The critical benign is `benign/normal_dotnet_build.txt`: it shares the
`Client\Client2\obj\Debug\Client2.pdb` tail and a look-alike "Update complete"
message, but its build prefix is `D:\work\...` not `D:\codedome\`, and the lure
string is not the exact `"Update Complete! Please refresh the page"`. It proves
the behaviour rule keys on the codedome build environment plus an exact campaign
marker, not on a generic .NET client PDB. `legit_360safe_readme.txt` proves a
bare `360Safe.exe` reference (the file the .NET variant impersonates) does not
fire without the codedome co-occurrence.

The `…_Specimen` rule pins the three **published** cms_plugin.exe SHA-1 hashes
via the `hash` module. The genuine binaries are not redistributed in-repo, so no
in-repo file fires that rule by design — it is verified by clean compilation and
will match only the real artifacts.

## Compile + smoke test

```
$ yara -w codedome-pakistan-police-implant.yar /dev/null && echo "COMPILE OK"
COMPILE OK

$ yara -r -w codedome-pakistan-police-implant.yar specimens/
Codedome_CMS_Implant_IOC specimens//ioc-dump.txt
Codedome_CMS_Implant_Behavior specimens//cms_plugin_strings.txt

$ yara -r -w codedome-pakistan-police-implant.yar benign/
(no output — clean)
```

Specimens hit the intended rules; the structurally-similar benign set is clean.

## Corpus FP test

Pending — MalShare corpus scan (`a corpus scanner scan --rule-file … --max-hits 40
--budget 15m`) queued after commit; result appended here when the job returns.
