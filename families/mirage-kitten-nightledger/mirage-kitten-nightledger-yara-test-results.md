# mirage-kitten-nightledger - test results

Family: Mirage Kitten (Iran, IRGC-linked) - NightLedger backdoor + BridgeHead/ArcBridge tunnelers
Disclosed: 2026-07-28 (Kaspersky GReAT)
Rules authored: 2026-07-30

## Rules
- `MirageKitten_NightLedger_Backdoor` (critical) - unique mutex GUID, `#%%#` C2 delimiter, the
  campaign's random-looking API endpoint paths, and the AppVShNotify delay-load-hijack artefact.
  MZ-gated. Does NOT key on the filename (SspiCli.dll is a real Windows DLL).
- `MirageKitten_Tunnelers_BridgeHead_ArcBridge` (critical) - ArcBridge `<<STARTXX>>`/`<<ENDXX>>`
  config markers + its GUIDs, or the WebSocket/SOCKS5 tunneler constants. Does NOT key on the legit
  filenames unbcl.dll / libwinpthread-1.dll / IPHLPAPI.dll.
- `MirageKitten_IOC` (high) - 10 MD5 pins + C2 domains.

## Smoke test (in-repo)
Specimens (should match):
```
MirageKitten_IOC                             specimens/iocs.txt
MirageKitten_NightLedger_Backdoor            specimens/nightledger.dll.bin
MirageKitten_Tunnelers_BridgeHead_ArcBridge  specimens/arcbridge.dll.bin
```
Benign (should NOT match): clean - `benign/legit_libwinpthread.dll.bin` (real MinGW
libwinpthread-1.dll markers, none of the campaign constants). This is the key FP guard: the malware
reuses legitimate DLL filenames, so a filename rule would FP; anchoring on mutex GUIDs / config
markers / unique paths avoids that.
Result: PASS on first compile.

## Corpus FP test
PENDING - the corpus-scan service unreachable at authoring time. Re-run:
a corpus false-positive scan.
Watch: verify no benign MinGW/Windows DLL in the corpus trips the tunneler rule (the
`GET /connect HTTP/1.1` + `token` pair is the loosest path).

## Notes
- 1 MD5 recorded to the digest store (family=mirage-kitten-nightledger); absent on MalShare.
  9 further MD5s are in the IOC rule but were not all added to the hash store (headline pin only).
