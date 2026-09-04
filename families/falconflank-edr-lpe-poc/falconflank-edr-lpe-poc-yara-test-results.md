# falconflank-edr-lpe-poc — YARA test results

## Rules
- `FalconFlank_EDR_LPE_PoC_Behaviour` (critical) — FALCONFLANK pipe + planted PowerShell
  bcrypt.dll + MareBackup task-abuse + oplock/reparse race strings
- `FalconFlank_EDR_LPE_PoC_IOC` (high) — PoC project filenames + FALCONFLANK/Flanker markers
- `FalconFlank_EDR_LPE_PoC_Pin` (critical) — SHA-256 hash pin (placeholder until a compiled
  PoC sample is captured)

## Smoke test
- `specimens/falconflank-src-stub.cpp` (reconstructed distinctive strings from the public
  PoC source) → matches `Behaviour` + `IOC`. Expected.
- `benign/normal-powershell-loader.cpp` (legit `LoadLibrary(bcrypt.dll)` + a schtasks query
  naming the real MareBackup task) → clean. Expected.

The benign case deliberately includes `bcrypt.dll`, the Application-Experience task path, and
`MareBackup` to confirm the rule needs the *planted-path* DLL string
(`\WindowsPowerShell\v1.0\bcrypt.dll`) or the FALCONFLANK pipe / ≥2 exploit-message strings —
a bare `bcrypt.dll` reference or a MareBackup query does not fire.

## Corpus FP test
Corpus FP scan pending (corpus service unreachable at scan time). To be run once reachable.

## Notes
- These rules detect the PUBLIC exploit PoC (source + compiled binary), not the CrowdStrike
  Falcon product. Wide `ascii wide` on the marker strings covers both the C++ source and a
  compiled x64 binary.
- Hash pin is a zero placeholder; populate with the compiled PoC SHA-256 when a sample lands.
