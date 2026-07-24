# FakeAgent → SectopRAT — test results

Family: `fakeagent-sectoprat-claude`
Rules: 3 — `FakeAgent_SectopRAT_SideloadChain` (critical), `FakeAgent_SectopRAT_ShaderStagingShape` (high), `FakeAgent_SectopRAT_IOC` (critical)
Disclosed: 2026-07-22/23 (Huntress). Authored: 2026-07-24.

## Threat summary
Bing malvertising that hid a fake "Claude Desktop" installer inside a public
claude.ai artifact (~7,100 views before Anthropic pulled it) and delivered
SectopRAT to 29 organizations on 21–22 Jul 2026. Chain: `ClaudeDesktop.exe`
(benign JetBrains jcef_helper) DLL-sideloads a malicious VMProtect-packed
`libcef.dll` that pulls its C2 config from BNB Smart Chain transactions
(EtherHiding); persistence via a `DockerDesktop.exe` scheduled task and a second
`sslconf.exe` → `tempdir.dll` sideload that GPU/anti-VM-gates and decrypts the
`.NET SectopRAT` payload (`appcfg.dat`) with DirectX shader-based AES-256-CTR.

## Design notes / FP avoidance
`ClaudeDesktop.exe`, `DockerDesktop.exe`, `sslconf.exe`, and the jcef
`libcef.dll` are all legitimate/benign binaries when unmodified, so no rule
anchors on those names alone. Attribution comes from campaign-unique artifacts:
the malicious sample SHA-256s, the two EtherHiding BNB Smart Chain contract
addresses, the attacker domains, the abused Claude artifact UUID, or the fake
installer name co-occurring with a malicious staging artifact
(`tempdir.dll`/`appcfg.dat`/`sslconf` chain). `$f_libcef` was dropped from the
condition (benign on its own).

## Smoke test (in-repo)
Command: `yara -r fakeagent-sectoprat-claude.yar specimens/` and `… benign/`

Specimens (should match): PASS
- `spec1_iocs_etherhiding.txt` → `FakeAgent_SectopRAT_SideloadChain` + `FakeAgent_SectopRAT_IOC`
- `spec2_sideload_chain.txt` → `FakeAgent_SectopRAT_SideloadChain`
- `spec3_shader_staging.txt` → `FakeAgent_SectopRAT_ShaderStagingShape`

Benign (should NOT match): PASS — clean (0 hits)
- `benign1_legit_jcef.txt` (legit renamed jcef + libcef.dll only)
- `benign2_legit_directx.txt` (legit DirectX compute shader app)
- `benign3_legit_spss.txt` (legit IBM SPSS sslconf.exe)

## Corpus FP test
PENDING — corpus false-positive scan launched (`--max-hits 40 --budget 15m`);
result appended on completion. Any corpus hit on a family this recent is a
candidate FP to investigate. The IOC rule is hash/contract/domain-anchored and
the behavioral/structural rules require campaign-specific co-occurrence, so a
clean pass is expected.
