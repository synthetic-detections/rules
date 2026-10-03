/*
   EVM contracts self-destructible / drainable by any caller
   ---------------------------------------------------------
   Deployed Ethereum (EVM) runtime bytecode whose dispatcher routes a
   destructive function reachable without any msg.sender / owner check —
   i.e. any account can trigger SELFDESTRUCT or force the contract to
   forward its balance. Surfaced by a static sweep of ~318K unique
   mainnet bytecodes: contracts that contain a dangerous capability yet
   no CALLER opcode anywhere in executable code (metadata trailer
   stripped before the opcode walk, so the IPFS hash's stray 0x33/0xff
   bytes are not mis-read as CALLER/SELFDESTRUCT).

   This is a vulnerability / audit-hunting rule, not a single malware
   family. The population it catches is dominated by intentionally
   destroyable contracts — CTF/practice targets, deploy scaffolding, and
   honeypots — whose function names advertise the behaviour: destroyMe(),
   gee(), drain()+target(), kill(), killme(), suicide(), die(address).
   Post-EIP-6780 a SELFDESTRUCT on an already-deployed contract only
   forwards its balance rather than deleting code, so the practical risk
   is "any caller can sweep the contract's ETH to an address of their
   choosing" — real only where the contract holds funds. Use it to triage
   a bytecode corpus for open-teardown / open-drain exposure, expecting
   benign test/tooling hits.

   Anchors are dispatcher selector bytes: PUSH4 <4-byte keccak selector>
   = { 63 XX XX XX XX }. Selectors are split into "strong" (function
   names essentially never seen on legitimate production contracts) and
   "weak" (names like drain()/destroy() that also occur in benign admin
   code and so are only reported in combination).

   Rule 1 — EVM bytecode: unguarded destructive dispatcher.
   Rule 2 — Source/artifact: Solidity or ABI advertising the same
            caller-invocable destroy/drain surface.
*/

rule EVM_Unguarded_SelfDestruct_Bytecode {
  meta:
    description = "EVM runtime bytecode exposing a caller-invocable self-destruct / drain function with no access-control guard"
    author = "synthetic-detections"
    date = "2026-07-17"
    severity = "medium"
    family = "evm-unguarded-selfdestruct"
    reference = "https://eips.ethereum.org/EIPS/eip-6780"
    note = "audit/hunting rule — expect benign CTF/test/tooling hits; confirm the SELFDESTRUCT is truly unguarded and the contract holds value before treating as actionable"
  strings:
    $evm = { 60 80 60 40 52 }
    $s_destroyme = { 63 0C 7C AD ED }
    $s_gee = { 63 5D 2B AF ED }
    $s_die = { 63 C9 35 3C B5 }
    $s_kill = { 63 41 C0 E1 B5 }
    $s_killme = { 63 24 D9 7A 4A }
    $s_suicide = { 63 C9 6C D4 6F }
    $w_drain = { 63 98 90 22 0B }
    $w_target = { 63 D4 B8 39 92 }
    $w_destroy = { 63 83 19 7E F0 }
    $w_destroyc = { 63 09 2A 5C CE }
    $w_run = { 63 C0 40 62 26 }
    $w_enable = { 63 A3 90 7D 71 }
    $w_emergency = { 63 6F F1 C9 BC }
    $o_owner = { 63 8D A5 CB 5B }
    $o_xferown = { 63 F2 FD E3 8B }
  condition:
    $evm at 0 and not any of ($o_*) and (any of ($s_*) or $w_drain and $w_target or 2 of ($w_*)) and filesize < 24KB
}

rule EVM_Unguarded_SelfDestruct_Source {
  meta:
    description = "Solidity source or ABI advertising a public, unguarded self-destruct / drain surface"
    author = "synthetic-detections"
    date = "2026-07-17"
    severity = "low"
    family = "evm-unguarded-selfdestruct"
    reference = "https://eips.ethereum.org/EIPS/eip-6780"
  strings:
    $sd_kw = "selfdestruct" nocase
    $sd_suicide = "suicide" nocase
    $f_destroyme = "function destroyMe" nocase
    $f_kill = "function kill" nocase
    $f_die = "function die" nocase
    $f_drain = "function drain" nocase
    $g_public = "public"
    $g_external = "external"
    $mod_onlyown = "onlyOwner"
    $mod_require = "require(msg.sender"
  condition:
    any of ($sd_*) and any of ($f_*) and any of ($g_public, $g_external) and not ($mod_onlyown or $mod_require) and filesize < 200KB
}
