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

rule EVM_Unguarded_SelfDestruct_Bytecode
{
    meta:
        description = "EVM runtime bytecode exposing a caller-invocable self-destruct / drain function with no access-control guard"
        author      = "synthetic-detections"
        date        = "2026-07-17"
        severity    = "medium"
        family      = "evm-unguarded-selfdestruct"
        reference   = "https://eips.ethereum.org/EIPS/eip-6780"
        note        = "audit/hunting rule — expect benign CTF/test/tooling hits; confirm the SELFDESTRUCT is truly unguarded and the contract holds value before treating as actionable"

    strings:
        // EVM runtime dispatcher preamble (Solidity): PUSH1 0x80 PUSH1 0x40 MSTORE
        $evm = { 60 80 60 40 52 }

        // --- "strong" destructive selectors: PUSH4 <sel> ---
        // names that essentially never appear on legitimate production code
        $s_destroyme = { 63 0c 7c ad ed }   // destroyMe()
        $s_gee       = { 63 5d 2b af ed }   // gee()  (pairs with destroyMe in CTF drain kits)
        $s_die       = { 63 c9 35 3c b5 }   // die(address)
        $s_kill      = { 63 41 c0 e1 b5 }   // kill()
        $s_killme    = { 63 24 d9 7a 4a }   // killme()
        $s_suicide   = { 63 c9 6c d4 6f }   // suicide()

        // --- "weak" destructive selectors: only meaningful in combination ---
        $w_drain     = { 63 98 90 22 0b }   // drain()
        $w_target    = { 63 d4 b8 39 92 }   // target()  (drain-to-target honeypot)
        $w_destroy   = { 63 83 19 7e f0 }   // destroy()
        $w_destroyc  = { 63 09 2a 5c ce }   // destroyContract()
        $w_run       = { 63 c0 40 62 26 }   // run()
        $w_enable    = { 63 a3 90 7d 71 }   // enable()
        $w_emergency = { 63 6f f1 c9 bc }   // emergencyWithdraw(address)

        // ownership markers — used to DOWN-weight: a contract with owner()
        // / transferOwnership() gates its destroy behind an owner, so it is
        // not "unguarded" and should not be reported on a weak selector alone
        $o_owner     = { 63 8d a5 cb 5b }   // owner()
        $o_xferown   = { 63 f2 fd e3 8b }   // transferOwnership(address)

    condition:
        $evm at 0 and filesize < 24KB
        // ownerless is part of the definition: a contract carrying owner()/
        // transferOwnership() gates its destroy behind an owner and is not
        // "unguarded". Requiring their absence on EVERY path removes the
        // dominant false positive (Ownable contracts with an onlyOwner kill()).
        and not any of ($o_*)
        and
        (
            // Path 1: an unambiguous self-destruct-by-anyone selector
            any of ($s_*)
            or
            // Path 2: drain-to-target honeypot pair
            ($w_drain and $w_target)
            or
            // Path 3: two or more weak destructive selectors
            (2 of ($w_*))
        )
}

rule EVM_Unguarded_SelfDestruct_Source
{
    meta:
        description = "Solidity source or ABI advertising a public, unguarded self-destruct / drain surface"
        author      = "synthetic-detections"
        date        = "2026-07-17"
        severity    = "low"
        family      = "evm-unguarded-selfdestruct"
        reference   = "https://eips.ethereum.org/EIPS/eip-6780"

    strings:
        $sd_kw     = "selfdestruct" ascii nocase
        $sd_suicide= "suicide" ascii nocase

        // caller-invocable destroy/drain function declarations
        $f_destroyme = "function destroyMe" ascii nocase
        $f_kill      = "function kill" ascii nocase
        $f_die       = "function die" ascii nocase
        $f_drain     = "function drain" ascii nocase

        // absence of a guard is the point — flag public/external + no modifier
        $g_public    = "public" ascii
        $g_external  = "external" ascii
        // guard tokens: if present alongside, likely NOT unguarded
        $mod_onlyown = "onlyOwner" ascii
        $mod_require = "require(msg.sender" ascii

    condition:
        filesize < 200KB
        and (any of ($sd_*))
        and (any of ($f_*))
        and (any of ($g_public, $g_external))
        and not ($mod_onlyown or $mod_require)
}
