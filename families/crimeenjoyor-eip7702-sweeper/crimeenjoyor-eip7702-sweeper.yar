/*
   CrimeEnjoyor EIP-7702 delegation sweeper contracts
   (first catalogued 2025-06-02, Wintermute Research)
   ---------------------------------------------------
   Family of malicious Ethereum smart contracts that abuse EIP-7702
   delegation to sweep funds from victim wallets. The delegation
   mechanism (introduced in the Pectra upgrade) allows an EOA to
   designate a contract whose code executes as if it were the EOA
   itself — CrimeEnjoyor variants exploit this to drain ETH and
   tokens from any wallet that signs a malicious authorization tuple.

   Four known generations:
     v1 "CrimeEnjoyor" (Solidity 0.8.20): minimal — destination(),
        initialize(address), receive(). Over 52K authorizations on
        mainnet via a single deployment.
     v1-rebrand "GOLD" (Solidity 0.8.25): identical bytecode shape to v1,
        different contract name. Deployed at 0xb59f...dfca (block 24605695).
     v2 "CrimeEnjoyor2" (Solidity 0.8.24): obfuscated function names
        with "loser" prefix and numeric suffixes. initLoser, xorLoser,
        doubleLoser naming convention.
     v3 "AdvancedCrimeEnjoyor2" (Solidity 0.8.30): multicall, arbitrary
        executeCall, token sweeping via transferTokens, self-destruct.
        "loser" prefix retained on core functions with large numeric
        suffixes (loserMulticall_3869193990, loserSweepETH_11435948882).
     v3b "AdvancedCrimeEnjoyor2" (Solidity 0.8.30): stripped v3 —
        identical sweeper logic but no destroyContract() or owner
        state variable. Different XOR destination wallet. Deployed at
        0x289c...48ae9 (block 24589357, verified 2026-06-06).

   By late 2025, >97% of all EIP-7702 delegations on mainnet pointed
   to CrimeEnjoyor-family bytecode. Used in the Polymarket $3.1M
   frontend supply chain attack (2026-06-25) among others.

   Rule 1 — Behavioral: Solidity source patterns — CrimeEnjoyor naming
            conventions, sweeper function signatures, EIP-7702 delegation
            interaction patterns.
   Rule 2 — Structural: Web3 interaction code (JS/TS) — EIP-7702
            authorization signing, delegation phishing patterns, contract
            deployment/interaction with sweeper ABIs.
   Rule 3 — IOC: Known contract addresses, deployer addresses, contract
            names, EVM bytecode markers.

   Sources:
     https://www.coindesk.com/tech/2025/06/02/post-pectra-upgrade-malicious-ethereum-contracts-are-trying-to-drain-wallets-but-to-no-avail-wintermute
     https://etherscan.io/address/0x89383882fc2d0cd4d7952a3267a3b6dae967e704
     https://etherscan.io/address/0x89046d34e70a65acab2152c26a0c8e493b5ba629
     https://etherscan.io/address/0x6b7879a5d747e30a3adb37a9e41c046928fce933
     https://eth.blockscout.com/address/0xb59f313dcf8c8107adffeabd0c041c896c64dfca
*/

rule CrimeEnjoyor_Sweeper_Behavior {
    meta:
        description = "CrimeEnjoyor family — Solidity sweeper contract source with EIP-7702 delegation abuse patterns"
        author = "synthetic-detections"
        date = "2026-06-29"
        severity = "critical"
        family = "crimeenjoyor-eip7702-sweeper"
        reference = "https://etherscan.io/address/0x89383882fc2d0cd4d7952a3267a3b6dae967e704"
    strings:
        // CrimeEnjoyor naming convention across generations
        $name_v1 = "CrimeEnjoyor" nocase
        $name_v2 = "CrimeEnjoyor2" nocase
        $name_v3 = "AdvancedCrimeEnjoyor" nocase
        $name_alt = "CrimeEnjoyer" nocase
        // v1 minimal sweeper — initialize + destination pattern
        $v1_init = "initialize(address"
        $v1_dest = "destination"
        // v2 obfuscated "loser" function family with numeric suffixes
        $v2_init = "initLoser_863360385"
        $v2_double = "doubleLoser_1858148230"
        $v2_xor = "xorLoser_835032332"
        $v2_loser = "loser_2494524213"
        // v3 advanced sweeper functions
        $v3_multicall = "loserMulticall_3869193990"
        $v3_sweep = "loserSweepETH_11435948882"
        $v3_fallback = "loserFallback_8092318215"
        $v3_exec = "executeCall"
        $v3_destroy = "destroyContract"
        $v3_transfer = "transferTokens"
        // Solidity sweeper structural patterns
        $sol_payable = "payable"
        $sol_transfer = ".transfer("
        $sol_balance = "address(this).balance"
        $sol_selfdest = "selfdestruct"
        $sol_delegat = "delegatecall"
        // v3 event signatures
        $evt_sweep = "TokenTransfer"
        $evt_call = "CallExecuted"
        // --- EVM bytecode-level artifacts ---
        // v1 function selectors (Keccak-256, from deployed bytecode)
        $sel_v1_dest = { 63 B2 69 68 1D }
        $sel_v1_init = { 63 C4 D6 6D E8 }
        // ownership selectors — the v1 sweeper is ownerless; presence of
        // owner()/transferOwnership() means a different (often legitimate)
        // init+destination contract, so the bytecode-only v1 path excludes them
        $sel_owner = { 63 8D A5 CB 5B }
        $sel_xferown = { 63 F2 FD E3 8B }
        // v2 function selectors
        $sel_v2_dbl = { 63 0C C5 1F 88 }
        $sel_v2_init = { 63 61 B0 18 C2 }
        $sel_v2_xor = { 63 C1 89 F7 2B }
        $sel_v2_loser = { 63 D5 67 69 D7 }
        // v3 function selectors
        $sel_v3_a = { 63 09 2A 5C CE }
        $sel_v3_b = { 63 0C 89 A0 DF }
        $sel_v3_c = { 63 29 CD 3D 04 }
        $sel_v3_d = { 63 2C 7B DD F4 }
        $sel_v3_e = { 63 AB 7E 4C 70 }
        $sel_v3_f = { 63 BC A8 C7 B5 }
        // v2 distinctive error strings in bytecode
        $err_portal = "Portal not conjured"
        $err_void = "No void allowed"
        // v3 error strings in bytecode
        $err_owner = "Only owner can destroy"
        $err_arrays = "Arrays length mismatch"
        // v3 destination-obfuscation primitive: two adjacent 32-byte
        // constants XOR'd (PUSH32 a; PUSH32 b; XOR) — a^b reconstructs the
        // 20-byte theft address at runtime so it is never a plain literal in
        // bytecode. The two constants share their high 12 bytes (they cancel),
        // leaving a 20-byte result. Rare on its own (~0.045% of mainnet
        // bytecodes) and used by ~all v3 variants; only asserted here in
        // combination with v3 sweeper selectors, since XOR-of-two-words also
        // occurs in unrelated (legitimate) contracts. Two suffix variants
        // (XOR;SWAP1;POP and XOR;PUSH0;SHR) give a fixed 3-byte atom so the
        // pattern is not a slow scan.
        $xor_deob_a = { 7F [32] 7F [32] 18 90 50 }
        $xor_deob_b = { 7F [32] 7F [32] 18 5F 1C }
        // v1 error strings in bytecode
        $err_notinit = "Not initialized"
        $err_invdest = "Invalid destination"
    condition:
        // Path 1: any CrimeEnjoyor name variant + sweeper functionality
        // Path 2: v2 obfuscated loser functions — 2+ is highly specific
        // Path 3: v3 advanced sweeper — multicall + sweep or exec
        // Path 4: v3 sweeper function trio
        // Path 5: any name + loser-prefixed functions
        // Path 6: v1 initialize+destination with CrimeEnjoyor name
        // Path 7: v3 events + sweeper functions
        // Path 8: v3 transferTokens + any other v3 function
        // Path 9: v2 bytecode — 3+ function selectors from v2 dispatcher
        // Path 10: v3 bytecode — 3+ function selectors from v3 dispatcher
        // Path 11: v1 bytecode — both selectors + error string
        // Path 11b: v1 bytecode-only — both selectors in a small, ownerless
        // runtime blob. Catches stripped/re-metadata'd v1 clones that carry
        // no English revert string ("Already initialized"/none), which the
        // error-string-gated Path 11 misses. The exact destination()+
        // initialize(address) selector pair in a <3KB contract with no owner
        // selector is the minimal EIP-7702 sweeper shape.
        // Path 12: v2 distinctive error strings together
        // Path 13: v3 error strings + any v3 selector
        // Path 14: v3 obfuscated variant — the PUSH32/PUSH32/XOR
        // destination-deobfuscation primitive together with 2+ v3 sweeper
        // selectors. Catches obfuscated v3 clones that carry too few
        // recognised selectors for Path 10 (which needs 3) but still XOR a
        // hidden destination. The XOR anchor is only asserted alongside the
        // sweeper selectors, so unrelated XOR-of-words contracts are excluded.
        filesize < 1MB and (any of ($name_*) and ($sol_payable or $sol_transfer or $sol_balance or $sol_selfdest or $sol_delegat) or 2 of ($v2_*) or $v3_multicall and any of ($v3_sweep, $v3_exec, $v3_destroy) or $v3_sweep and $v3_fallback and $v3_exec or any of ($name_*) and any of ($v2_init, $v2_double, $v3_multicall, $v3_sweep) or any of ($name_*) and $v1_init and $v1_dest or $evt_sweep and $evt_call and any of ($v3_exec, $v3_multicall) or $v3_transfer and any of ($v3_sweep, $v3_multicall, $v3_destroy) or 3 of ($sel_v2_*) or 3 of ($sel_v3_*) or $sel_v1_dest and $sel_v1_init and any of ($err_notinit, $err_invdest) or $sel_v1_dest and $sel_v1_init and not any of ($sel_owner, $sel_xferown) and filesize < 3KB or $err_portal and $err_void or $err_owner and $err_arrays and any of ($sel_v3_*) or any of ($xor_deob_*) and 2 of ($sel_v3_*) and filesize < 8KB)
}

rule CrimeEnjoyor_Phishing_Frontend {
    meta:
        description = "CrimeEnjoyor family — web3 frontend code performing EIP-7702 delegation phishing or interacting with known sweeper ABIs"
        author = "synthetic-detections"
        date = "2026-06-29"
        severity = "high"
        family = "crimeenjoyor-eip7702-sweeper"
        reference = "https://www.coindesk.com/tech/2025/06/02/post-pectra-upgrade-malicious-ethereum-contracts-are-trying-to-drain-wallets-but-to-no-avail-wintermute"
    strings:
        // EIP-7702 authorization signing in JS/TS. Note: "7702" and
        // "delegate" are only ever used here paired with a sweeper ABI
        // name or a known sweeper address — never on their own, since
        // EIP-7702 delegation is itself a legitimate protocol feature.
        $eip_7702 = "7702"
        $eip_delegate = "delegate" nocase
        $eip_sign = "signAuthorization"
        $eip_type4 = "0x04"
        // Web3 wallet interaction
        $w3_request = "eth_requestAccounts"
        $w3_sendtx = "eth_sendTransaction"
        $w3_sign = "personal_sign"
        $w3_provider = "ethereum.request"
        $w3_ethers = "ethers"
        $w3_web3 = "web3" nocase
        // Sweeper ABI function names in JS interaction code
        $abi_init = "initLoser"
        $abi_sweep = "loserSweepETH"
        $abi_multi = "loserMulticall"
        $abi_exec = "executeCall"
        $abi_xfer = "transferTokens"
        $abi_destroy = "destroyContract"
        // Known sweeper contract addresses (lowercase, no checksum)
        $addr_v1 = "89383882fc2d0cd4d7952a3267a3b6dae967e704" nocase
        $addr_v2 = "6b7879a5d747e30a3adb37a9e41c046928fce933" nocase
        $addr_v3 = "89046d34e70a65acab2152c26a0c8e493b5ba629" nocase
        // Polymarket attacker wallet
        $addr_poly = "e65b1c586757c5510b60f998eebb14c1ef71e1ed" nocase
    condition:
        // Path 1: any known sweeper address + web3 interaction
        // Path 2: EIP-7702 authorization signing + wallet draining pattern
        // (Removed the former Path 2b "authorization + 7702 + wallet"
        // heuristic: EIP-7702 delegation is a legitimate protocol
        // feature, so an EIP-7702 reference plus a wallet call is not
        // malicious on its own. Malicious delegation is caught below by
        // pairing the 7702/delegate markers with a sweeper ABI name or a
        // known sweeper address — Paths 4, 5b, 5 and 6.)
        // Path 3: sweeper ABI names in web3 interaction code
        // Path 4: EIP-7702 + delegation + sweeper ABI
        // Path 5b: EIP-7702 type 4 tx + sweeper ABI
        // Path 5: known address + sweeper ABI references
        // Path 6: Polymarket attacker wallet + any sweeper indicator
        (any of ($addr_*) and any of ($w3_*) or $eip_sign and any of ($w3_request, $w3_sendtx, $w3_provider) or 2 of ($abi_*) and any of ($w3_*) or $eip_7702 and $eip_delegate and any of ($abi_*) or $eip_type4 and $eip_7702 and any of ($abi_*) or any of ($addr_v1, $addr_v2, $addr_v3) and any of ($abi_*) or $addr_poly and (any of ($abi_*) or any of ($eip_sign, $eip_delegate))) and filesize < 5MB
}

rule CrimeEnjoyor_IOC {
    meta:
        description = "CrimeEnjoyor family — static IOC sweep for known contract addresses, deployer identifiers, and EVM bytecode markers"
        author = "synthetic-detections"
        date = "2026-07-01"
        severity = "high"
        family = "crimeenjoyor-eip7702-sweeper"
        reference = "https://etherscan.io/address/0x89046d34e70a65acab2152c26a0c8e493b5ba629"
    strings:
        // Known CrimeEnjoyor contract addresses (with 0x prefix)
        $addr01 = "0x89383882fc2d0cd4d7952a3267a3b6dae967e704" nocase
        $addr02 = "0x6b7879a5d747e30a3adb37a9e41c046928fce933" nocase
        $addr03 = "0x89046d34e70a65acab2152c26a0c8e493b5ba629" nocase
        // v1 rebrand "GOLD" — same bytecode shape, Solidity 0.8.25
        $addr04 = "0xb59f313dcf8c8107adffeabd0c041c896c64dfca" nocase
        // Polymarket incident — attacker wallet
        $addr05 = "0xe65b1C586757c5510B60F998Eebb14C1eF71E1eD" nocase
        // v3 XOR-deobfuscated theft destination (a^b resolved by decompiler)
        $addr06 = "0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d" nocase
        // v3 deployer/owner (only address that can call destroyContract)
        $addr07 = "0x86d9ad92fc3f69cc9c1a83aff7834fea27f1fff2" nocase
        // v1 deployer (from Sourcify verification metadata)
        $addr08 = "0x63a3AABa7B12573ff0A68A45b56EeEA5508C4DBf" nocase
        // v3b contract — stripped v3 without destroyContract
        $addr09 = "0x289c9c58355e1a7d2b0ad4a5e8f2c3c961b48ae9" nocase
        // v3b XOR-deobfuscated theft destination
        $addr10 = "0xbfe129315f75dd7ba60ec85b4024e0fe1264fb13" nocase
        // v1 clones caught by corpus sweep 2026-07-17 (ownerless
        // destination()+initialize() bytecode, not in the original 123-set)
        $addr11 = "0x71d3410b017de35ad643f67a4f7bc5d02af4dc71" nocase
        $addr12 = "0x058c9df053828f5817ef67bac3cd90672ae4489a" nocase
        $addr13 = "0xf6fcd2ccd2472b71f334c3e4f1a7001f1ee53700" nocase
        $addr14 = "0x2f22ca91e03a96bf5f055d7ded57574eb4b53fbf" nocase
        $addr15 = "0x8d95ce736d17e3daa8afb9b8d5b5b68af9518c1c" nocase
        // v3 obfuscated clone (PUSH32/PUSH32/XOR destination, executeCall+
        // transferTokens, ownerless) caught by the XOR-anchor path 2026-07-17
        $addr16 = "0xc474aefd254694e25fbda8af64caba4c55a8619a" nocase
        // v1 clone (ownerless destination()+initialize(), <3KB, no XOR) caught by
        // the live contract scanner at block 25711950 on 2026-08-08
        $addr17 = "0x23b4a130273edac471a1b061d9a53cfeae1afbf2" nocase
        // v3c stripped variant (transferTokens, 1967B, new deployer) caught by
        // the live contract scanner at block 25943206 on 2026-09-09
        $addr18 = "0x7e7dd63e2d42993ce84060c594b52631fbb0505b" nocase
        $addr19 = "0x4ab75558aa4a348f7e936ac0c8adc9c9eae098ed" nocase
        // v3c clone (identical fingerprints to 0x7e7dd63e, new deployer 0x277622cd)
        // caught by live contract scanner at block 25956136 on 2026-09-11
        $addr20 = "0xd8e252367271923f556c3f3a0790bd1740f005b2" nocase
        $addr21 = "0x277622cd50eccb9007f2e1e84399831249c43b74" nocase
        // Contract names as strings (appear in deployment artifacts, ABIs, configs)
        $name01 = "CrimeEnjoyor"
        $name02 = "AdvancedCrimeEnjoyor"
        $name03 = "CrimeEnjoyer"
        // EIP-7702 delegation designator prefix in EVM bytecode
        // 0xef0100 followed by 20-byte address = delegation pointer
        $evm_7702 = { EF 01 00 }
        // CrimeEnjoyor2 IPFS metadata hash
        $ipfs_meta = "fc0bb3d0e111b4da157837da949b55336b2da5151d395fd529c0597e97487903" nocase
    condition:
        // Any known CrimeEnjoyor contract or operator address
        // Polymarket attacker wallet + any contract name
        // Contract name + EIP-7702 bytecode marker
        // IPFS metadata reference
        (any of ($addr01, $addr02, $addr03, $addr04, $addr06, $addr07, $addr08, $addr09, $addr10, $addr11, $addr12, $addr13, $addr14, $addr15, $addr16, $addr17, $addr18, $addr19, $addr20, $addr21) or $addr05 and any of ($name*) or any of ($name*) and $evm_7702 or $ipfs_meta) and filesize < 50MB
}
