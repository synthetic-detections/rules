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

rule CrimeEnjoyor_Sweeper_Behavior
{
    meta:
        description = "CrimeEnjoyor family — Solidity sweeper contract source with EIP-7702 delegation abuse patterns"
        author      = "synthetic-detections"
        date        = "2026-06-29"
        severity    = "critical"
        family      = "crimeenjoyor-eip7702-sweeper"
        reference   = "https://etherscan.io/address/0x89383882fc2d0cd4d7952a3267a3b6dae967e704"

    strings:
        // CrimeEnjoyor naming convention across generations
        $name_v1      = "CrimeEnjoyor" ascii nocase
        $name_v2      = "CrimeEnjoyor2" ascii nocase
        $name_v3      = "AdvancedCrimeEnjoyor" ascii nocase
        $name_alt     = "CrimeEnjoyer" ascii nocase

        // v1 minimal sweeper — initialize + destination pattern
        $v1_init      = "initialize(address" ascii
        $v1_dest      = "destination" ascii

        // v2 obfuscated "loser" function family with numeric suffixes
        $v2_init      = "initLoser_863360385" ascii
        $v2_double    = "doubleLoser_1858148230" ascii
        $v2_xor       = "xorLoser_835032332" ascii
        $v2_loser     = "loser_2494524213" ascii

        // v3 advanced sweeper functions
        $v3_multicall = "loserMulticall_3869193990" ascii
        $v3_sweep     = "loserSweepETH_11435948882" ascii
        $v3_fallback  = "loserFallback_8092318215" ascii
        $v3_exec      = "executeCall" ascii
        $v3_destroy   = "destroyContract" ascii
        $v3_transfer  = "transferTokens" ascii

        // Solidity sweeper structural patterns
        $sol_payable  = "payable" ascii
        $sol_transfer = ".transfer(" ascii
        $sol_balance  = "address(this).balance" ascii
        $sol_selfdest = "selfdestruct" ascii
        $sol_delegat  = "delegatecall" ascii

        // v3 event signatures
        $evt_sweep    = "TokenTransfer" ascii
        $evt_call     = "CallExecuted" ascii

        // --- EVM bytecode-level artifacts ---

        // v1 function selectors (Keccak-256, from deployed bytecode)
        $sel_v1_dest  = { 63 b2 69 68 1d }  // destination()
        $sel_v1_init  = { 63 c4 d6 6d e8 }  // initialize(address)

        // v2 function selectors
        $sel_v2_dbl   = { 63 0c c5 1f 88 }  // doubleLoser_1858148230(uint256,bool)
        $sel_v2_init  = { 63 61 b0 18 c2 }  // initLoser_863360385(address)
        $sel_v2_xor   = { 63 c1 89 f7 2b }  // xorLoser_835032332(bytes32,uint256)
        $sel_v2_loser = { 63 d5 67 69 d7 }  // loser_2494524213()

        // v3 function selectors
        $sel_v3_a     = { 63 09 2a 5c ce }  // loserSweepETH_11435948882()
        $sel_v3_b     = { 63 0c 89 a0 df }  // loserFallback_8092318215()
        $sel_v3_c     = { 63 29 cd 3d 04 }  // executeCall(address,bytes)
        $sel_v3_d     = { 63 2c 7b dd f4 }  // loserMulticall_3869193990(address[],bytes[])
        $sel_v3_e     = { 63 ab 7e 4c 70 }  // transferTokens(address)
        $sel_v3_f     = { 63 bc a8 c7 b5 }  // destroyContract()

        // v2 distinctive error strings in bytecode
        $err_portal   = "Portal not conjured" ascii
        $err_void     = "No void allowed" ascii

        // v3 error strings in bytecode
        $err_owner    = "Only owner can destroy" ascii
        $err_arrays   = "Arrays length mismatch" ascii

        // v1 error strings in bytecode
        $err_notinit  = "Not initialized" ascii
        $err_invdest  = "Invalid destination" ascii

    condition:
        filesize < 1MB
        and (
            // Path 1: any CrimeEnjoyor name variant + sweeper functionality
            (any of ($name_*) and ($sol_payable or $sol_transfer or $sol_balance or $sol_selfdest or $sol_delegat))
            or
            // Path 2: v2 obfuscated loser functions — 2+ is highly specific
            (2 of ($v2_*))
            or
            // Path 3: v3 advanced sweeper — multicall + sweep or exec
            ($v3_multicall and any of ($v3_sweep, $v3_exec, $v3_destroy))
            or
            // Path 4: v3 sweeper function trio
            ($v3_sweep and $v3_fallback and $v3_exec)
            or
            // Path 5: any name + loser-prefixed functions
            (any of ($name_*) and any of ($v2_init, $v2_double, $v3_multicall, $v3_sweep))
            or
            // Path 6: v1 initialize+destination with CrimeEnjoyor name
            (any of ($name_*) and $v1_init and $v1_dest)
            or
            // Path 7: v3 events + sweeper functions
            ($evt_sweep and $evt_call and any of ($v3_exec, $v3_multicall))
            or
            // Path 8: v3 transferTokens + any other v3 function
            ($v3_transfer and any of ($v3_sweep, $v3_multicall, $v3_destroy))
            or
            // Path 9: v2 bytecode — 3+ function selectors from v2 dispatcher
            (3 of ($sel_v2_*))
            or
            // Path 10: v3 bytecode — 3+ function selectors from v3 dispatcher
            (3 of ($sel_v3_*))
            or
            // Path 11: v1 bytecode — both selectors + error string
            ($sel_v1_dest and $sel_v1_init and any of ($err_notinit, $err_invdest))
            or
            // Path 12: v2 distinctive error strings together
            ($err_portal and $err_void)
            or
            // Path 13: v3 error strings + any v3 selector
            ($err_owner and $err_arrays and any of ($sel_v3_*))
        )
}

rule CrimeEnjoyor_Phishing_Frontend
{
    meta:
        description = "CrimeEnjoyor family — web3 frontend code performing EIP-7702 delegation phishing or interacting with known sweeper ABIs"
        author      = "synthetic-detections"
        date        = "2026-06-29"
        severity    = "high"
        family      = "crimeenjoyor-eip7702-sweeper"
        reference   = "https://www.coindesk.com/tech/2025/06/02/post-pectra-upgrade-malicious-ethereum-contracts-are-trying-to-drain-wallets-but-to-no-avail-wintermute"

    strings:
        // EIP-7702 authorization signing in JS/TS
        $eip_7702     = "7702" ascii
        $eip_auth     = "authorization" ascii nocase
        $eip_delegate = "delegate" ascii nocase
        $eip_sign     = "signAuthorization" ascii
        $eip_type4    = "0x04" ascii

        // Web3 wallet interaction
        $w3_request   = "eth_requestAccounts" ascii
        $w3_sendtx    = "eth_sendTransaction" ascii
        $w3_sign      = "personal_sign" ascii
        $w3_provider  = "ethereum.request" ascii
        $w3_ethers    = "ethers" ascii
        $w3_web3      = "web3" ascii nocase

        // Sweeper ABI function names in JS interaction code
        $abi_init     = "initLoser" ascii
        $abi_sweep    = "loserSweepETH" ascii
        $abi_multi    = "loserMulticall" ascii
        $abi_exec     = "executeCall" ascii
        $abi_xfer     = "transferTokens" ascii
        $abi_destroy  = "destroyContract" ascii

        // Known sweeper contract addresses (lowercase, no checksum)
        $addr_v1      = "89383882fc2d0cd4d7952a3267a3b6dae967e704" ascii nocase
        $addr_v2      = "6b7879a5d747e30a3adb37a9e41c046928fce933" ascii nocase
        $addr_v3      = "89046d34e70a65acab2152c26a0c8e493b5ba629" ascii nocase

        // Polymarket attacker wallet
        $addr_poly    = "e65b1c586757c5510b60f998eebb14c1ef71e1ed" ascii nocase

    condition:
        filesize < 5MB
        and (
            // Path 1: any known sweeper address + web3 interaction
            (any of ($addr_*) and any of ($w3_*))
            or
            // Path 2: EIP-7702 authorization signing + wallet draining pattern
            ($eip_sign and any of ($w3_request, $w3_sendtx, $w3_provider))
            or
            // Path 2b: EIP-7702 authorization keyword + wallet connect
            ($eip_auth and $eip_7702 and any of ($w3_*))
            or
            // Path 3: sweeper ABI names in web3 interaction code
            (2 of ($abi_*) and any of ($w3_*))
            or
            // Path 4: EIP-7702 + delegation + sweeper ABI
            ($eip_7702 and $eip_delegate and any of ($abi_*))
            or
            // Path 5b: EIP-7702 type 4 tx + sweeper ABI
            ($eip_type4 and $eip_7702 and any of ($abi_*))
            or
            // Path 5: known address + sweeper ABI references
            (any of ($addr_v1, $addr_v2, $addr_v3) and any of ($abi_*))
            or
            // Path 6: Polymarket attacker wallet + any sweeper indicator
            ($addr_poly and (any of ($abi_*) or any of ($eip_sign, $eip_delegate)))
        )
}

rule CrimeEnjoyor_IOC
{
    meta:
        description = "CrimeEnjoyor family — static IOC sweep for known contract addresses, deployer identifiers, and EVM bytecode markers"
        author      = "synthetic-detections"
        date        = "2026-06-29"
        severity    = "high"
        family      = "crimeenjoyor-eip7702-sweeper"
        reference   = "https://etherscan.io/address/0x89046d34e70a65acab2152c26a0c8e493b5ba629"

    strings:
        // Known CrimeEnjoyor contract addresses (with 0x prefix)
        $addr01 = "0x89383882fc2d0cd4d7952a3267a3b6dae967e704" ascii nocase
        $addr02 = "0x6b7879a5d747e30a3adb37a9e41c046928fce933" ascii nocase
        $addr03 = "0x89046d34e70a65acab2152c26a0c8e493b5ba629" ascii nocase

        // v1 rebrand "GOLD" — same bytecode shape, Solidity 0.8.25
        $addr04 = "0xb59f313dcf8c8107adffeabd0c041c896c64dfca" ascii nocase

        // Polymarket incident — attacker wallet
        $addr05 = "0xe65b1C586757c5510B60F998Eebb14C1eF71E1eD" ascii nocase

        // v3 XOR-deobfuscated theft destination (a^b resolved by decompiler)
        $addr06 = "0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d" ascii nocase
        // v3 deployer/owner (only address that can call destroyContract)
        $addr07 = "0x86d9ad92fc3f69cc9c1a83aff7834fea27f1fff2" ascii nocase
        // v1 deployer (from Sourcify verification metadata)
        $addr08 = "0x63a3AABa7B12573ff0A68A45b56EeEA5508C4DBf" ascii nocase

        // Contract names as strings (appear in deployment artifacts, ABIs, configs)
        $name01 = "CrimeEnjoyor" ascii
        $name02 = "AdvancedCrimeEnjoyor" ascii
        $name03 = "CrimeEnjoyer" ascii

        // EIP-7702 delegation designator prefix in EVM bytecode
        // 0xef0100 followed by 20-byte address = delegation pointer
        $evm_7702 = { ef 01 00 }

        // CrimeEnjoyor2 IPFS metadata hash
        $ipfs_meta = "fc0bb3d0e111b4da157837da949b55336b2da5151d395fd529c0597e97487903" ascii nocase

    condition:
        filesize < 50MB
        and (
            // Any known CrimeEnjoyor contract or operator address
            any of ($addr01, $addr02, $addr03, $addr04, $addr06, $addr07, $addr08)
            or
            // Polymarket attacker wallet + any contract name
            ($addr05 and any of ($name*))
            or
            // Contract name + EIP-7702 bytecode marker
            (any of ($name*) and $evm_7702)
            or
            // IPFS metadata reference
            $ipfs_meta
        )
}
