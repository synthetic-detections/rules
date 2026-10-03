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
        $name_v1 = "CrimeEnjoyor" nocase
        $name_v2 = "CrimeEnjoyor2" nocase
        $name_v3 = "AdvancedCrimeEnjoyor" nocase
        $name_alt = "CrimeEnjoyer" nocase
        $v1_init = "initialize(address"
        $v1_dest = "destination"
        $v2_init = "initLoser_863360385"
        $v2_double = "doubleLoser_1858148230"
        $v2_xor = "xorLoser_835032332"
        $v2_loser = "loser_2494524213"
        $v3_multicall = "loserMulticall_3869193990"
        $v3_sweep = "loserSweepETH_11435948882"
        $v3_fallback = "loserFallback_8092318215"
        $v3_exec = "executeCall"
        $v3_destroy = "destroyContract"
        $v3_transfer = "transferTokens"
        $sol_payable = "payable"
        $sol_transfer = ".transfer("
        $sol_balance = "address(this).balance"
        $sol_selfdest = "selfdestruct"
        $sol_delegat = "delegatecall"
        $evt_sweep = "TokenTransfer"
        $evt_call = "CallExecuted"
        $sel_v1_dest = { 63 B2 69 68 1D }
        $sel_v1_init = { 63 C4 D6 6D E8 }
        $sel_owner = { 63 8D A5 CB 5B }
        $sel_xferown = { 63 F2 FD E3 8B }
        $sel_v2_dbl = { 63 0C C5 1F 88 }
        $sel_v2_init = { 63 61 B0 18 C2 }
        $sel_v2_xor = { 63 C1 89 F7 2B }
        $sel_v2_loser = { 63 D5 67 69 D7 }
        $sel_v3_a = { 63 09 2A 5C CE }
        $sel_v3_b = { 63 0C 89 A0 DF }
        $sel_v3_c = { 63 29 CD 3D 04 }
        $sel_v3_d = { 63 2C 7B DD F4 }
        $sel_v3_e = { 63 AB 7E 4C 70 }
        $sel_v3_f = { 63 BC A8 C7 B5 }
        $err_portal = "Portal not conjured"
        $err_void = "No void allowed"
        $err_owner = "Only owner can destroy"
        $err_arrays = "Arrays length mismatch"
        $xor_deob_a = { 7F [32] 7F [32] 18 90 50 }
        $xor_deob_b = { 7F [32] 7F [32] 18 5F 1C }
        $err_notinit = "Not initialized"
        $err_invdest = "Invalid destination"
    condition:
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
        $eip_7702 = "7702"
        $eip_delegate = "delegate" nocase
        $eip_sign = "signAuthorization"
        $eip_type4 = "0x04"
        $w3_request = "eth_requestAccounts"
        $w3_sendtx = "eth_sendTransaction"
        $w3_sign = "personal_sign"
        $w3_provider = "ethereum.request"
        $w3_ethers = "ethers"
        $w3_web3 = "web3" nocase
        $abi_init = "initLoser"
        $abi_sweep = "loserSweepETH"
        $abi_multi = "loserMulticall"
        $abi_exec = "executeCall"
        $abi_xfer = "transferTokens"
        $abi_destroy = "destroyContract"
        $addr_v1 = "89383882fc2d0cd4d7952a3267a3b6dae967e704" nocase
        $addr_v2 = "6b7879a5d747e30a3adb37a9e41c046928fce933" nocase
        $addr_v3 = "89046d34e70a65acab2152c26a0c8e493b5ba629" nocase
        $addr_poly = "e65b1c586757c5510b60f998eebb14c1ef71e1ed" nocase
    condition:
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
        $addr01 = "0x89383882fc2d0cd4d7952a3267a3b6dae967e704" nocase
        $addr02 = "0x6b7879a5d747e30a3adb37a9e41c046928fce933" nocase
        $addr03 = "0x89046d34e70a65acab2152c26a0c8e493b5ba629" nocase
        $addr04 = "0xb59f313dcf8c8107adffeabd0c041c896c64dfca" nocase
        $addr05 = "0xe65b1C586757c5510B60F998Eebb14C1eF71E1eD" nocase
        $addr06 = "0x77dd9a93d7a1ab9dd3bdd4a70a51b2e8c9b2350d" nocase
        $addr07 = "0x86d9ad92fc3f69cc9c1a83aff7834fea27f1fff2" nocase
        $addr08 = "0x63a3AABa7B12573ff0A68A45b56EeEA5508C4DBf" nocase
        $addr09 = "0x289c9c58355e1a7d2b0ad4a5e8f2c3c961b48ae9" nocase
        $addr10 = "0xbfe129315f75dd7ba60ec85b4024e0fe1264fb13" nocase
        $addr11 = "0x71d3410b017de35ad643f67a4f7bc5d02af4dc71" nocase
        $addr12 = "0x058c9df053828f5817ef67bac3cd90672ae4489a" nocase
        $addr13 = "0xf6fcd2ccd2472b71f334c3e4f1a7001f1ee53700" nocase
        $addr14 = "0x2f22ca91e03a96bf5f055d7ded57574eb4b53fbf" nocase
        $addr15 = "0x8d95ce736d17e3daa8afb9b8d5b5b68af9518c1c" nocase
        $addr16 = "0xc474aefd254694e25fbda8af64caba4c55a8619a" nocase
        $addr17 = "0x23b4a130273edac471a1b061d9a53cfeae1afbf2" nocase
        $addr18 = "0x7e7dd63e2d42993ce84060c594b52631fbb0505b" nocase
        $addr19 = "0x4ab75558aa4a348f7e936ac0c8adc9c9eae098ed" nocase
        $addr20 = "0xd8e252367271923f556c3f3a0790bd1740f005b2" nocase
        $addr21 = "0x277622cd50eccb9007f2e1e84399831249c43b74" nocase
        $name01 = "CrimeEnjoyor"
        $name02 = "AdvancedCrimeEnjoyor"
        $name03 = "CrimeEnjoyer"
        $evm_7702 = { EF 01 00 }
        $ipfs_meta = "fc0bb3d0e111b4da157837da949b55336b2da5151d395fd529c0597e97487903" nocase
    condition:
        (any of ($addr01, $addr02, $addr03, $addr04, $addr06, $addr07, $addr08, $addr09, $addr10, $addr11, $addr12, $addr13, $addr14, $addr15, $addr16, $addr17, $addr18, $addr19, $addr20, $addr21) or $addr05 and any of ($name*) or any of ($name*) and $evm_7702 or $ipfs_meta) and filesize < 50MB
}
