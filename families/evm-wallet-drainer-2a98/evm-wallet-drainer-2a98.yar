/*
   EVM wallet-drainer operator 0x2a9874…0760
   -----------------------------------------
   Unnamed Ethereum operator that hardcodes a single payout wallet
   (0x2a98741765b58e4de3873b8783e750a2a4d40760) across a toolkit of ~23
   deployed contracts: 5 CrimeEnjoyor v3 EIP-7702 sweepers plus ~18
   single-purpose wallet-drainer / exploit contracts whose function names
   state the intent (exploit(), victim(), attack(), attacker(),
   targetWallet(), TARGET(), RECIPIENT(), takeOwnership(), withdrawAll()).
   Surfaced 2026-07-17 by shared-constant clustering over the ~318K-bytecode
   mainnet corpus: following the wallet as an embedded bytecode constant
   expanded a known CrimeEnjoyor self-operator into its full kit.

   Reliable discriminator = the embedded payout wallet (attack-style
   function names alone are common in CTF/test contracts, so they are only
   used here to raise confidence, never on their own). The 20-byte wallet
   is embedded as PUSH20 (73 …) in some contracts and zero-padded PUSH32
   (7f 0000…0000 …) in others; the raw 20-byte run matches both.

   Related: [[crimeenjoyor-eip7702-sweeper]] (the v3 sweepers in this kit).

   Rule 1 — Bytecode IOC: contract embeds the operator payout wallet.
   Rule 2 — Toolkit behavior: wallet + attack-TTP selectors (drainer kit).
   Rule 3 — IOC: wallet + known contract addresses in source/config/reports.
*/

rule EVM_Drainer_2a98_Bytecode
{
    meta:
        description = "Contract bytecode embedding the 0x2a9874…0760 wallet-drainer operator's hardcoded payout wallet"
        author      = "synthetic-detections"
        date        = "2026-07-17"
        severity    = "high"
        family      = "evm-wallet-drainer-2a98"
        reference   = "https://etherscan.io/address/0x2a98741765b58e4de3873b8783e750a2a4d40760"

    strings:
        // payout wallet as a raw 20-byte run (matches PUSH20 and padded PUSH32).
        // 20 fixed bytes is unique enough to stand alone; no EVM-preamble anchor
        // needed (and some toolkit contracts do not start with 60 80 60 40 52).
        $wallet = { 2a 98 74 17 65 b5 8e 4d e3 87 3b 87 83 e7 50 a2 a4 d4 07 60 }

    condition:
        filesize < 64KB and $wallet
}

rule EVM_Drainer_2a98_Toolkit_Behavior
{
    meta:
        description = "0x2a9874…0760 wallet-drainer toolkit — payout wallet co-occurring with attack/exploit dispatcher selectors"
        author      = "synthetic-detections"
        date        = "2026-07-17"
        severity    = "critical"
        family      = "evm-wallet-drainer-2a98"
        reference   = "https://etherscan.io/address/0x2a98741765b58e4de3873b8783e750a2a4d40760"

    strings:
        $wallet     = { 2a 98 74 17 65 b5 8e 4d e3 87 3b 87 83 e7 50 a2 a4 d4 07 60 }
        // attack-TTP dispatcher selectors (PUSH4 <selector>)
        $s_exploit  = { 63 63 d9 b7 70 }   // exploit()
        $s_victim   = { 63 93 0c 20 03 }   // victim()
        $s_attack   = { 63 9e 5f aa fc }   // attack()
        $s_attacker = { 63 48 eb 76 ee }   // attacker()
        $s_takeown  = { 63 60 53 61 72 }   // takeOwnership()
        $s_withall  = { 63 85 38 28 b6 }   // withdrawAll()
        $s_targetw  = { 63 b9 26 20 bd }   // targetWallet()
        $s_recipient= { 63 0d 90 19 e1 }   // RECIPIENT()
        $s_target   = { 63 cc 1f 2a fa }   // TARGET()
        $s_getTbal  = { 63 eb 17 5b 7e }   // getTargetBalance()
        $s_getRbal  = { 63 ac 57 04 11 }   // getRecipientBalance()
        $s_ckOwnBal = { 63 38 fe 91 e1 }   // checkOwnerBalance()

    condition:
        filesize < 64KB and $wallet and 2 of ($s_*)
}

rule EVM_Drainer_2a98_IOC
{
    meta:
        description = "0x2a9874…0760 wallet-drainer operator — payout wallet and known contract addresses (source/config/IOC lists)"
        author      = "synthetic-detections"
        date        = "2026-07-17"
        severity    = "high"
        family      = "evm-wallet-drainer-2a98"
        reference   = "https://etherscan.io/address/0x2a98741765b58e4de3873b8783e750a2a4d40760"

    strings:
        $wallet = "2a98741765b58e4de3873b8783e750a2a4d40760" ascii nocase

        // drainer / exploit contracts
        $c01 = "1448c4995c5c92206415f8e264a8702e5e52e508" ascii nocase  // exploit()/targetWallet()
        $c02 = "453d46afdf1cb88626a0238b5bd50b2fccea44cb" ascii nocase  // RECIPIENT()/attacker()
        $c03 = "85cdee271662f691adfa283ebe6b1d02dd81af47" ascii nocase
        $c04 = "17d3a2cc566e317e727528cd1ca85ae8b28c6489" ascii nocase
        $c05 = "4792d2fb8a3203c962570c06d9a7f120e1e67f32" ascii nocase  // victim()/attack()
        $c06 = "5011fc49def04ac55258cbfe742b72ccfebc3673" ascii nocase  // takeOwnership()
        $c07 = "1005ebb8a2fd7c0a38bc84e07a0a566e6efd2ada" ascii nocase
        $c08 = "bca7c8f6352d786e19ec3157a2d986a434f0a085" ascii nocase
        $c09 = "0bd986f46bb5c2d54e290701c3a1faa107a05b3d" ascii nocase
        $c10 = "e52019e4d85908ca017e0bc87be7953d0b79f41c" ascii nocase
        $c11 = "bbca39e1cdb9176e406c2b49e1d863dd02991e25" ascii nocase
        $c12 = "049ae43bc201383c5e242c9ac4d70327f95810c0" ascii nocase
        $c13 = "bd9b3c88f7b7add2ba50beca1db74fc245ead994" ascii nocase
        $c14 = "2506571867d407e31d8e81cb05f1dbf33366ec69" ascii nocase
        $c15 = "c43f2d51ce9eeb93c69d586e1fc5d2b923f3c083" ascii nocase
        $c16 = "4186e767a669c6408e94e9d7a4450b2f0b6a85de" ascii nocase
        $c17 = "3a5d9e8689c1195751cf5d36f2989ec942f49a37" ascii nocase
        // CrimeEnjoyor v3 sweepers in this kit
        $c18 = "34ee0e6e1661fbd1f4a9401e8eaa11db966756c5" ascii nocase
        $c19 = "6799946b74e065f14ebf4933df96dcfa24c27c28" ascii nocase
        $c20 = "cc3f0923ccbed291a2109bce77579c328691eea4" ascii nocase
        $c21 = "ff413c217a33e0e35979ed8117f2e8634f47076a" ascii nocase
        $c22 = "668924ffadb2b3e226468aaf42c35b356d8d7589" ascii nocase

    condition:
        filesize < 5MB and any of them
}
