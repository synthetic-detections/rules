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
        $wallet = { 2A 98 74 17 65 B5 8E 4D E3 87 3B 87 83 E7 50 A2 A4 D4 07 60 }
    condition:
        $wallet and filesize < 64KB
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
        $wallet      = { 2A 98 74 17 65 B5 8E 4D E3 87 3B 87 83 E7 50 A2 A4 D4 07 60 }
        // attack-TTP dispatcher selectors (PUSH4 <selector>)
        // exploit()
        $s_exploit   = { 63 63 D9 B7 70 }
        // victim()
        $s_victim    = { 63 93 0C 20 03 }
        // attack()
        $s_attack    = { 63 9E 5F AA FC }
        // attacker()
        $s_attacker  = { 63 48 EB 76 EE }
        // takeOwnership()
        $s_takeown   = { 63 60 53 61 72 }
        // withdrawAll()
        $s_withall   = { 63 85 38 28 B6 }
        // targetWallet()
        $s_targetw   = { 63 B9 26 20 BD }
        // RECIPIENT()
        $s_recipient = { 63 0D 90 19 E1 }
        // TARGET()
        $s_target    = { 63 CC 1F 2A FA }
        // getTargetBalance()
        $s_getTbal   = { 63 EB 17 5B 7E }
        // getRecipientBalance()
        $s_getRbal   = { 63 AC 57 04 11 }
        // checkOwnerBalance()
        $s_ckOwnBal  = { 63 38 FE 91 E1 }
    condition:
        $wallet and 2 of ($s_*) and filesize < 64KB
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
        $wallet = "2a98741765b58e4de3873b8783e750a2a4d40760" nocase
        // drainer / exploit contracts
        // exploit()/targetWallet()
        $c01    = "1448c4995c5c92206415f8e264a8702e5e52e508" nocase
        // RECIPIENT()/attacker()
        $c02    = "453d46afdf1cb88626a0238b5bd50b2fccea44cb" nocase
        $c03    = "85cdee271662f691adfa283ebe6b1d02dd81af47" nocase
        $c04    = "17d3a2cc566e317e727528cd1ca85ae8b28c6489" nocase
        // victim()/attack()
        $c05    = "4792d2fb8a3203c962570c06d9a7f120e1e67f32" nocase
        // takeOwnership()
        $c06    = "5011fc49def04ac55258cbfe742b72ccfebc3673" nocase
        $c07    = "1005ebb8a2fd7c0a38bc84e07a0a566e6efd2ada" nocase
        $c08    = "bca7c8f6352d786e19ec3157a2d986a434f0a085" nocase
        $c09    = "0bd986f46bb5c2d54e290701c3a1faa107a05b3d" nocase
        $c10    = "e52019e4d85908ca017e0bc87be7953d0b79f41c" nocase
        $c11    = "bbca39e1cdb9176e406c2b49e1d863dd02991e25" nocase
        $c12    = "049ae43bc201383c5e242c9ac4d70327f95810c0" nocase
        $c13    = "bd9b3c88f7b7add2ba50beca1db74fc245ead994" nocase
        $c14    = "2506571867d407e31d8e81cb05f1dbf33366ec69" nocase
        $c15    = "c43f2d51ce9eeb93c69d586e1fc5d2b923f3c083" nocase
        $c16    = "4186e767a669c6408e94e9d7a4450b2f0b6a85de" nocase
        $c17    = "3a5d9e8689c1195751cf5d36f2989ec942f49a37" nocase
        // CrimeEnjoyor v3 sweepers in this kit
        $c18    = "34ee0e6e1661fbd1f4a9401e8eaa11db966756c5" nocase
        $c19    = "6799946b74e065f14ebf4933df96dcfa24c27c28" nocase
        $c20    = "cc3f0923ccbed291a2109bce77579c328691eea4" nocase
        $c21    = "ff413c217a33e0e35979ed8117f2e8634f47076a" nocase
        $c22    = "668924ffadb2b3e226468aaf42c35b356d8d7589" nocase
    condition:
        any of them and filesize < 5MB
}
